use bytes::Bytes;
use http::Request;
use rand::rngs::ThreadRng;
use rand::RngCore;
use reqwest::Url;
use std::{
    convert::TryInto,
    io::{prelude::*, BufReader},
    net::{TcpListener, TcpStream},
    str,
};
use std::{sync::Arc, time::Instant};
use tame_oidc::auth_scheme::{AuthenticationScheme, ClientAuthentication, PkceCredentials};
use tame_oidc::provider::Claims;
use tame_oidc::{
    oidc::Token,
    provider::{self, Provider, JWKS},
};

use serde::Deserialize;
use typed_builder::TypedBuilder;

use crate::{
    client::{auth::sasl::SaslResponse, options::ServerApi},
    cmap::Connection,
    error::{Error, Result},
};

use super::{Credential, MONGODB_OIDC_STR};

/// The user-supplied callbacks for OIDC authentication.
#[derive(Clone)]
pub struct Callbacks {
    inner: Arc<CallbacksInner>,
}

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Callbacks {
    /// Create a new instance with a token request callback.
    pub fn new<F>(on_request: F) -> Self
    where
        F: Fn(IdpServerInfo, RequestParameters) -> BoxFuture<'static, Result<IdpServerResponse>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            inner: Arc::new(CallbacksInner {
                on_request: Box::new(on_request),
            }),
        }
    }
}

impl std::fmt::Debug for Callbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Callbacks").finish()
    }
}

struct CallbacksInner {
    on_request: Box<
        dyn Fn(IdpServerInfo, RequestParameters) -> BoxFuture<'static, Result<IdpServerResponse>>
            + Send
            + Sync,
    >,
    // on_refresh: Option<Box<dyn Fn(&IdpServerInfo) -> IdpServerResponse + Send + Sync>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct IdpServerInfo {
    pub issuer: String,
    pub client_id: String,
    pub request_scopes: Option<Vec<String>>,
}

#[derive(TypedBuilder)]
#[builder(field_defaults(setter(into)))]
#[non_exhaustive]
pub struct IdpServerResponse {
    pub access_token: String,
    pub expires: Option<Instant>,
    pub refresh_token: Option<String>,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct RequestParameters {
    pub deadline: Instant,
}

fn http_status_ok() -> String {
    "HTTP/1.1 200 OK\r\n\r\n".to_string()
}

fn handle_connection(mut stream: TcpStream) -> Option<String> {
    let mut reader = BufReader::new(&stream);
    let mut request = String::new();
    reader.read_line(&mut request).unwrap();

    let query_params = request.split_whitespace().nth(1).unwrap();
    let url = Url::parse(&format!("http://127.0.0.1:8000{query_params}")).unwrap();

    stream.write_all(http_status_ok().as_bytes()).unwrap();
    stream.flush().unwrap();

    // Extract the `code` query param and value
    url.query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, code)| code.to_string())
}

/// Spins up a listener on port, waits for any request from
/// the authentication provider and tries to return an `auth_code`
async fn listener(host: &str, port: u16) -> String {
    let urn = format!("{host}:{port}");
    let listener = TcpListener::bind(&urn).unwrap();
    println!("Listening on {}", urn);

    let mut auth_code = String::new();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        if let Some(code) = handle_connection(stream) {
            auth_code = code;
            break;
        };
    }

    auth_code.trim().to_string()
}

/// Return reqwest response
async fn http_send<Body: Into<reqwest::Body>>(
    http_client: &reqwest::Client,
    request: Request<Body>,
) -> http::Response<Bytes> {
    // Make the request
    let mut response = http_client
        .execute(request.try_into().unwrap())
        .await
        .unwrap();
    // Convert to http::Response
    let mut builder = http::Response::builder()
        .status(response.status())
        .version(response.version());
    std::mem::swap(builder.headers_mut().unwrap(), response.headers_mut());
    builder.body(response.bytes().await.unwrap()).unwrap()
}

pub(crate) async fn authenticate_stream(
    _conn: &mut Connection,
    credential: &Credential,
    _server_api: Option<&ServerApi>,
) -> Result<()> {
    let issuer_domain = credential
        .mechanism_properties
        .as_ref()
        .unwrap()
        .get("ISSUER_DOMAIN")
        .ok_or_else(|| auth_error("no issuer domain supplied in mechanism properties"))?
        .to_string()
        .trim_matches('"')
        .to_string();
    let client_id = credential
        .mechanism_properties
        .as_ref()
        .unwrap()
        .get("CLIENT_ID")
        .ok_or_else(|| auth_error("no issuer domain supplied in mechanism properties"))?
        .to_string()
        .trim_matches('"')
        .to_string();
    let client_secret = credential
        .mechanism_properties
        .as_ref()
        .unwrap()
        .get("CLIENT_SECRET")
        .ok_or_else(|| auth_error("no issuer domain supplied in mechanism properties"))?
        .to_string()
        .trim_matches('"')
        .to_string();
    println!("{}, {}, {}", issuer_domain, client_id, client_secret);

    let http_client = reqwest::Client::new();
    let state = {
        let mut rng = ThreadRng::default();
        let mut state = [0u8; 64];
        rng.fill_bytes(&mut state);
        state
    };
    let verifier = {
        let mut rng = ThreadRng::default();
        let mut verifier = [0u8; 64];
        rng.fill_bytes(&mut verifier);
        verifier
    };
    let state_str = data_encoding::BASE64URL.encode(&state);
    let verifier_str = data_encoding::BASE64URL_NOPAD.encode(&verifier);
    let challenge_digest = ring::digest::digest(&ring::digest::SHA256, verifier_str.as_bytes());
    let challenge = data_encoding::BASE64URL_NOPAD.encode(challenge_digest.as_ref());
    let challenge_method = "S256".to_string();

    let host = "127.0.0.1";
    let port = 8000u16;
    // It's very important that this exactly matches where it's provided in other places, protocol and trailing slash all
    let redirect_uri = format!("http://{host}:{port}/");

    // Fetch and instantiate a provider using a `well-known` uri from an issuer
    let request = provider::well_known(&issuer_domain).unwrap();
    let response = http_send(&http_client, request).await;
    let provider = Provider::from_response(response).unwrap();
    let auth_endpoint = provider.authorization_endpoint.to_string();
    // 1. Authenticate through web browser
    // user goes to embark auth url in browser
    // auth service returns auth_code to listener at `redirect_uri`
    // Add idp-specific extra query-parameters to the below `authorize_url`
    let authorize_url = format!(
        "{auth_endpoint}?\
code_challenge={challenge}&\
code_challenge_method=S256&\
response_type=code&\
client_id={client_id}&\
redirect_uri={redirect_uri}&\
state={state_str}&\
scope=openid+offline_access",
    );
    println!("Authorize at {authorize_url}");
    //open::with(authorize_url, "firefox").unwrap();

    let auth_code = listener(host, 7999).await;
    println!("Listener closed down");
    println!("Final code {}", auth_code);

    // 3. User now has 2 minutes to swap the auth code for an Embark Access token.
    // Make a `POST` request to the auth service /oauth2/token
    let scheme = AuthenticationScheme::Pkce(PkceCredentials::new(
        challenge.clone(),
        challenge_method.clone(),
        verifier_str.clone(),
        Some(client_secret.clone()),
    ));
    let client_authentication = ClientAuthentication::new(client_id, scheme, None, None);
    let exchange_request = provider
        .exchange_token_request(&redirect_uri, &client_authentication, &auth_code)
        .unwrap();

    let response = http_send(&http_client, exchange_request).await;

    // construct the response
    let access_token = Token::from_response(response).unwrap();

    // 4. Fetch the required JWKs
    let request = provider.jwks_request().unwrap();
    let response = http_send(&http_client, request).await;
    let jwks = JWKS::from_response(response).unwrap();

    let token_data = provider::verify_token::<Claims>(&access_token.access_token, &jwks.keys);
    dbg!(&token_data);
    dbg!(&access_token);
    let refresh_token = access_token.refresh_token.unwrap();
    let id_token = access_token.id_token.unwrap();
    let id_token_data = provider::verify_token::<Claims>(&id_token, &jwks.keys);
    dbg!(&id_token_data);
    // 5. Refresh token
    let request = provider
        .refresh_token_request(&client_authentication, &refresh_token)
        .unwrap();
    let response = http_send(&http_client, request).await;
    let new_refresh_token = Token::from_response(response).unwrap();
    dbg!(&new_refresh_token);

    //    let source = credential.source.as_deref().unwrap_or("$external");
    //    let callbacks = credential
    //        .oidc_callbacks
    //        .as_ref()
    //        .ok_or_else(|| auth_error("no callbacks supplied"))?
    //        .clone();
    //
    //    let mut start_doc = rawdoc! {};
    //    if let Some(username) = credential.username.as_deref() {
    //        start_doc.append("n", username);
    //    }
    //    let sasl_start = SaslStart::new(
    //        source.to_string(),
    //        AuthMechanism::MongoDbOidc,
    //        start_doc.into_bytes(),
    //        server_api.cloned(),
    //    )
    //    .into_command();
    //    let response = send_sasl_command(conn, sasl_start).await?;
    //    if response.done {
    //        return Err(invalid_auth_response());
    //    }
    //    let idp_response = {
    //        let server_info: IdpServerInfo =
    //            bson::from_slice(&response.payload).map_err(|_| invalid_auth_response())?;
    //        const CALLBACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
    //        let cb_params = RequestParameters {
    //            deadline: Instant::now() + CALLBACK_TIMEOUT,
    //        };
    //        (callbacks.inner.on_request)(server_info, cb_params).await?
    //    };
    //
    //    let sasl_continue = SaslContinue::new(
    //        source.to_string(),
    //        response.conversation_id,
    //        rawdoc! { "jwt": idp_response.access_token }.into_bytes(),
    //        server_api.cloned(),
    //    )
    //    .into_command();
    //    let response = send_sasl_command(conn, sasl_continue).await?;
    //    if !response.done {
    //        return Err(invalid_auth_response());
    //    }

    Ok(())
}

fn auth_error(s: impl AsRef<str>) -> Error {
    Error::authentication_error(MONGODB_OIDC_STR, s.as_ref())
}

fn invalid_auth_response() -> Error {
    Error::invalid_authentication_response(MONGODB_OIDC_STR)
}

async fn send_sasl_command(
    conn: &mut Connection,
    command: crate::cmap::Command,
) -> Result<SaslResponse> {
    let response = conn.send_command(command, None).await?;
    SaslResponse::parse(
        MONGODB_OIDC_STR,
        response.auth_response_body(MONGODB_OIDC_STR)?,
    )
}
