use crate::{
    client::{
        auth::{oidc, AuthMechanism, Credential},
        options::ClientOptions,
    },
    test::log_uncaptured,
    Client,
};
use std::sync::{Arc, Mutex};

macro_rules! mongodb_uri {
    () => {
        "mongodb://localhost/"
    };
    ( $user:literal ) => {
        concat!("mongodb://", $user, "@localhost/")
    };
}

macro_rules! mongodb_uri_single {
    () => {
        concat!(mongodb_uri!(), "?authMechanism=MONGODB-OIDC")
    };
    ( $user:literal ) => {
        concat!(mongodb_uri!($user), "?authMechanism=MONGODB-OIDC")
    };
}

macro_rules! mongodb_uri_multi {
    () => {
        concat!(
            mongodb_uri!(),
            "?authMechanism=MONGODB-OIDC&directConnection=true"
        )
    };
    ( $user:literal ) => {
        concat!(
            mongodb_uri!($user),
            "?authMechanism=MONGODB-OIDC&directConnection=true"
        )
    };
}

macro_rules! token_dir {
    ( $path: literal ) => {
        concat!("/tmp/tokens", $path)
    };
}

// Machine Callback tests
// Prose test 1.1 Single Principal Implicit Username
#[tokio::test]
async fn machine_single_principal_implicit_username() -> anyhow::Result<()> {
    use bson::Document;
    use futures_util::FutureExt;

    if std::env::var("OIDC_TOKEN_DIR").is_err() {
        log_uncaptured("Skipping OIDC test");
        return Ok(());
    }

    // we need to assert that the callback is only called once
    let call_count = Arc::new(Mutex::new(0));
    let cb_call_count = call_count.clone();

    let mut opts = ClientOptions::parse(mongodb_uri_single!()).await?;
    opts.credential = Credential::builder()
        .mechanism(AuthMechanism::MongoDbOidc)
        .oidc_callback(oidc::Callback::machine(move |_| {
            let call_count = cb_call_count.clone();
            *call_count.lock().unwrap() += 1;
            async move {
                Ok(oidc::IdpServerResponse {
                    access_token: tokio::fs::read_to_string(token_dir!("test_user1")).await?,
                    expires: None,
                    refresh_token: None,
                })
            }
            .boxed()
        }))
        .build()
        .into();
    let client = Client::with_options(opts)?;
    client
        .database("test")
        .collection::<Document>("test")
        .find_one(None, None)
        .await?;
    assert_eq!(1, *(*call_count).lock().unwrap());
    Ok(())
}

// Human Callback tests
// Prose test 1.1 Single Principal Implicit Username
#[tokio::test]
async fn human_single_principal_implicit_username() -> anyhow::Result<()> {
    use crate::{
        client::{
            auth::{oidc, AuthMechanism, Credential},
            options::ClientOptions,
        },
        test::log_uncaptured,
        Client,
    };
    use bson::Document;
    use futures_util::FutureExt;

    if std::env::var("OIDC_TOKEN_DIR").is_err() {
        log_uncaptured("Skipping OIDC test");
        return Ok(());
    }

    // we need to assert that the callback is only called once
    let call_count = Arc::new(Mutex::new(0));
    let cb_call_count = call_count.clone();

    let mut opts = ClientOptions::parse(mongodb_uri_single!()).await?;
    opts.credential = Credential::builder()
        .mechanism(AuthMechanism::MongoDbOidc)
        .oidc_callback(oidc::Callback::human(move |_| {
            let call_count = cb_call_count.clone();
            *call_count.lock().unwrap() += 1;
            async move {
                Ok(oidc::IdpServerResponse {
                    access_token: tokio::fs::read_to_string(token_dir!("test_user1")).await?,
                    expires: None,
                    refresh_token: None,
                })
            }
            .boxed()
        }))
        .build()
        .into();
    let client = Client::with_options(opts)?;
    client
        .database("test")
        .collection::<Document>("test")
        .find_one(None, None)
        .await?;
    assert_eq!(1, *(*call_count).lock().unwrap());
    Ok(())
}

// Prose test 1.2 Single Principal Explicit Username
#[tokio::test]
async fn human_single_principal_explicit_username() -> anyhow::Result<()> {
    use crate::{
        client::{
            auth::{oidc, AuthMechanism, Credential},
            options::ClientOptions,
        },
        test::log_uncaptured,
        Client,
    };
    use bson::Document;
    use futures_util::FutureExt;

    if std::env::var("OIDC_TOKEN_DIR").is_err() {
        log_uncaptured("Skipping OIDC test");
        return Ok(());
    }

    // we need to assert that the callback is only called once
    let call_count = Arc::new(Mutex::new(0));
    let cb_call_count = call_count.clone();

    let mut opts = ClientOptions::parse(mongodb_uri!("test_user1")).await?;
    opts.credential = Credential::builder()
        .mechanism(AuthMechanism::MongoDbOidc)
        .oidc_callback(oidc::Callback::human(move |_| {
            let call_count = cb_call_count.clone();
            *call_count.lock().unwrap() += 1;
            async move {
                Ok(oidc::IdpServerResponse {
                    access_token: tokio::fs::read_to_string(token_dir!("test_user1")).await?,
                    expires: None,
                    refresh_token: None,
                })
            }
            .boxed()
        }))
        .build()
        .into();
    let client = Client::with_options(opts)?;
    client
        .database("test")
        .collection::<Document>("test")
        .find_one(None, None)
        .await?;
    assert_eq!(1, *(*call_count).lock().unwrap());
    Ok(())
}

// Prose test 1.3 Multiple Principal User1
#[tokio::test]
async fn human_multiple_principal_user1() -> anyhow::Result<()> {
    use crate::{
        client::{
            auth::{oidc, AuthMechanism, Credential},
            options::ClientOptions,
        },
        test::log_uncaptured,
        Client,
    };
    use bson::Document;
    use futures_util::FutureExt;

    if std::env::var("OIDC_TOKEN_DIR").is_err() {
        log_uncaptured("Skipping OIDC test");
        return Ok(());
    }

    // we need to assert that the callback is only called once
    let call_count = Arc::new(Mutex::new(0));
    let cb_call_count = call_count.clone();

    let mut opts = ClientOptions::parse(mongodb_uri_multi!("user1")).await?;
    opts.credential = Credential::builder()
        .mechanism(AuthMechanism::MongoDbOidc)
        .oidc_callback(oidc::Callback::human(move |_| {
            let call_count = cb_call_count.clone();
            *call_count.lock().unwrap() += 1;
            async move {
                Ok(oidc::IdpServerResponse {
                    access_token: tokio::fs::read_to_string(token_dir!("test_user1")).await?,
                    expires: None,
                    refresh_token: None,
                })
            }
            .boxed()
        }))
        .build()
        .into();
    let client = Client::with_options(opts)?;
    client
        .database("test")
        .collection::<Document>("test")
        .find_one(None, None)
        .await?;
    assert_eq!(1, *(*call_count).lock().unwrap());
    Ok(())
}

// Prose test 1.4 Multiple Principal User2
#[tokio::test]
async fn human_multiple_principal_user2() -> anyhow::Result<()> {
    use crate::{
        client::{
            auth::{oidc, AuthMechanism, Credential},
            options::ClientOptions,
        },
        test::log_uncaptured,
        Client,
    };
    use bson::Document;
    use futures_util::FutureExt;

    if std::env::var("OIDC_TOKEN_DIR").is_err() {
        log_uncaptured("Skipping OIDC test");
        return Ok(());
    }

    // we need to assert that the callback is only called once
    let call_count = Arc::new(Mutex::new(0));
    let cb_call_count = call_count.clone();

    let mut opts = ClientOptions::parse(mongodb_uri_multi!("user2")).await?;
    opts.credential = Credential::builder()
        .mechanism(AuthMechanism::MongoDbOidc)
        .oidc_callback(oidc::Callback::human(move |_| {
            let call_count = cb_call_count.clone();
            *call_count.lock().unwrap() += 1;
            async move {
                Ok(oidc::IdpServerResponse {
                    access_token: tokio::fs::read_to_string(token_dir!("test_user2")).await?,
                    expires: None,
                    refresh_token: None,
                })
            }
            .boxed()
        }))
        .build()
        .into();
    let client = Client::with_options(opts)?;
    client
        .database("test")
        .collection::<Document>("test")
        .find_one(None, None)
        .await?;
    assert_eq!(1, *(*call_count).lock().unwrap());
    Ok(())
}
