#![no_main]
use libfuzzer_sys::fuzz_target;
use mongodb::cmap::conn::wire::header::Header;

fuzz_target!(|data: &[u8]| {
    // Only process if we have enough data for a header
    if data.len() < 16 { return; }

    // Try to parse the header from the fuzz input
    if let Ok(header) = Header::from_slice(data) {
        // Check for potential integer overflow in length field
        if header.length <= 0 {
            panic!("Invalid negative length: {}", header.length);
        }

        // Check for length field exceeding actual data size
        if header.length as usize > data.len() {
            panic!("Length overflow: header claims {} bytes but only {} available",
                  header.length, data.len());
        }
    }
});
