# Fuzzing mongo-rust-driver

This directory contains fuzzing tests for the MongoDB Rust driver. These tests help identify potential security issues and robustness problems by providing randomly generated inputs to various components.

## Message Header Length Fuzzing
Tests overflow conditions in MongoDB wire protocol message headers. This fuzzer specifically targets:
- Integer overflow in length calculations
- Negative lengths
- Length vs actual payload size mismatches
- Length remaining underflow
- Edge cases around DEFAULT_MAX_MESSAGE_SIZE_BYTES (48MB)

### Running the Fuzzer
To run the message header length fuzzer:
```bash
cargo fuzz run message_header_length
```

### Test Cases
The fuzzer includes several pre-generated test cases in `corpus/message_header_length/`:
- Maximum valid length (48MB)
- Length near i32::MAX
- Negative length
- Length exactly at maximum
- Length slightly over maximum

These test cases help ensure the fuzzer explores known edge cases while also searching for new problematic inputs.
