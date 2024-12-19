use byteorder::{LittleEndian, WriteBytesExt};
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const DEFAULT_MAX_MESSAGE_SIZE_BYTES: i32 = 48 * 1024 * 1024; // 48MB

fn create_test_case(
    filename: &Path,
    length: i32,
    request_id: i32,
    response_to: i32,
    op_code: i32,
) -> io::Result<()> {
    let file = fs::File::create(filename)?;
    let mut writer = io::BufWriter::new(file);

    // Write header fields in little-endian format
    writer.write_i32::<LittleEndian>(length)?;
    writer.write_i32::<LittleEndian>(request_id)?;
    writer.write_i32::<LittleEndian>(response_to)?;
    writer.write_i32::<LittleEndian>(op_code)?;
    writer.flush()?;

    Ok(())
}

fn main() -> io::Result<()> {
    // Create corpus directory
    let corpus_dir = Path::new("..").join("corpus").join("message_header_length");
    fs::create_dir_all(&corpus_dir)?;

    // Define test cases with their expected values
    let test_cases = [
        ("max_valid_length", DEFAULT_MAX_MESSAGE_SIZE_BYTES), // 48MB
        ("near_i32_max", i32::MAX - 1),                       // Almost max i32
        ("negative_length", -1),                              // Negative length
        ("exact_max_length", DEFAULT_MAX_MESSAGE_SIZE_BYTES), // Exactly 48MB
        ("over_max_length", DEFAULT_MAX_MESSAGE_SIZE_BYTES + 1), // Just over 48MB
    ];

    // Create test cases
    for (name, length) in test_cases.iter() {
        let file_path = corpus_dir.join(name);
        create_test_case(
            &file_path, *length, 1,    // request_id
            0,    // response_to
            2013, // op_code (OP_MSG)
        )?;
        println!(
            "Created test case '{}' with length {} (0x{:08x})",
            name, length, length
        );
    }

    Ok(())
}
