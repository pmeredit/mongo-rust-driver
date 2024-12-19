import struct
import os

def create_test_case(filename, length, request_id=1, response_to=0, op_code=2013):
    """Create a test case with the specified header values."""
    header = struct.pack("<iiii", length, request_id, response_to, op_code)
    with open(filename, "wb") as f:
        f.write(header)

def main():
    # Create corpus directory
    corpus_dir = "corpus/message_header_length"
    os.makedirs(corpus_dir, exist_ok=True)

    # Create test cases
    test_cases = [
        ("max_valid_length", 48*1024*1024),  # 48MB
        ("near_i32_max", 2**31-1),           # i32::MAX
        ("negative_length", -1),              # Negative length
        ("exact_max_length", 48*1024*1024),   # Exactly max
        ("over_max_length", 48*1024*1024 + 1) # Slightly over max
    ]

    for name, length in test_cases:
        create_test_case(os.path.join(corpus_dir, name), length)

if __name__ == "__main__":
    main()
