"""
hash_util.py

Provides the user-defined hash function required by Lab 5 (start value 5381, multiply by 33,
add ASCII, mixing, and keep within 32-bit range). Also includes helpers to compute and verify
hashes and a small CLI for quick tests.
"""

from typing import Union

MASK_32 = 0xFFFFFFFF

def custom_hash(data: Union[str, bytes]) -> int:
    """Compute the custom 32-bit hash as specified.

    Algorithm:
    - Start with h = 5381
    - For each byte/char: h = ((h * 33) + value) with additional bit mixing
    - Keep h within 32-bit by applying MASK_32

    Returns integer hash (0..2^32-1).
    """
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data

    h = 5381
    for b in data_bytes:
        # multiply by 33 and add byte
        h = ((h * 33) + b) & MASK_32
        # extra mixing step: left rotate 5 and XOR
        h = (((h << 5) | (h >> (32 - 5))) & MASK_32) ^ h
    return h


def custom_hash_hex(data: Union[str, bytes]) -> str:
    """Return hex string of 8 hex chars (32-bit) for convenience."""
    return f"{custom_hash(data):08x}"


def verify_hash(data: Union[str, bytes], expected_hex: str) -> bool:
    """Verify that the custom hash of data matches expected hex string."""
    return custom_hash_hex(data) == expected_hex.lower()


if __name__ == '__main__':
    # Quick CLI test
    import argparse
    parser = argparse.ArgumentParser(description='Compute custom 32-bit hash')
    parser.add_argument('message', nargs='?', default='hello world', help='Message to hash')
    args = parser.parse_args()

    h = custom_hash_hex(args.message)
    print(f"Message: {args.message}")
    print(f"Custom hash (32-bit hex): {h}")
