"""
hash_server.py

Simple TCP server that accepts one connection at a time. Protocol:
- Client sends 8-byte big-endian length N (unsigned integer)
- Client then sends N bytes of data
- Server computes custom hash (from hash_util) and returns 8-byte ASCII hex string (without newline)

This is a minimal template for lab testing of data-integrity via hashes.
"""

import socket
import struct
from hash_util import custom_hash_hex

HOST = '0.0.0.0'
PORT = 9000

def handle_connection(conn, addr):
    print(f"Connection from {addr}")
    try:
        # Read 8-byte length
        length_bytes = conn.recv(8)
        if len(length_bytes) < 8:
            print("Invalid length header")
            return
        (n,) = struct.unpack('>Q', length_bytes)
        # Read n bytes
        remaining = n
        chunks = []
        while remaining > 0:
            chunk = conn.recv(min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b''.join(chunks)
        if len(data) != n:
            print("Warning: received less data than expected")
        # Compute hash
        hexhash = custom_hash_hex(data)
        # Send back 8-byte ASCII hex
        conn.sendall(hexhash.encode('ascii'))
        print(f"Processed {n} bytes, hash={hexhash}")
    finally:
        conn.close()


def run_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"Hash server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)


if __name__ == '__main__':
    run_server()
