"""
multipart_server.py

Server that accepts a length-prefixed series of parts.
Protocol:
- Client first sends 4-byte big-endian unsigned int P (number of parts)
- For i in 1..P: client sends 4-byte big-endian unsigned int L_i then L_i bytes of data
- Server reassembles parts in order, computes the custom hash, and returns 8 ASCII hex chars

This is useful to demonstrate sending large messages in segments and verifying integrity
after reassembly.
"""

import socket
import struct
from hash_util import custom_hash_hex

HOST = '0.0.0.0'
PORT = 9001


def recv_all(conn, n):
    parts = []
    remaining = n
    while remaining > 0:
        chunk = conn.recv(min(4096, remaining))
        if not chunk:
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b''.join(parts)


def handle_connection(conn, addr):
    print(f"Multipart connection from {addr}")
    try:
        header = conn.recv(4)
        if len(header) < 4:
            print("Invalid header")
            return
        (parts_count,) = struct.unpack('>I', header)
        assembled = []
        for _ in range(parts_count):
            lenb = conn.recv(4)
            if len(lenb) < 4:
                print("Invalid part length")
                return
            (L,) = struct.unpack('>I', lenb)
            data = recv_all(conn, L)
            if len(data) != L:
                print("Warning: short read for part")
            assembled.append(data)
        message = b''.join(assembled)
        hexhash = custom_hash_hex(message)
        conn.sendall(hexhash.encode('ascii'))
        print(f"Reassembled {len(message)} bytes from {parts_count} parts, hash={hexhash}")
    finally:
        conn.close()


def run_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"Multipart hash server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr)


if __name__ == '__main__':
    run_server()
