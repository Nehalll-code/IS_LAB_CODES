"""
hash_client.py

Simple TCP client to send a message to `hash_server.py` and verify the returned custom hash
against a locally computed hash.

Usage examples:
    python hash_client.py "Hello world"

Protocol (must match server): send 8-byte big-endian length followed by message bytes.
Receive 8 ASCII hex chars as result.
"""

import socket
import struct
import argparse
from hash_util import custom_hash_hex, verify_hash

HOST = '127.0.0.1'
PORT = 9000


def send_message(message: bytes, host=HOST, port=PORT) -> str:
    n = len(message)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(struct.pack('>Q', n))
        s.sendall(message)
        # expect 8 ascii hex chars back
        resp = b''
        while len(resp) < 8:
            chunk = s.recv(8 - len(resp))
            if not chunk:
                break
            resp += chunk
    return resp.decode('ascii') if resp else ''


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send data to hash server and verify')
    parser.add_argument('message', nargs='?', default='hello world', help='Message to send')
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    args = parser.parse_args()

    msg_bytes = args.message.encode('utf-8')
    printed = send_message(msg_bytes, host=args.host, port=args.port)
    local = custom_hash_hex(msg_bytes)
    print(f"Server returned: {printed}")
    print(f"Local hash:    {local}")
    if verify_hash(msg_bytes, printed):
        print("Integrity verified: hashes match")
    else:
        print("Integrity failure: hashes do not match")
