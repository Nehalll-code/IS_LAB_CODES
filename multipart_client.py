"""
multipart_client.py

Send a message split into parts to `multipart_server.py`.
Usage:
    python multipart_client.py "A long message..." --parts 5

Protocol (server must match):
- send 4-byte parts count
- for each part: send 4-byte length then bytes
- receive 8 ASCII hex chars back
"""

import socket
import struct
import argparse
from hash_util import custom_hash_hex, verify_hash

HOST = '127.0.0.1'
PORT = 9001


def split_into_parts(data: bytes, parts: int):
    if parts <= 1:
        return [data]
    n = len(data)
    base = n // parts
    parts_list = []
    i = 0
    for p in range(parts):
        end = i + base + (1 if p < (n % parts) else 0)
        parts_list.append(data[i:end])
        i = end
    return parts_list


def send_parts(message: bytes, parts: int, host=HOST, port=PORT) -> str:
    parts_list = split_into_parts(message, parts)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(struct.pack('>I', len(parts_list)))
        for p in parts_list:
            s.sendall(struct.pack('>I', len(p)))
            if len(p):
                s.sendall(p)
        # receive 8 ascii hex
        resp = b''
        while len(resp) < 8:
            chunk = s.recv(8 - len(resp))
            if not chunk:
                break
            resp += chunk
    return resp.decode('ascii') if resp else ''


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('message', nargs='?', default='hello multipart world')
    parser.add_argument('--parts', type=int, default=3)
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    args = parser.parse_args()

    msg_bytes = args.message.encode('utf-8')
    returned = send_parts(msg_bytes, args.parts, host=args.host, port=args.port)
    local = custom_hash_hex(msg_bytes)
    print(f"Server returned: {returned}")
    print(f"Local hash:    {local}")
    if verify_hash(msg_bytes, returned):
        print("Integrity verified after reassembly")
    else:
        print("Integrity failure after reassembly")
