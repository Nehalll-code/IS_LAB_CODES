"""
sig_client.py

Client to interact with `sig_server.py` for signing and verifying messages.
Sends length-prefixed JSON (8-byte big-endian length) and receives length-prefixed JSON reply.

Examples:
  # RSA sign (server uses private d)
  python sig_client.py --op sign --alg RSA --message "Hello" --key '{"n":"12345","d":"6789"}'

  # RSA verify
  python sig_client.py --op verify --alg RSA --message "Hello" --key '{"n":"12345","e":"65537"}' --signature '<hex>'

For lab use you can also call server to sign (server-side keys) or verify signatures.
"""

import argparse
import socket
import struct
import json
import base64

HOST = '127.0.0.1'
PORT = 9010


def send_request(req: dict, host=HOST, port=PORT) -> dict:
    body = json.dumps(req).encode('utf-8')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(struct.pack('>Q', len(body)))
        s.sendall(body)
        hdr = s.recv(8)
        if len(hdr) < 8:
            raise RuntimeError('no response header')
        (n,) = struct.unpack('>Q', hdr)
        resp = b''
        while len(resp) < n:
            chunk = s.recv(n - len(resp))
            if not chunk:
                break
            resp += chunk
    return json.loads(resp.decode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default=HOST)
    parser.add_argument('--port', type=int, default=PORT)
    parser.add_argument('--op', choices=['sign','verify'], required=True)
    parser.add_argument('--alg', choices=['RSA','ELGAMAL','SCHNORR'], default='RSA')
    parser.add_argument('--message', required=True)
    parser.add_argument('--key', help='JSON string with key parameters', required=True)
    parser.add_argument('--signature', help='Signature (hex for RSA or list for others)')
    args = parser.parse_args()

    key_obj = json.loads(args.key)
    req = {
        'op': args.op,
        'alg': args.alg,
        'message': base64.b64encode(args.message.encode('utf-8')).decode('ascii'),
        'key': key_obj
    }
    if args.op == 'verify':
        # signature: if RSA, pass hex string; else pass list
        if args.alg == 'RSA':
            req['signature'] = args.signature
        else:
            # expect e.g. "123,456" or JSON array string
            if args.signature.startswith('['):
                req['signature'] = json.loads(args.signature)
            else:
                req['signature'] = args.signature.split(',')

    resp = send_request(req, host=args.host, port=args.port)
    print('Server response:')
    print(json.dumps(resp, indent=2))
