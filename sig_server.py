"""
sig_server.py

Simple signature service.
Protocol (length-prefixed JSON):
- Client sends 8-byte big-endian length N followed by N bytes of UTF-8 JSON.
- JSON fields: { "op": "sign"|"verify", "alg": "RSA"|"ELGAMAL"|"SCHNORR", "message": base64, "key": {...} }
- For 'sign' the server uses provided private key parameters to compute a signature and returns JSON {"status":"ok","signature":...}
- For 'verify' the client provides public key and signature; server returns {"status":"ok","valid":true|false}

This is a teaching/demo server. Keep keys local and small for lab exercises.
"""

import socket
import struct
import json
import base64
from digital_signature_utils import rsa_sign, rsa_verify, elgamal_sign, elgamal_verify, schnorr_sign, schnorr_verify

HOST = '0.0.0.0'
PORT = 9010


def recv_n(conn, n):
    parts = []
    rem = n
    while rem > 0:
        chunk = conn.recv(rem)
        if not chunk:
            break
        parts.append(chunk)
        rem -= len(chunk)
    return b''.join(parts)


def handle_conn(conn, addr):
    try:
        hdr = conn.recv(8)
        if len(hdr) < 8:
            return
        (n,) = struct.unpack('>Q', hdr)
        body = recv_n(conn, n)
        req = json.loads(body.decode('utf-8'))

        op = req.get('op')
        alg = req.get('alg', 'RSA').upper()
        message = base64.b64decode(req.get('message', ''))
        key = req.get('key', {})

        if op == 'sign':
            if alg == 'RSA':
                # expect key: {"n":..., "d":...}
                n_k = int(key['n'])
                d_k = int(key['d'])
                sig = rsa_sign(message, (n_k, d_k))
                resp = {'status':'ok', 'signature': sig}
            elif alg == 'ELGAMAL':
                p = int(key['p']); g = int(key['g']); x = int(key['x'])
                r,s = elgamal_sign(message, p, g, x)
                resp = {'status':'ok', 'signature': [str(r), str(s)]}
            elif alg == 'SCHNORR':
                p = int(key['p']); q = int(key['q']); g = int(key['g']); x = int(key['x'])
                e,s = schnorr_sign(message, p, q, g, x)
                resp = {'status':'ok', 'signature': [str(e), str(s)]}
            else:
                resp = {'status':'error','error':'unknown algorithm'}
        elif op == 'verify':
            sig = req.get('signature')
            if alg == 'RSA':
                n_k = int(key['n']); e_k = int(key['e'])
                ok = rsa_verify(message, sig, (n_k, e_k))
                resp = {'status':'ok', 'valid': ok}
            elif alg == 'ELGAMAL':
                p = int(key['p']); g = int(key['g']); y = int(key['y'])
                r = int(sig[0]); s = int(sig[1])
                ok = elgamal_verify(message, (r, s), p, g, y)
                resp = {'status':'ok', 'valid': ok}
            elif alg == 'SCHNORR':
                p = int(key['p']); q = int(key['q']); g = int(key['g']); y = int(key['y'])
                e = int(sig[0]); s = int(sig[1])
                ok = schnorr_verify(message, (e, s), p, q, g, y)
                resp = {'status':'ok', 'valid': ok}
            else:
                resp = {'status':'error','error':'unknown algorithm'}
        else:
            resp = {'status':'error','error':'unknown operation'}

        out = json.dumps(resp).encode('utf-8')
        conn.sendall(struct.pack('>Q', len(out)))
        conn.sendall(out)
    finally:
        conn.close()


def run(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        print(f"Signature server listening on {host}:{port}")
        while True:
            conn, addr = s.accept()
            handle_conn(conn, addr)


if __name__ == '__main__':
    run()
