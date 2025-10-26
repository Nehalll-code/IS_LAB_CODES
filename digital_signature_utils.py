"""
digital_signature_utils.py

Educational templates for digital signatures used in Lab 6.
Includes:
- RSA sign/verify (simple hash-then-sign using pow)
- ElGamal signature (classic scheme)
- Schnorr signature (educational; requires appropriate parameters)

NOTES:
- These implementations are for learning / lab demonstration only. They are not
  hardened PKCS#1 or standardized padding schemes and should not be used in
  production.
- Parameters (p,g,q) must be chosen correctly for Schnorr; this file provides
  simple helpers and small example parameters for testing.

Functions accept keys/parameters as integers/tuples so you can plug in keys
generated elsewhere (e.g., from your RSA/ElGamal modules).
"""

import hashlib
import random
from typing import Tuple, Any

# ---------- Helpers ----------
MASK_1024 = (1 << 1024) - 1


def sha256_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), 'big')


# ---------- RSA sign / verify (simplified) ----------
# Sign/verify by hashing the message with SHA-256 then signing the integer
# with modular exponentiation. public_key = (n, e), private_key = (n, d)

def rsa_sign(message: bytes, private_key: Tuple[int, int]) -> str:
    """Return signature as hex string."""
    n, d = private_key
    h = sha256_int(message)
    # reduce to modulus range
    h_mod = h % n
    sig = pow(h_mod, d, n)
    return hex(sig)[2:]


def rsa_verify(message: bytes, sig_hex: str, public_key: Tuple[int, int]) -> bool:
    n, e = public_key
    sig = int(sig_hex, 16)
    recovered = pow(sig, e, n)
    h = sha256_int(message) % n
    return recovered == h


# ---------- ElGamal signature (classic) ----------
# public: (p, g, y)  where y = g^x mod p
# private: x
# signature: (r, s)

def mod_inverse(a: int, m: int) -> int:
    """Modular inverse using extended gcd"""
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError('modular inverse does not exist')
    return x % m


def elgamal_sign(message: bytes, p: int, g: int, x: int) -> Tuple[int, int]:
    """Return (r, s) signature. x is private key, public y = g^x mod p."""
    h = sha256_int(message) % (p - 1)
    while True:
        k = random.randint(2, p - 2)
        if math_gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = mod_inverse(k, p - 1)
    s = (k_inv * (h - x * r)) % (p - 1)
    return (r, s)


def elgamal_verify(message: bytes, signature: Tuple[int, int], p: int, g: int, y: int) -> bool:
    r, s = signature
    if not (0 < r < p):
        return False
    h = sha256_int(message) % (p - 1)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2


# ---------- Schnorr signature (educational) ----------
# Requires group params (p, q, g) where q divides p-1 and g^q = 1 mod p.
# public: (p, q, g, y) where y = g^x mod p
# private: x in Z_q
# signature: (e, s) where e = H(m || r) mod q


def schnorr_sign(message: bytes, p: int, q: int, g: int, x: int) -> Tuple[int, int]:
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    e = int.from_bytes(hashlib.sha256(message + r.to_bytes((r.bit_length()+7)//8, 'big')).digest(), 'big') % q
    s = (k - x * e) % q
    return (e, s)


def schnorr_verify(message: bytes, signature: Tuple[int, int], p: int, q: int, g: int, y: int) -> bool:
    e, s = signature
    r_prime = (pow(g, s, p) * pow(y, e, p)) % p
    e_prime = int.from_bytes(hashlib.sha256(message + r_prime.to_bytes((r_prime.bit_length()+7)//8, 'big')).digest(), 'big') % q
    return e_prime == e


# ---------- Small utilities ----------

def math_gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


# ---------- Example usage (small/safe-for-lab only) ----------
if __name__ == '__main__':
    import argparse
    import json

    parser = argparse.ArgumentParser(description='Digital signature utilities demo (educational)')
    parser.add_argument('--demo', choices=['rsa', 'elgamal', 'schnorr'], default='rsa')
    args = parser.parse_args()

    msg = b"Test message for signature"

    if args.demo == 'rsa':
        # Small RSA example (for lab demo only) -- small primes, not secure
        p = 2953
        q = 3253
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        d = pow(e, -1, phi)
        pk = (n, e)
        sk = (n, d)
        sig = rsa_sign(msg, sk)
        print('RSA signature (hex):', sig)
        print('Verify:', rsa_verify(msg, sig, pk))

    elif args.demo == 'elgamal':
        # Small ElGamal demo (lab only)
        p = 2089
        g = 2
        x = 1234
        y = pow(g, x, p)
        sig = elgamal_sign(msg, p, g, x)
        print('ElGamal signature:', sig)
        print('Verify:', elgamal_verify(msg, sig, p, g, y))

    else:
        # Schnorr small demo. Choose p,q,g such that q divides p-1.
        # For demonstration we pick small values (not secure).
        q = 101
        p = 2 * q + 1  # p = 203 (not prime) -- for real use pick safe primes
        # We'll instead pick a known small safe prime for demo
        p = 7199
        q = 3599  # (p-1)/2
        g = 3
        x = 123
        y = pow(g, x, p)
        sig = schnorr_sign(msg, p, q, g, x)
        print('Schnorr signature:', sig)
        print('Verify:', schnorr_verify(msg, sig, p, q, g, y))
