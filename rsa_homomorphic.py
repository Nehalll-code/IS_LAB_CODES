"""
rsa_homomorphic.py

Simple RSA implementation and demonstration of multiplicative homomorphism.
- generate_keypair(bits=1024)
- encrypt(pub_key, m)
- decrypt(priv_key, c)
- homomorphic_multiply(c1, c2, pub_key)

Notes:
- This demo uses Python's built-in pow for modular arithmetic.
- For real keys use a vetted crypto library (PyCryptodome). This file is educational.
"""

import random
import math
from typing import Tuple

# Try to import PyCryptodome RSA for reliable key generation; fallback if not available.
try:
    from Crypto.PublicKey import RSA
    def generate_keypair(bits=1024):
        key = RSA.generate(bits)
        pub = (key.n, key.e)
        priv = (key.n, key.d)
        return pub, priv
except Exception:
    # Lightweight fallback (not secure)
    def generate_prime(bits: int) -> int:
        def is_probable_prime(n, k=8):
            if n < 2:
                return False
            small_primes = [2,3,5,7,11,13,17,19,23,29]
            for p in small_primes:
                if n == p:
                    return True
                if n % p == 0:
                    return False
            d = n - 1
            r = 0
            while d % 2 == 0:
                r += 1
                d //= 2
            import random
            for _ in range(k):
                a = random.randrange(2, n - 1)
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(r - 1):
                    x = (x * x) % n
                    if x == n - 1:
                        break
                else:
                    return False
            return True
        while True:
            p = random.getrandbits(bits) | 1 | (1 << (bits - 1))
            if is_probable_prime(p):
                return p

    def generate_keypair(bits=512):
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while q == p:
            q = generate_prime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        # ensure e is coprime to phi
        if math.gcd(e, phi) != 1:
            e = 3
            while math.gcd(e, phi) != 1:
                e += 2
        d = pow(e, -1, phi)
        return (n, e), (n, d)


def encrypt(pub_key: Tuple[int,int], m: int) -> int:
    n, e = pub_key
    if not (0 <= m < n):
        raise ValueError('message out of range')
    return pow(m, e, n)


def decrypt(priv_key: Tuple[int,int], c: int) -> int:
    n, d = priv_key
    return pow(c, d, n)


def homomorphic_multiply(c1: int, c2: int, pub_key: Tuple[int,int]) -> int:
    n, _ = pub_key
    return (c1 * c2) % n


if __name__ == '__main__':
    print('RSA homomorphic demo: generate keys')
    pub, priv = generate_keypair(1024)
    n, e = pub
    print('n (modulus) bits:', n.bit_length())
    a = 7
    b = 3
    ca = encrypt(pub, a)
    cb = encrypt(pub, b)
    print('Ciphertext a:', ca)
    print('Ciphertext b:', cb)
    cmul = homomorphic_multiply(ca, cb, pub)
    print('Encrypted product (ciphertext):', cmul)
    dec = decrypt(priv, cmul)
    print('Decrypted product:', dec)
    assert dec == (a * b) % n
    print('RSA multiplicative homomorphism demo complete')
