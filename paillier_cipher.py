"""
paillier_cipher.py

Paillier cryptosystem educational implementation.

Features:
- generate_keypair(bits=512)
- encrypt(pub_key, m)
- decrypt(priv_key, ciphertext)
- homomorphic_add(c1, c2, pub_key)  # ciphertext addition -> plaintext addition
- homomorphic_scalar_mul(c, k, pub_key)  # multiply plaintext by scalar k

Notes:
- This implementation is for lab/demo use only. It is not optimized for production.
"""

import random
import math
import sys
from typing import Tuple

# Miller-Rabin primality test

def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # find r and d such that n-1 = 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        r += 1
        d //= 2
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


def generate_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if is_probable_prime(p):
            return p


def lcm(a: int, b: int) -> int:
    return a // math.gcd(a, b) * b


def L(u: int, n: int) -> int:
    return (u - 1) // n


def generate_keypair(bits: int = 512) -> Tuple[Tuple[int,int], Tuple[int,int,int]]:
    """Generate Paillier keypair.
    Returns (public_key, private_key)
    public_key: (n, nsquare)
    private_key: (lambda, mu, n)
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    nsquare = n * n
    lam = lcm(p - 1, q - 1)
    # choose g = n + 1 for simplicity
    g = n + 1
    # compute mu = (L(g^lambda mod n^2))^{-1} mod n
    x = pow(g, lam, nsquare)
    l_val = L(x, n)
    mu = pow(l_val, -1, n)
    public_key = (n, nsquare, g)
    private_key = (lam, mu, n)
    return public_key, private_key


def encrypt(pub_key: Tuple[int,int,int], m: int) -> int:
    n, nsquare, g = pub_key
    if not (0 <= m < n):
        raise ValueError('plaintext out of range')
    while True:
        r = random.randrange(1, n)
        if math.gcd(r, n) == 1:
            break
    c = (pow(g, m, nsquare) * pow(r, n, nsquare)) % nsquare
    return c


def decrypt(priv_key: Tuple[int,int,int], ciphertext: int) -> int:
    lam, mu, n = priv_key
    nsquare = n * n
    u = pow(ciphertext, lam, nsquare)
    l_val = L(u, n)
    m = (l_val * mu) % n
    return m


def homomorphic_add(c1: int, c2: int, pub_key: Tuple[int,int,int]) -> int:
    # ciphertext multiplication corresponds to plaintext addition
    n, nsquare, _ = pub_key
    return (c1 * c2) % nsquare


def homomorphic_scalar_mul(c: int, k: int, pub_key: Tuple[int,int,int]) -> int:
    # c^k mod n^2 corresponds to plaintext multiplied by k
    n, nsquare, _ = pub_key
    return pow(c, k, nsquare)


if __name__ == '__main__':
    print('Paillier demo: generating small keypair (this may take a few seconds)')
    pub, priv = generate_keypair(512)
    n, nsquare, g = pub
    print('Public n:', n)
    a = 15
    b = 25
    ca = encrypt(pub, a)
    cb = encrypt(pub, b)
    print('Ciphertext a:', ca)
    print('Ciphertext b:', cb)
    csum = homomorphic_add(ca, cb, pub)
    print('Encrypted sum (ciphertext):', csum)
    dec = decrypt(priv, csum)
    print('Decrypted sum:', dec)
    assert dec == (a + b) % n
    print('Paillier demo complete')
