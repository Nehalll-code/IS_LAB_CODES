"""
elgamal_homomorphic.py

Demonstration of ElGamal encryption and homomorphic multiplication.
- Uses `ElGamalCipher` class if present in the workspace (elgamal_cipher.py).
- Provides generate_keys, encrypt, decrypt, homomorphic_multiply helper functions.

Notes:
- ElGamal supports multiplicative homomorphism: multiplying two ciphertexts yields
  a ciphertext of the product of plaintexts.
- Encrypted comparison (greater-than) is not directly supported by ElGamal. That
  requires more advanced protocols (e.g., secure comparison protocols).
"""

from elgamal_cipher import ElGamalCipher


def demo():
    print('ElGamal homomorphic demo using local ElGamalCipher')
    eg = ElGamalCipher(key_size=256)
    keys = eg.generate_keys()
    pub = keys['public_key']  # (p,g,y)
    priv = keys['private_key']

    m1 = 6
    m2 = 9
    c1 = eg.encrypt(m1, public_key=pub)
    c2 = eg.encrypt(m2, public_key=pub)
    print('Ciphertext m1:', c1)
    print('Ciphertext m2:', c2)

    # Homomorphic multiplication: multiply component-wise -> plaintext multiplication
    p, g, y = pub
    c1a, c1b = c1
    c2a, c2b = c2
    cprod = ((c1a * c2a) % p, (c1b * c2b) % p)
    print('Encrypted product (ciphertext):', cprod)

    # Decrypt product
    eg.set_keys(p, g, y, priv)
    dec = eg.decrypt(cprod)
    print('Decrypted product (as string or int):', dec)

    # Note: dec may be string if originally encoded; above we used ints and
    # the ElGamalCipher decrypt tries to decode bytes to string. If you pass integers
    # as messages, the encryption/decryption path will convert accordingly.

if __name__ == '__main__':
    demo()
