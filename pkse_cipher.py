"""
pkse_cipher.py

Public-Key Searchable Encryption (PKSE) educational template.

This demo uses a deterministic RSA-style token for index keys by computing
token = (hash(word) ** e) mod n (i.e., raw RSA on the word-hash). This is
NOT secure for production (no padding) but is deterministic and suitable for
lab demonstration of PKSE concepts.

Functions:
- generate_keys(bits=2048)
- create_index(documents, pub_key) -> dict mapping token_int -> list of ciphertext_int
- search(encrypted_index, query, pub_key, priv_key) -> list of doc_id strings

Caveats:
- Deterministic raw RSA (no padding) is insecure. This file is for teaching only.
"""

from Crypto.PublicKey import RSA
import hashlib
from typing import Dict, List, Tuple


def generate_keys(bits: int = 2048) -> Tuple[Tuple[int,int], Tuple[int,int]]:
    key = RSA.generate(bits)
    pub = (key.n, key.e)
    priv = (key.n, key.d)
    return pub, priv


def _word_hash_int(word: str, n: int) -> int:
    h = hashlib.sha256(word.encode('utf-8')).digest()
    return int.from_bytes(h, 'big') % n


def create_index(documents: Dict[str, str], pub_key: Tuple[int,int]) -> Dict[int, List[int]]:
    n, e = pub_key
    index: Dict[int, List[int]] = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            w = word.lower()
            h_int = _word_hash_int(w, n)
            token = pow(h_int, e, n)  # deterministic token via raw RSA
            entry = index.setdefault(token, [])
            # encrypt doc id using raw RSA (deterministic) for demo
            doc_int = int.from_bytes(doc_id.encode('utf-8'), 'big')
            cipher_doc = pow(doc_int, e, n)
            entry.append(cipher_doc)
    return index


def search(encrypted_index: Dict[int, List[int]], query: str, pub_key: Tuple[int,int], priv_key: Tuple[int,int]) -> List[str]:
    n, e = pub_key
    n2, d = priv_key
    assert n == n2
    h_int = _word_hash_int(query.lower(), n)
    token = pow(h_int, e, n)
    results: List[str] = []
    if token not in encrypted_index:
        return results
    for c in encrypted_index[token]:
        m = pow(c, d, n)
        # convert back to string
        try:
            b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            results.append(b.decode('utf-8'))
        except Exception:
            continue
    return results


if __name__ == '__main__':
    # Demo
    docs = {
        'doc1': 'This is a sample document',
        'doc2': 'Another sample document with extra words',
        'doc3': 'Different content with different words'
    }
    pub, priv = generate_keys(1024)
    idx = create_index(docs, pub)
    q = 'document'
    res = search(idx, q, pub, priv)
    print(f"PKSE search for '{q}':", res)
