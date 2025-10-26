"""
sse_cipher.py

Symmetric Searchable Encryption (SSE) educational template.
- Deterministic tokenization via HMAC-SHA256 (keyed PRF) for index keys.
- AES-CBC to encrypt stored doc IDs and document payload (with random IVs).

Important notes:
- Tokenization uses HMAC (deterministic for a given key) to allow search.
- Encrypted index keys are token_hex strings; values are lists of base64 iv+ciphertext
  representing encrypted document IDs (or encrypted doc payloads if desired).
- This is an educational template for lab use only.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hmac
import hashlib
import base64
from typing import Dict, List, Tuple

BLOCK_SIZE = AES.block_size


def generate_symmetric_key(length: int = 32) -> bytes:
    """Return a random symmetric key (bytes)."""
    return get_random_bytes(length)


def _tokenize(key: bytes, word: str) -> str:
    """Return deterministic token hex for a word using HMAC-SHA256 (keyed PRF)."""
    return hmac.new(key, word.encode('utf-8'), hashlib.sha256).hexdigest()


def encrypt_data(key: bytes, data: bytes) -> bytes:
    """AES-CBC encrypt, return iv + ciphertext (raw bytes)."""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, BLOCK_SIZE))
    return iv + ct


def decrypt_data(key: bytes, iv_ciphertext: bytes) -> bytes:
    """Decrypt iv + ciphertext and return plaintext bytes."""
    iv = iv_ciphertext[:BLOCK_SIZE]
    ct = iv_ciphertext[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt


def create_index(documents: Dict[str, str], key: bytes) -> Dict[str, List[str]]:
    """Create encrypted inverted index.

    Returns a dict mapping token_hex -> list of base64(iv+ciphertext) encrypted doc_id strings.
    """
    index: Dict[str, List[str]] = {}
    for doc_id, doc in documents.items():
        for word in doc.split():
            token = _tokenize(key, word.lower())
            entry = index.setdefault(token, [])
            # encrypt doc_id deterministically? For privacy we encrypt doc_id with random IV
            enc = encrypt_data(key, doc_id.encode('utf-8'))
            entry.append(base64.b64encode(enc).decode('ascii'))
    return index


def search(encrypted_index: Dict[str, List[str]], query: str, key: bytes) -> List[str]:
    """Search encrypted index and return decrypted doc IDs that match query."""
    token = _tokenize(key, query.lower())
    results = []
    if token not in encrypted_index:
        return results
    for enc_b64 in encrypted_index[token]:
        enc = base64.b64decode(enc_b64)
        try:
            doc_id = decrypt_data(key, enc).decode('utf-8')
            results.append(doc_id)
        except Exception:
            # decryption failure
            continue
    return results


if __name__ == '__main__':
    # Small demo
    docs = {
        'doc1': 'This is a document with some words',
        'doc2': 'Another document with different words',
        'doc3': 'Yet another document with some common words'
    }
    key = generate_symmetric_key()
    idx = create_index(docs, key)
    print('Tokens in index:', len(idx))
    q = 'document'
    matches = search(idx, q, key)
    print(f"Search for '{q}':", matches)
