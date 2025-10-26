"""
pkse_demo.py

Small driver to demonstrate PKSE (uses `pkse_cipher.py`).
Builds a 10-document corpus and runs searches using RSA-based deterministic tokens (lab demo only).
"""

from pkse_cipher import generate_keys, create_index, search


def make_corpus():
    corpus = {}
    for i in range(1, 11):
        corpus[f'doc{i}'] = f"This is document number {i} with sample words and value {i}"
    return corpus


def main():
    docs = make_corpus()
    pub, priv = generate_keys(1024)
    idx = create_index(docs, pub)
    queries = ['document', 'sample', 'value', 'missingword']
    for q in queries:
        hits = search(idx, q, pub, priv)
        print(f"Query='{q}' -> hits: {hits}")

if __name__ == '__main__':
    main()
