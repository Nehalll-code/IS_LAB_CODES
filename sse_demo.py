"""
sse_demo.py

Small driver to demonstrate SSE (uses `sse_cipher.py`).
Generates a corpus of 10 documents, builds encrypted inverted index, and runs a few searches.
"""

from sse_cipher import generate_symmetric_key, create_index, search


def make_corpus():
    corpus = {}
    for i in range(1, 11):
        corpus[f'doc{i}'] = f"This is document number {i} with sample words and value {i}"
    return corpus


def main():
    docs = make_corpus()
    key = generate_symmetric_key()
    idx = create_index(docs, key)
    queries = ['document', 'sample', 'value', 'missingword']
    for q in queries:
        hits = search(idx, q, key)
        print(f"Query='{q}' -> hits: {hits}")

if __name__ == '__main__':
    main()
