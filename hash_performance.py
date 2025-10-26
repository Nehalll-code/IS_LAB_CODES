"""
hash_performance.py

Compare performance of built-in hashes (MD5, SHA1, SHA256) vs the custom hash
and detect collisions over a dataset of random strings (50..100 strings of varying length).

Produces a simple report of timings and collision counts.
"""

import hashlib
import random
import string
import time
from collections import defaultdict
from hash_util import custom_hash_hex


def random_string(min_len=50, max_len=100):
    l = random.randint(min_len, max_len)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=l))


def measure_hash(func, data_list):
    start = time.perf_counter()
    digests = []
    for d in data_list:
        digests.append(func(d))
    elapsed = time.perf_counter() - start
    return elapsed, digests


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def custom_hex(s: str) -> str:
    return custom_hash_hex(s)


def collision_count(digests):
    counts = defaultdict(int)
    for d in digests:
        counts[d] += 1
    collisions = sum(1 for c in counts.values() if c > 1)
    return collisions, {d: c for d, c in counts.items() if c > 1}


if __name__ == '__main__':
    # Create dataset with random number of strings between 50 and 100
    n = random.randint(50, 100)
    data = [random_string() for _ in range(n)]
    print(f"Dataset size: {n}")

    results = {}
    for name, func in [('MD5', md5_hex), ('SHA1', sha1_hex), ('SHA256', sha256_hex), ('Custom32', custom_hex)]:
        t, digests = measure_hash(func, data)
        collisions, coll_map = collision_count(digests)
        results[name] = {
            'time_s': t,
            'collisions': collisions,
            'collision_map_sample': dict(list(coll_map.items())[:5])
        }

    print("\nResults:")
    for name, r in results.items():
        print(f"{name}: time={r['time_s']:.6f}s, collisions={r['collisions']}")
        if r['collisions']:
            print(f"  sample collisions: {r['collision_map_sample']}")
