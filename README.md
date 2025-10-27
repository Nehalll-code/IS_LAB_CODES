IS_Lab 
===================

This repository contains educational implementations and templates for common cryptographic primitives and lab exercises used in the IS lab course. The files are intentionally simple and well‑commented so you can study, adapt, and run them during your end‑semester lab exam.

Prerequisites
-------------
- Python 3.8+ (3.10 or 3.11 recommended)
- Recommended packages (install in your active environment):

```powershell
python -m pip install --upgrade pip
pip install pycryptodome
```

If you prefer a requirements file, create one with:

```powershell
pip freeze > requirements.txt
```

Security note
-------------
These implementations are for teaching and lab use only. They intentionally use simplified algorithms (raw RSA, small parameters, no padding) to make the math and flow clear. Do not use these scripts for production or to protect real secrets.

Repository layout (high level)
-----------------------------
- Basic classical ciphers (useful for Labs 1–3)
    - `additive_cipher.py`, `multiplicative_cipher.py`, `affine_cipher.py`, `vigenere_cipher.py`, `autokey_cipher.py`, `playfair_cipher.py`, `hill_cipher.py`, `transposition_cipher.py`

- Symmetric block ciphers and utilities
    - `aes_cipher.py`, `des_cipher.py`, `triple_des_cipher.py`, `symmetric_ciphers.py`

- Hashing and integrity (Lab 5)
    - `hash_util.py` — custom 32-bit hash (start 5381, multiply by 33 + mixing)
    - `hash_server.py` / `hash_client.py` — single-shot integrity server/client demo
    - `multipart_server.py` / `multipart_client.py` — split/reassemble integrity demo
    - `hash_performance.py` — compare MD5, SHA-1, SHA-256, and the custom hash (timings + collisions)

- Asymmetric crypto & signatures (Labs 4 & 6)
    - `rsa_cipher.py`, `rsa_homomorphic.py` (RSA & multiplicative homomorphism)
    - `elgamal_cipher.py`, `elgamal_homomorphic.py` (ElGamal & multiplicative homomorphism)
    - `rabin_cipher.py`
    - `digital_signature_utils.py`, `sig_server.py`, `sig_client.py` — signature helpers and client/server demo (RSA, ElGamal, Schnorr)

- Public-Key / Partially Homomorphic (Lab 7)
    - `paillier_cipher.py` — Paillier implementation (additive homomorphism)

- Searchable Encryption (Lab 8)
    - `sse_cipher.py`, `sse_demo.py` — Symmetric Searchable Encryption (HMAC tokenization + AES payload encryption)
    - `pkse_cipher.py`, `pkse_demo.py` — Public-key Searchable Encryption (demonstration using deterministic RSA tokens)

- Key management and access control
    IS_Lab_Code_Helper
    ===================

    This repository contains educational implementations and templates for common cryptographic primitives and lab exercises used in the IS lab course. The files are intentionally simple and well‑commented so you can study, adapt, and run them during your end‑semester lab exam.

    How to run the common demos
    ---------------------------
    Open a PowerShell terminal in the repository root (for example `C:\Users\Nehal\Desktop\Is_lab_code_helper`).

    1) Quick sanity: compute custom hash

    ```powershell
    python .\hash_util.py "hello world"
    ```

    2) Hash server / client (single-shot)

    Terminal A (server):
    ```powershell
    python .\hash_server.py
    ```

    Terminal B (client):
    ```powershell
    python .\hash_client.py "Message to check"
    ```

    3) Multipart integrity demo (split message into parts)

    Terminal A (server):
    ```powershell
    python .\multipart_server.py
    ```

    Terminal B (client):
    ```powershell
    python .\multipart_client.py "A long message to split and verify" --parts 5
    ```

    4) Hash performance experiment

    ```powershell
    python .\hash_performance.py
    ```

    5) Run Paillier demo (additive homomorphism)

    ```powershell
    python .\paillier_cipher.py
    ```

    6) RSA homomorphic demo (multiplicative)

    ```powershell
    python .\rsa_homomorphic.py
    ```

    7) ElGamal homomorphic demo

    ```powershell
    python .\elgamal_homomorphic.py
    ```

    8) Signature server/client (Lab 6 work-flow)

    Start signature server:
    ```powershell
    python .\sig_server.py
    ```

    Use the client to request a sign/verify operation (example: RSA sign):
    ```powershell
    python .\sig_client.py --op sign --alg RSA --message "Hello" --key '{"n":"<n>","d":"<d>"}'
    ```

    9) Searchable encryption demos (Lab 8)

    ```powershell
    python .\sse_demo.py
    python .\pkse_demo.py
    ```

    Notes and troubleshooting
    -------------------------
    - Windows firewall: if servers fail to accept connections, allow Python through Windows Defender Firewall or run on localhost and use `127.0.0.1`.
    - Large key generation can be slow on low-end machines. For demos you can lower key sizes (e.g., 512 bits) but do not treat them as secure.
    - Some demos use PyCryptodome. If an import fails, install the package: `pip install pycryptodome`.

    Testing and quick validation
    ----------------------------
    Run a short import check to ensure modules load:

    ```powershell
    python - <<'PY'
    import importlib
    modules = ['hash_util','paillier_cipher','rsa_homomorphic','elgamal_cipher','sse_cipher','pkse_cipher']
    for m in modules:
            try:
                    importlib.import_module(m)
                    print(m, 'OK')
            except Exception as e:
                    print(m, 'ERROR ->', e)
    PY
    ```

    Extending the repository
    ------------------------
    - Add more algorithms (e.g., ECC / OPRF-based SE) as separate modules.
    - Integrate `key_management.py` with the demo servers to allow persistent key storage.
    - Replace educational primitives with PyCryptodome-verified schemes and proper padding (PKCS#1 or RSA-OAEP) for stronger demos.

    References & further reading
    --------------------------
    - Menezes, van Oorschot and Vanstone — Handbook of Applied Cryptography
    - Boneh & Waters — Searchable Encryption literature
    - PyCryptodome documentation: https://pycryptodome.readthedocs.io
