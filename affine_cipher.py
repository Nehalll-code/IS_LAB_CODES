import string

def clean_text(text):
    """Remove spaces and convert to uppercase"""
    return ''.join(text.upper().split())

def mod_inverse(a, m):
    """Find modular multiplicative inverse"""
    for x in range(1, m):
        if ((a % m) * (x % m)) % m == 1:
            return x
    return None

def affine_encrypt(plaintext, mult_key, add_key):
    """
    Encrypt using affine cipher
    Example:
    plaintext = "HELLO"
    mult_key = 5
    add_key = 8
    """
    alphabet = string.ascii_uppercase
    plaintext = clean_text(plaintext)
    ciphertext = ''
    
    # Check if multiplicative key has inverse
    if mod_inverse(mult_key, 26) is None:
        raise ValueError("Multiplicative key must have an inverse in Z26")
    
    for char in plaintext:
        if char in alphabet:
            # Apply affine transformation: (ax + b) mod 26
            idx = (alphabet.index(char) * mult_key + add_key) % 26
            ciphertext += alphabet[idx]
        else:
            ciphertext += char
    return ciphertext

def affine_decrypt(ciphertext, mult_key, add_key):
    """Decrypt using inverse of affine transformation"""
    alphabet = string.ascii_uppercase
    inv_key = mod_inverse(mult_key, 26)
    if inv_key is None:
        raise ValueError("Multiplicative key must have an inverse in Z26")
    
    ciphertext = clean_text(ciphertext)
    plaintext = ''
    
    for char in ciphertext:
        if char in alphabet:
            # Apply inverse transformation: a^(-1)(x - b) mod 26
            idx = (inv_key * (alphabet.index(char) - add_key)) % 26
            plaintext += alphabet[idx]
        else:
            plaintext += char
    return plaintext

# Example usage
if __name__ == "__main__":
    message = "I am learning information security"
    mult_key = 15  # Must be coprime with 26
    add_key = 20
    
    encrypted = affine_encrypt(message, mult_key, add_key)
    decrypted = affine_decrypt(encrypted, mult_key, add_key)
    
    print(f"Original:  {message}")
    print(f"Keys:      a={mult_key}, b={add_key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")