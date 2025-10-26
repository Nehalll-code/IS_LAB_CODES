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

def multiplicative_encrypt(plaintext, key):
    """
    Encrypt using multiplicative cipher
    Example:
    plaintext = "HELLO"
    key = 7
    """
    alphabet = string.ascii_uppercase
    plaintext = clean_text(plaintext)
    ciphertext = ''
    
    # Check if key has multiplicative inverse
    if mod_inverse(key, 26) is None:
        raise ValueError("Key must have a multiplicative inverse in Z26")
    
    for char in plaintext:
        if char in alphabet:
            # Multiply the position by key
            idx = (alphabet.index(char) * key) % 26
            ciphertext += alphabet[idx]
        else:
            ciphertext += char
    return ciphertext

def multiplicative_decrypt(ciphertext, key):
    """Decrypt using multiplicative inverse of key"""
    inv_key = mod_inverse(key, 26)
    if inv_key is None:
        raise ValueError("Key must have a multiplicative inverse in Z26")
    return multiplicative_encrypt(ciphertext, inv_key)

# Example usage
if __name__ == "__main__":
    message = "I am learning information security"
    key = 15  # Must be coprime with 26
    
    encrypted = multiplicative_encrypt(message, key)
    decrypted = multiplicative_decrypt(encrypted, key)
    
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")