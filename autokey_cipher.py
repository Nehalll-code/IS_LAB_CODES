import string

def clean_text(text):
    """Remove spaces and convert to uppercase"""
    return ''.join(text.upper().split())

def autokey_encrypt(plaintext, key):
    """
    Encrypt using Autokey cipher
    Example:
    plaintext = "HELLO"
    key = 7
    """
    alphabet = string.ascii_uppercase
    plaintext = clean_text(plaintext)
    ciphertext = ''
    
    for i, char in enumerate(plaintext):
        if char in alphabet:
            # For first character, use the initial key
            if i == 0:
                shift = key
            # For subsequent characters, use previous plaintext character position
            else:
                shift = alphabet.index(plaintext[i-1])
            # Apply shift
            idx = (alphabet.index(char) + shift) % 26
            ciphertext += alphabet[idx]
        else:
            ciphertext += char
    return ciphertext

def autokey_decrypt(ciphertext, key):
    """Decrypt using initial key and recovered plaintext"""
    alphabet = string.ascii_uppercase
    ciphertext = clean_text(ciphertext)
    plaintext = ''
    
    for i, char in enumerate(ciphertext):
        if char in alphabet:
            # For first character, use the initial key
            if i == 0:
                shift = key
            # For subsequent characters, use previous recovered plaintext character
            else:
                shift = alphabet.index(plaintext[i-1])
            # Apply reverse shift
            idx = (alphabet.index(char) - shift) % 26
            plaintext += alphabet[idx]
        else:
            plaintext += char
    return plaintext

# Example usage
if __name__ == "__main__":
    message = "the house is being sold tonight"
    key = 7
    
    encrypted = autokey_encrypt(message, key)
    decrypted = autokey_decrypt(encrypted, key)
    
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")