import string

def clean_text(text):
    """Remove spaces and convert to uppercase"""
    return ''.join(text.upper().split())

def additive_encrypt(plaintext, key):
    """
    Encrypt using additive (Caesar) cipher
    Example: 
    plaintext = "HELLO"
    key = 3
    Result: "KHOOR"
    """
    alphabet = string.ascii_uppercase
    plaintext = clean_text(plaintext)
    ciphertext = ''
    
    for char in plaintext:
        if char in alphabet:
            # Shift the character by key positions
            idx = (alphabet.index(char) + key) % 26
            ciphertext += alphabet[idx]
        else:
            ciphertext += char
    return ciphertext

def additive_decrypt(ciphertext, key):
    """Decrypt by shifting in opposite direction"""
    return additive_encrypt(ciphertext, -key)

# Example usage
if __name__ == "__main__":
    message = "I am learning information security"
    key = 20
    
    encrypted = additive_encrypt(message, key)
    decrypted = additive_decrypt(encrypted, key)
    
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")