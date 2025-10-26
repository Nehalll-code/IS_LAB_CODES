import string

def clean_text(text):
    """Remove spaces and convert to uppercase"""
    return ''.join(text.upper().split())

def vigenere_encrypt(plaintext, keyword):
    """
    Encrypt using Vigenere cipher
    Example:
    plaintext = "HELLO"
    keyword = "KEY"
    """
    alphabet = string.ascii_uppercase
    plaintext = clean_text(plaintext)
    keyword = clean_text(keyword)
    ciphertext = ''
    key_idx = 0
    
    for char in plaintext:
        if char in alphabet:
            # Get shift from keyword letter
            shift = alphabet.index(keyword[key_idx])
            # Apply shift to current character
            idx = (alphabet.index(char) + shift) % 26
            ciphertext += alphabet[idx]
            # Move to next keyword letter
            key_idx = (key_idx + 1) % len(keyword)
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, keyword):
    """Decrypt by shifting in opposite direction"""
    alphabet = string.ascii_uppercase
    ciphertext = clean_text(ciphertext)
    keyword = clean_text(keyword)
    plaintext = ''
    key_idx = 0
    
    for char in ciphertext:
        if char in alphabet:
            # Get shift from keyword letter
            shift = alphabet.index(keyword[key_idx])
            # Apply reverse shift
            idx = (alphabet.index(char) - shift) % 26
            plaintext += alphabet[idx]
            # Move to next keyword letter
            key_idx = (key_idx + 1) % len(keyword)
        else:
            plaintext += char
    return plaintext

# Example usage
if __name__ == "__main__":
    message = "the house is being sold tonight"
    keyword = "DOLLARS"
    
    encrypted = vigenere_encrypt(message, keyword)
    decrypted = vigenere_decrypt(encrypted, keyword)
    
    print(f"Original:  {message}")
    print(f"Keyword:   {keyword}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")