import string
import numpy as np

def clean_text(text):
    """Remove spaces and convert to uppercase"""
    return ''.join(text.upper().split())

def hill_encrypt(plaintext, key_matrix):
    """
    Encrypt using Hill cipher
    Example:
    plaintext = "HELLO"
    key_matrix = np.array([[3, 3], [2, 7]])
    """
    alphabet = string.ascii_uppercase
    plaintext = clean_text(plaintext)
    n = len(key_matrix)
    
    # Pad plaintext if necessary
    if len(plaintext) % n != 0:
        plaintext += 'X' * (n - (len(plaintext) % n))
    
    ciphertext = ''
    # Process n characters at a time
    for i in range(0, len(plaintext), n):
        block = plaintext[i:i+n]
        # Convert block to vector of numbers
        vector = np.array([alphabet.index(c) for c in block])
        # Matrix multiplication
        result = np.dot(key_matrix, vector) % 26
        # Convert back to letters
        ciphertext += ''.join(alphabet[int(x)] for x in result)
    
    return ciphertext

def matrix_mod_inverse(matrix, modulus):
    """Find the modular multiplicative inverse of a matrix"""
    # This is a simplified version - for a complete implementation,
    # you would need to handle all edge cases
    det = int(round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    adj = np.round(det * np.linalg.inv(matrix)).astype(int)
    return (det_inv * adj % modulus)

def hill_decrypt(ciphertext, key_matrix):
    """Decrypt using inverse of key matrix"""
    # Note: This is a basic implementation and might not work for all cases
    try:
        inv_matrix = matrix_mod_inverse(key_matrix, 26)
        return hill_encrypt(ciphertext, inv_matrix)
    except:
        return "Error: Could not find inverse matrix"

# Example usage
if __name__ == "__main__":
    message = "We live in an insecure world"
    # 2x2 matrix example
    key_matrix = np.array([[3, 3],
                          [2, 7]])
    
    encrypted = hill_encrypt(message, key_matrix)
    decrypted = hill_decrypt(encrypted, key_matrix)
    
    print(f"Original:  {message}")
    print(f"Key Matrix:\n{key_matrix}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")