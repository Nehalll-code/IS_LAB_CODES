def create_key_order(keyword):
    """Create the order of columns based on the keyword"""
    # Convert keyword to numbers based on alphabetical order
    order = {char: i for i, char in enumerate(sorted(keyword))}
    return [order[char] for char in keyword]

def pad_text(text, width):
    """Pad text to fit into the matrix"""
    padding = width - (len(text) % width)
    if padding < width:
        text += 'X' * padding
    return text

def transposition_encrypt(plaintext, keyword):
    """
    Encrypt using columnar transposition cipher
    Example:
    plaintext = "HELLO WORLD"
    keyword = "CRYPTO"
    """
    # Remove spaces and convert to uppercase
    plaintext = ''.join(plaintext.upper().split())
    
    # Get the width of the matrix from keyword length
    width = len(keyword)
    
    # Pad plaintext if necessary
    plaintext = pad_text(plaintext, width)
    
    # Create matrix
    height = len(plaintext) // width
    matrix = [[''] * width for _ in range(height)]
    
    # Fill matrix row by row
    for i in range(height):
        for j in range(width):
            matrix[i][j] = plaintext[i * width + j]
    
    # Get column order from keyword
    order = create_key_order(keyword)
    
    # Read off columns in keyword order
    ciphertext = ''
    for col in order:
        for row in range(height):
            ciphertext += matrix[row][col]
    
    return ciphertext

def transposition_decrypt(ciphertext, keyword):
    """Decrypt using columnar transposition cipher"""
    width = len(keyword)
    height = len(ciphertext) // width
    
    # Get column order
    order = create_key_order(keyword)
    
    # Create empty matrix
    matrix = [[''] * width for _ in range(height)]
    
    # Fill matrix column by column in keyword order
    pos = 0
    for col in order:
        for row in range(height):
            matrix[row][col] = ciphertext[pos]
            pos += 1
    
    # Read matrix row by row
    plaintext = ''
    for row in range(height):
        for col in range(width):
            plaintext += matrix[row][col]
    
    return plaintext

# Example usage
if __name__ == "__main__":
    message = "HELLO WORLD"
    key = "CRYPTO"
    
    encrypted = transposition_encrypt(message, key)
    decrypted = transposition_decrypt(encrypted, key)
    
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

    # Example from lab exercise
    message = "abcdefghi"
    key = "KEY"  # This would give us the permutation pattern shown in exercise
    
    encrypted = transposition_encrypt(message, key)
    print(f"\nExample from lab exercise:")
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")