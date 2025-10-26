import string

def clean_text(text):
    """Remove spaces and convert to uppercase"""
    return ''.join(text.upper().split())

def create_playfair_matrix(key):
    """Create 5x5 Playfair matrix from key"""
    key = clean_text(key)
    matrix = []
    used_chars = set()
    alphabet = string.ascii_uppercase.replace('J', '')  # I/J combined
    
    # Fill with key first
    for char in key:
        if char not in used_chars and char != 'J':
            matrix.append(char)
            used_chars.add(char)
    
    # Fill remaining alphabet
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    
    # Convert to 5x5 matrix
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    """Find position of character in matrix"""
    if char == 'J':
        char = 'I'
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return i, j
    return None

def playfair_encrypt(plaintext, key):
    """
    Encrypt using Playfair cipher
    Example:
    plaintext = "HELLO"
    key = "KEYWORD"
    """
    matrix = create_playfair_matrix(key)
    plaintext = clean_text(plaintext).replace('J', 'I')
    
    # If length is odd, append 'X'
    if len(plaintext) % 2 != 0:
        plaintext += 'X'
    
    # Split into digraphs
    digraphs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
    
    # If digraph has same letters, insert 'X'
    processed_digraphs = []
    for d in digraphs:
        if len(d) == 2 and d[0] == d[1]:
            processed_digraphs.append(d[0] + 'X')
            plaintext = d[1] + plaintext[len(processed_digraphs)*2:]
        else:
            processed_digraphs.append(d)
    
    ciphertext = ''
    for digraph in processed_digraphs:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])
        
        if row1 == row2:  # Same row
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]
    
    return ciphertext

def print_matrix(matrix):
    """Print Playfair matrix in readable format"""
    for row in matrix:
        print(' '.join(row))

# Example usage
if __name__ == "__main__":
    message = "The key is hidden under the door pad"
    key = "GUIDANCE"
    
    print("Playfair Matrix:")
    matrix = create_playfair_matrix(key)
    print_matrix(matrix)
    print()
    
    encrypted = playfair_encrypt(message, key)
    
    print(f"Original:  {message}")
    print(f"Key:       {key}")
    print(f"Encrypted: {encrypted}")
    # Note: Decryption is similar but with reverse rules