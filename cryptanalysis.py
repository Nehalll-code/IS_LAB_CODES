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

def additive_decrypt(ciphertext, key):
    """Decrypt using additive cipher with given key"""
    alphabet = string.ascii_uppercase
    plaintext = ''
    for char in ciphertext:
        if char in alphabet:
            idx = (alphabet.index(char) - key) % 26
            plaintext += alphabet[idx]
        else:
            plaintext += char
    return plaintext

def affine_decrypt(ciphertext, mult_key, add_key):
    """Decrypt using affine cipher with given keys"""
    alphabet = string.ascii_uppercase
    inv_key = mod_inverse(mult_key, 26)
    if inv_key is None:
        return None
    
    plaintext = ''
    for char in ciphertext:
        if char in alphabet:
            idx = (inv_key * (alphabet.index(char) - add_key)) % 26
            plaintext += alphabet[idx]
        else:
            plaintext += char
    return plaintext

def brute_force_additive(ciphertext, known_plain=None, known_cipher=None, birthday_hint=None):
    """
    Brute force attack on additive cipher
    If birthday_hint is provided, tries keys near that number first
    """
    alphabet = string.ascii_uppercase
    possible_solutions = []
    
    # If we have a known plaintext-ciphertext pair
    if known_plain and known_cipher:
        known_plain = clean_text(known_plain)
        known_cipher = clean_text(known_cipher)
        if len(known_plain) != len(known_cipher):
            return []
        
        # Calculate the key from the known pair
        key = (alphabet.index(known_cipher[0]) - alphabet.index(known_plain[0])) % 26
        decrypted = additive_decrypt(ciphertext, key)
        possible_solutions.append((key, decrypted))
        return possible_solutions
    
    # If we have a birthday hint
    if birthday_hint:
        # Try keys near the birthday first
        keys_to_try = list(range(birthday_hint-2, birthday_hint+3)) + \
                     [k for k in range(26) if k not in range(birthday_hint-2, birthday_hint+3)]
    else:
        keys_to_try = range(26)
    
    # Try all possible keys
    for key in keys_to_try:
        decrypted = additive_decrypt(ciphertext, key)
        possible_solutions.append((key, decrypted))
    
    return possible_solutions

def brute_force_affine(ciphertext, known_plain="ab", known_cipher="GL"):
    """
    Brute force attack on affine cipher
    Using known plaintext-ciphertext pair to determine possible keys
    """
    alphabet = string.ascii_uppercase
    possible_solutions = []
    
    # Convert known texts
    known_plain = clean_text(known_plain)
    known_cipher = clean_text(known_cipher)
    
    # Get indices
    p1, p2 = [alphabet.index(c) for c in known_plain]
    c1, c2 = [alphabet.index(c) for c in known_cipher]
    
    # Try all possible multiplicative keys (must be coprime with 26)
    for a in range(1, 26):
        if mod_inverse(a, 26) is None:
            continue
            
        # Calculate possible additive key
        b = (c1 - a * p1) % 26
        
        # Verify this key pair works for second character
        if (a * p2 + b) % 26 == c2:
            # This is a valid key pair
            decrypted = affine_decrypt(ciphertext, a, b)
            if decrypted:
                possible_solutions.append(((a, b), decrypted))
    
    return possible_solutions

# Example usage
if __name__ == "__main__":
    # Example from lab exercises - Additive cipher with birthday hint
    ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
    print("Brute force attack on additive cipher with birthday hint:")
    solutions = brute_force_additive(ciphertext, birthday_hint=13)
    for key, plaintext in solutions[:5]:  # Show first 5 possibilities
        print(f"Key = {key}: {plaintext}")
    
    # Example from lab exercises - Affine cipher with known plaintext
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    print("\nBrute force attack on affine cipher with known plaintext 'ab' -> 'GL':")
    solutions = brute_force_affine(ciphertext)
    for keys, plaintext in solutions:
        print(f"Keys a={keys[0]}, b={keys[1]}: {plaintext}")