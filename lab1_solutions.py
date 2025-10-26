from symmetric_ciphers import SymmetricCiphers
import numpy as np

def main():
    cipher = SymmetricCiphers()
    
    print("Lab Exercise Solutions\n")
    
    # Exercise 1
    print("Exercise 1:")
    message = "I am learning information security"
    
    # a) Additive cipher with key = 20
    print("\na) Additive cipher (key = 20):")
    encrypted = cipher.additive_cipher_encrypt(message, 20)
    decrypted = cipher.additive_cipher_decrypt(encrypted, 20)
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    # b) Multiplicative cipher with key = 15
    print("\nb) Multiplicative cipher (key = 15):")
    encrypted = cipher.multiplicative_cipher_encrypt(message, 15)
    decrypted = cipher.multiplicative_cipher_decrypt(encrypted, 15)
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    # c) Affine cipher with key = (15, 20)
    print("\nc) Affine cipher (key = (15, 20)):")
    encrypted = cipher.affine_cipher_encrypt(message, 15, 20)
    decrypted = cipher.affine_cipher_decrypt(encrypted, 15, 20)
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    # Exercise 2
    print("\nExercise 2:")
    message = "the house is being sold tonight"
    
    # a) Vigenere cipher with key = "dollars"
    print("\na) Vigenere cipher (key = 'dollars'):")
    encrypted = cipher.vigenere_cipher_encrypt(message, "dollars")
    decrypted = cipher.vigenere_cipher_decrypt(encrypted, "dollars")
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    # b) Autokey cipher with key = 7
    print("\nb) Autokey cipher (key = 7):")
    encrypted = cipher.autokey_cipher_encrypt(message, 7)
    decrypted = cipher.autokey_cipher_decrypt(encrypted, 7)
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    
    # Exercise 3
    print("\nExercise 3:")
    message = "The key is hidden under the door pad"
    key = "GUIDANCE"
    print("\nPlayfair cipher (key = 'GUIDANCE'):")
    encrypted = cipher.playfair_cipher_encrypt(message, key)
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    
    # Exercise 4
    print("\nExercise 4:")
    message = "We live in an insecure world"
    key_matrix = np.array([[3, 3], [2, 7]])
    print("\nHill cipher:")
    encrypted = cipher.hill_cipher_encrypt(message, key_matrix)
    print(f"Original:  {message}")
    print(f"Encrypted: {encrypted}")
    
    # Exercise 5
    print("\nExercise 5:")
    print("Known plaintext-ciphertext pair: 'yes' -> 'CIW'")
    print("This is a shift cipher (additive cipher)")
    print("Ciphertext found in cave: 'XVIEWYWI'")
    print("Using the same shift as determined from yes->CIW")
    shift = (ord('C') - ord('y')) % 26
    print(f"Determined shift: {shift}")
    cave_text = cipher.additive_cipher_decrypt("XVIEWYWI", shift)
    print(f"Cave text decrypted: {cave_text}")
    
    # Exercise 6
    print("\nExercise 6:")
    print("Affine cipher with known plaintext-ciphertext pair: 'ab' -> 'GL'")
    print("Ciphertext: XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS")
    # We need to solve for the affine cipher parameters (a,b) using the known pair
    # This would require solving the system of equations:
    # (0*a + b) mod 26 = 6  (for a->G)
    # (1*a + b) mod 26 = 11 (for b->L)
    # Then use these parameters to decrypt the message

if __name__ == "__main__":
    main()