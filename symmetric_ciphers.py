import string
import numpy as np

class SymmetricCiphers:
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        
    def clean_text(self, text):
        """Remove spaces and convert to uppercase"""
        return ''.join(text.upper().split())
    
    def mod_inverse(self, a, m):
        """Find modular multiplicative inverse"""
        for x in range(1, m):
            if ((a % m) * (x % m)) % m == 1:
                return x
        return None

    # Additive (Caesar) Cipher
    def additive_cipher_encrypt(self, plaintext, key):
        plaintext = self.clean_text(plaintext)
        ciphertext = ''
        for char in plaintext:
            if char in self.alphabet:
                idx = (self.alphabet.index(char) + key) % 26
                ciphertext += self.alphabet[idx]
            else:
                ciphertext += char
        return ciphertext
    
    def additive_cipher_decrypt(self, ciphertext, key):
        return self.additive_cipher_encrypt(ciphertext, -key)
    
    # Multiplicative Cipher
    def multiplicative_cipher_encrypt(self, plaintext, key):
        if self.mod_inverse(key, 26) is None:
            raise ValueError("Key must have a multiplicative inverse in Z26")
        plaintext = self.clean_text(plaintext)
        ciphertext = ''
        for char in plaintext:
            if char in self.alphabet:
                idx = (self.alphabet.index(char) * key) % 26
                ciphertext += self.alphabet[idx]
            else:
                ciphertext += char
        return ciphertext
    
    def multiplicative_cipher_decrypt(self, ciphertext, key):
        inv_key = self.mod_inverse(key, 26)
        if inv_key is None:
            raise ValueError("Key must have a multiplicative inverse in Z26")
        return self.multiplicative_cipher_encrypt(ciphertext, inv_key)
    
    # Affine Cipher
    def affine_cipher_encrypt(self, plaintext, mult_key, add_key):
        if self.mod_inverse(mult_key, 26) is None:
            raise ValueError("Multiplicative key must have an inverse in Z26")
        plaintext = self.clean_text(plaintext)
        ciphertext = ''
        for char in plaintext:
            if char in self.alphabet:
                idx = (self.alphabet.index(char) * mult_key + add_key) % 26
                ciphertext += self.alphabet[idx]
            else:
                ciphertext += char
        return ciphertext
    
    def affine_cipher_decrypt(self, ciphertext, mult_key, add_key):
        inv_key = self.mod_inverse(mult_key, 26)
        if inv_key is None:
            raise ValueError("Multiplicative key must have an inverse in Z26")
        ciphertext = self.clean_text(ciphertext)
        plaintext = ''
        for char in ciphertext:
            if char in self.alphabet:
                idx = (inv_key * (self.alphabet.index(char) - add_key)) % 26
                plaintext += self.alphabet[idx]
            else:
                plaintext += char
        return plaintext
    
    # Vigenere Cipher
    def vigenere_cipher_encrypt(self, plaintext, keyword):
        plaintext = self.clean_text(plaintext)
        keyword = self.clean_text(keyword)
        ciphertext = ''
        key_idx = 0
        
        for char in plaintext:
            if char in self.alphabet:
                shift = self.alphabet.index(keyword[key_idx])
                idx = (self.alphabet.index(char) + shift) % 26
                ciphertext += self.alphabet[idx]
                key_idx = (key_idx + 1) % len(keyword)
            else:
                ciphertext += char
        return ciphertext
    
    def vigenere_cipher_decrypt(self, ciphertext, keyword):
        ciphertext = self.clean_text(ciphertext)
        keyword = self.clean_text(keyword)
        plaintext = ''
        key_idx = 0
        
        for char in ciphertext:
            if char in self.alphabet:
                shift = self.alphabet.index(keyword[key_idx])
                idx = (self.alphabet.index(char) - shift) % 26
                plaintext += self.alphabet[idx]
                key_idx = (key_idx + 1) % len(keyword)
            else:
                plaintext += char
        return plaintext
    
    # Autokey Cipher
    def autokey_cipher_encrypt(self, plaintext, key):
        plaintext = self.clean_text(plaintext)
        ciphertext = ''
        for i, char in enumerate(plaintext):
            if char in self.alphabet:
                if i == 0:
                    shift = key
                else:
                    shift = self.alphabet.index(plaintext[i-1])
                idx = (self.alphabet.index(char) + shift) % 26
                ciphertext += self.alphabet[idx]
            else:
                ciphertext += char
        return ciphertext
    
    def autokey_cipher_decrypt(self, ciphertext, key):
        ciphertext = self.clean_text(ciphertext)
        plaintext = ''
        for i, char in enumerate(ciphertext):
            if char in self.alphabet:
                if i == 0:
                    shift = key
                else:
                    shift = self.alphabet.index(plaintext[i-1])
                idx = (self.alphabet.index(char) - shift) % 26
                plaintext += self.alphabet[idx]
            else:
                plaintext += char
        return plaintext
    
    # Playfair Cipher
    def create_playfair_matrix(self, key):
        key = self.clean_text(key)
        matrix = []
        used_chars = set()
        
        # Fill with key first
        for char in key:
            if char not in used_chars and char != 'J':  # I/J combined
                matrix.append(char)
                used_chars.add(char)
        
        # Fill remaining alphabet
        for char in self.alphabet:
            if char not in used_chars and char != 'J':
                matrix.append(char)
                used_chars.add(char)
        
        return [matrix[i:i+5] for i in range(0, 25, 5)]
    
    def find_position(self, matrix, char):
        if char == 'J':
            char = 'I'
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j
        return None
    
    def playfair_cipher_encrypt(self, plaintext, key):
        matrix = self.create_playfair_matrix(key)
        plaintext = self.clean_text(plaintext).replace('J', 'I')
        
        # Prepare text (split into digraphs)
        if len(plaintext) % 2 != 0:
            plaintext += 'X'
        
        digraphs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
        ciphertext = ''
        
        for digraph in digraphs:
            row1, col1 = self.find_position(matrix, digraph[0])
            row2, col2 = self.find_position(matrix, digraph[1])
            
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
    
    # Hill Cipher
    def hill_cipher_encrypt(self, plaintext, key_matrix):
        plaintext = self.clean_text(plaintext)
        n = len(key_matrix)
        
        # Pad plaintext if necessary
        if len(plaintext) % n != 0:
            plaintext += 'X' * (n - (len(plaintext) % n))
        
        ciphertext = ''
        for i in range(0, len(plaintext), n):
            block = plaintext[i:i+n]
            # Convert block to vector of numbers
            vector = np.array([self.alphabet.index(c) for c in block])
            # Matrix multiplication
            result = np.dot(key_matrix, vector) % 26
            # Convert back to letters
            ciphertext += ''.join(self.alphabet[int(x)] for x in result)
        
        return ciphertext