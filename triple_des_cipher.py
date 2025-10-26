from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

class TripleDESCipher:
    def __init__(self, key):
        """Initialize 3DES cipher with a key
        key must be either 16 or 24 bytes long"""
        if len(key) not in [16, 24]:
            raise ValueError("Key must be either 16 or 24 bytes long")
        self.key = key

    def encrypt(self, plaintext):
        """Encrypt using 3DES in ECB mode"""
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        padded_text = pad(plaintext.encode(), DES3.block_size)
        encrypted_text = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt(self, ciphertext):
        """Decrypt using 3DES in ECB mode"""
        cipher = DES3.new(self.key, DES3.MODE_ECB)
        encrypted_data = binascii.unhexlify(ciphertext)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_text = unpad(decrypted_data, DES3.block_size)
        return unpadded_text.decode('utf-8')

    def encrypt_cbc(self, plaintext, iv):
        """Encrypt using 3DES in CBC mode"""
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        padded_text = pad(plaintext.encode(), DES3.block_size)
        encrypted_text = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt_cbc(self, ciphertext, iv):
        """Decrypt using 3DES in CBC mode"""
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        encrypted_data = binascii.unhexlify(ciphertext)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_text = unpad(decrypted_data, DES3.block_size)
        return unpadded_text.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Example 1: Basic 3DES
    key = b'1234567890ABCDEF1234567890ABCDEF'  # 24-byte key
    tdes = TripleDESCipher(key)
    
    message = "Classified Text"
    print("\nTriple DES ECB Mode Example:")
    print(f"Original message: {message}")
    
    # Encrypt
    encrypted = tdes.encrypt(message)
    print(f"Encrypted (hex): {encrypted}")
    
    # Decrypt
    decrypted = tdes.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")

    # Example 2: 3DES in CBC mode
    print("\nTriple DES CBC Mode Example:")
    iv = b'12345678'  # 8-byte IV
    message = "Secret Communication"
    
    # Encrypt
    encrypted_cbc = tdes.encrypt_cbc(message, iv)
    print(f"Original message: {message}")
    print(f"Encrypted (hex): {encrypted_cbc}")
    
    # Decrypt
    decrypted_cbc = tdes.decrypt_cbc(encrypted_cbc, iv)
    print(f"Decrypted: {decrypted_cbc}")

    # Performance comparison
    import time
    message = "Performance Testing of Encryption Algorithms" * 100
    
    start_time = time.time()
    encrypted = tdes.encrypt(message)
    decrypted = tdes.decrypt(encrypted)
    end_time = time.time()
    
    print(f"\nTriple DES Performance:")
    print(f"Time taken for encryption and decryption: {end_time - start_time:.4f} seconds")