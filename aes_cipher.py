from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import time

class AESCipher:
    def __init__(self, key_size=128):
        """Initialize AES cipher with specified key size (128, 192, or 256 bits)"""
        if key_size not in [128, 192, 256]:
            raise ValueError("Key size must be 128, 192, or 256 bits")
        self.key_size = key_size
        self.key = None

    def set_key(self, key):
        """Set the encryption key"""
        required_length = self.key_size // 8
        if len(key) != required_length:
            raise ValueError(f"Key must be {required_length} bytes long")
        self.key = key

    def generate_key(self):
        """Generate a random key"""
        self.key = get_random_bytes(self.key_size // 8)
        return self.key

    def encrypt_ecb(self, plaintext):
        """Encrypt using AES in ECB mode"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_text = pad(plaintext.encode(), AES.block_size)
        encrypted_text = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt_ecb(self, ciphertext):
        """Decrypt using AES in ECB mode"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_data = binascii.unhexlify(ciphertext)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_text = unpad(decrypted_data, AES.block_size)
        return unpadded_text.decode('utf-8')

    def encrypt_cbc(self, plaintext, iv):
        """Encrypt using AES in CBC mode"""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_text = pad(plaintext.encode(), AES.block_size)
        encrypted_text = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt_cbc(self, ciphertext, iv):
        """Decrypt using AES in CBC mode"""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = binascii.unhexlify(ciphertext)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_text = unpad(decrypted_data, AES.block_size)
        return unpadded_text.decode('utf-8')

    def encrypt_ctr(self, plaintext, nonce):
        """Encrypt using AES in CTR mode"""
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        encrypted_text = cipher.encrypt(plaintext.encode())
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt_ctr(self, ciphertext, nonce):
        """Decrypt using AES in CTR mode"""
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        encrypted_data = binascii.unhexlify(ciphertext)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Example 1: AES-128
    print("\nAES-128 Example:")
    aes128 = AESCipher(128)
    key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF")
    aes128.set_key(key)
    
    message = "Sensitive Information"
    print(f"Original message: {message}")
    
    encrypted = aes128.encrypt_ecb(message)
    print(f"Encrypted (hex): {encrypted}")
    
    decrypted = aes128.decrypt_ecb(encrypted)
    print(f"Decrypted: {decrypted}")

    # Example 2: AES-192
    print("\nAES-192 Example:")
    aes192 = AESCipher(192)
    key = binascii.unhexlify("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210")
    aes192.set_key(key)
    
    message = "Top Secret Data"
    print(f"Original message: {message}")
    
    encrypted = aes192.encrypt_ecb(message)
    print(f"Encrypted (hex): {encrypted}")
    
    decrypted = aes192.decrypt_ecb(encrypted)
    print(f"Decrypted: {decrypted}")

    # Example 3: AES-256
    print("\nAES-256 Example:")
    aes256 = AESCipher(256)
    key = binascii.unhexlify("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
    aes256.set_key(key)
    
    message = "Encryption Strength"
    print(f"Original message: {message}")
    
    encrypted = aes256.encrypt_ecb(message)
    print(f"Encrypted (hex): {encrypted}")
    
    decrypted = aes256.decrypt_ecb(encrypted)
    print(f"Decrypted: {decrypted}")

    # Example 4: AES CTR Mode
    print("\nAES CTR Mode Example:")
    nonce = binascii.unhexlify("00000000000000000000000000000000")
    message = "Cryptography Lab Exercise"
    
    encrypted_ctr = aes128.encrypt_ctr(message, nonce)
    print(f"Original message: {message}")
    print(f"Encrypted (hex): {encrypted_ctr}")
    
    decrypted_ctr = aes128.decrypt_ctr(encrypted_ctr, nonce)
    print(f"Decrypted: {decrypted_ctr}")

    # Performance Comparison
    print("\nPerformance Comparison:")
    test_message = "Performance Testing of Encryption Algorithms" * 100
    
    for bits in [128, 192, 256]:
        aes = AESCipher(bits)
        key = get_random_bytes(bits // 8)
        aes.set_key(key)
        
        start_time = time.time()
        encrypted = aes.encrypt_ecb(test_message)
        decrypted = aes.decrypt_ecb(encrypted)
        end_time = time.time()
        
        print(f"AES-{bits} time: {end_time - start_time:.4f} seconds")