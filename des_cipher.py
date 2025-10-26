from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

class DESCipher:
    def __init__(self, key):
        """Initialize DES cipher with a key
        key must be 8 bytes long (64 bits)"""
        if len(key) != 8:
            raise ValueError("Key must be 8 bytes long")
        self.key = key

    def encrypt(self, plaintext):
        """Encrypt using DES in ECB mode"""
        # Create cipher object and encrypt the data
        cipher = DES.new(self.key, DES.MODE_ECB)
        # Pad the plaintext to be multiple of 8 bytes
        padded_text = pad(plaintext.encode(), DES.block_size)
        # Encrypt and return hex representation
        encrypted_text = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt(self, ciphertext):
        """Decrypt using DES in ECB mode"""
        # Create cipher object
        cipher = DES.new(self.key, DES.MODE_ECB)
        # Convert hex string to bytes
        encrypted_data = binascii.unhexlify(ciphertext)
        # Decrypt and unpad
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_text = unpad(decrypted_data, DES.block_size)
        return unpadded_text.decode('utf-8')

    def encrypt_cbc(self, plaintext, iv):
        """Encrypt using DES in CBC mode"""
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        padded_text = pad(plaintext.encode(), DES.block_size)
        encrypted_text = cipher.encrypt(padded_text)
        return binascii.hexlify(encrypted_text).decode('utf-8')

    def decrypt_cbc(self, ciphertext, iv):
        """Decrypt using DES in CBC mode"""
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        encrypted_data = binascii.unhexlify(ciphertext)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_text = unpad(decrypted_data, DES.block_size)
        return unpadded_text.decode('utf-8')

# Example usage
if __name__ == "__main__":
    # Example 1: Basic DES in ECB mode
    key = b'A1B2C3D4'  # 8-byte key
    des = DESCipher(key)
    
    message = "Confidential Data"
    print("\nDES ECB Mode Example:")
    print(f"Original message: {message}")
    
    # Encrypt
    encrypted = des.encrypt(message)
    print(f"Encrypted (hex): {encrypted}")
    
    # Decrypt
    decrypted = des.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")

    # Example 2: DES in CBC mode
    print("\nDES CBC Mode Example:")
    iv = b'12345678'  # 8-byte IV
    message = "Secure Communication"
    
    # Encrypt
    encrypted_cbc = des.encrypt_cbc(message, iv)
    print(f"Original message: {message}")
    print(f"Encrypted (hex): {encrypted_cbc}")
    
    # Decrypt
    decrypted_cbc = des.decrypt_cbc(encrypted_cbc, iv)
    print(f"Decrypted: {decrypted_cbc}")

    # Example 3: Encrypting hex blocks
    print("\nDES Block Encryption Example:")
    key = b'A1B2C3D4'
    block1 = "54686973206973206120636f6e666964656e7469616c206d657373616765"
    block2 = "416e64207468697320697320746865207365636f6e6420626c6f636b"
    
    # Convert hex to bytes and encrypt
    block1_bytes = binascii.unhexlify(block1)
    block2_bytes = binascii.unhexlify(block2)
    
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_block1 = binascii.hexlify(cipher.encrypt(pad(block1_bytes, DES.block_size))).decode()
    encrypted_block2 = binascii.hexlify(cipher.encrypt(pad(block2_bytes, DES.block_size))).decode()
    
    print(f"Block 1 encrypted: {encrypted_block1}")
    print(f"Block 2 encrypted: {encrypted_block2}")