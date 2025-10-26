from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import math
import time

class RSACipher:
    def __init__(self, key_size=2048):
        """Initialize RSA with specified key size"""
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        """Generate public and private key pair"""
        # Generate RSA key pair
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.publickey()
        return (self.public_key, self.private_key)

    def encrypt(self, message, public_key=None):
        """Encrypt a message using RSA"""
        if public_key is None:
            public_key = self.public_key
        
        # Create cipher object
        cipher = PKCS1_OAEP.new(public_key)
        
        # Convert message to bytes if it's not already
        if isinstance(message, str):
            message = message.encode()
            
        # Encrypt the message
        ciphertext = cipher.encrypt(message)
        return ciphertext

    def decrypt(self, ciphertext, private_key=None):
        """Decrypt a message using RSA"""
        if private_key is None:
            private_key = self.private_key
            
        # Create cipher object
        cipher = PKCS1_OAEP.new(private_key)
        
        # Decrypt the message
        message = cipher.decrypt(ciphertext)
        return message.decode()

    @staticmethod
    def set_known_keys(n, e, d):
        """Create RSA key objects from known values"""
        # Create public key
        pub_key = RSA.construct((n, e))
        # Create private key
        priv_key = RSA.construct((n, e, d))
        return pub_key, priv_key

def measure_performance(message, key_size=2048):
    """Measure RSA performance metrics"""
    start_time = time.time()
    rsa = RSACipher(key_size)
    pub_key, priv_key = rsa.generate_keys()
    key_gen_time = time.time() - start_time

    start_time = time.time()
    encrypted = rsa.encrypt(message, pub_key)
    encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted = rsa.decrypt(encrypted, priv_key)
    decryption_time = time.time() - start_time

    return {
        'key_generation_time': key_gen_time,
        'encryption_time': encryption_time,
        'decryption_time': decryption_time,
        'key_size': key_size,
        'message_size': len(message)
    }

# Example usage
if __name__ == "__main__":
    # Example 1: Basic RSA encryption/decryption
    rsa = RSACipher(2048)
    public_key, private_key = rsa.generate_keys()
    
    message = "Asymmetric Encryption"
    print("\nRSA Example:")
    print(f"Original message: {message}")
    
    # Encrypt
    encrypted = rsa.encrypt(message, public_key)
    print(f"Encrypted (hex): {encrypted.hex()}")
    
    # Decrypt
    decrypted = rsa.decrypt(encrypted, private_key)
    print(f"Decrypted: {decrypted}")

    # Example 2: Using known keys from lab exercise
    n = 323
    e = 5
    d = 173
    message = "Cryptographic Protocols"
    
    pub_key, priv_key = RSACipher.set_known_keys(n, e, d)
    rsa = RSACipher()
    
    print("\nRSA with Known Keys:")
    print(f"Original message: {message}")
    
    encrypted = rsa.encrypt(message, pub_key)
    decrypted = rsa.decrypt(encrypted, priv_key)
    
    print(f"Encrypted (hex): {encrypted.hex()}")
    print(f"Decrypted: {decrypted}")

    # Example 3: Performance measurement
    print("\nPerformance Metrics:")
    test_sizes = [1024, 2048, 4096]
    test_message = "Performance testing message" * 10
    
    for size in test_sizes:
        metrics = measure_performance(test_message, size)
        print(f"\nKey size: {size} bits")
        print(f"Key generation time: {metrics['key_generation_time']:.4f} seconds")
        print(f"Encryption time: {metrics['encryption_time']:.4f} seconds")
        print(f"Decryption time: {metrics['decryption_time']:.4f} seconds")