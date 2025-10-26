import random
import math
import time

def is_prime(n):
    """Check if a number is prime"""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def mod_inverse(a, m):
    """Find modular multiplicative inverse"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return (x % m + m) % m

class ElGamalCipher:
    def __init__(self, key_size=256):
        """Initialize ElGamal with specified key size"""
        self.key_size = key_size
        self.p = None  # Prime modulus
        self.g = None  # Generator
        self.x = None  # Private key
        self.y = None  # Public key

    def generate_keys(self):
        """Generate public and private key pair"""
        # Find a prime number p
        while True:
            self.p = random.getrandbits(self.key_size)
            if is_prime(self.p):
                break

        # Find a generator g
        self.g = 2  # Using 2 as generator for simplicity
        
        # Generate private key x
        self.x = random.randint(1, self.p - 2)
        
        # Calculate public key y = g^x mod p
        self.y = pow(self.g, self.x, self.p)
        
        return {
            'public_key': (self.p, self.g, self.y),
            'private_key': self.x
        }

    def set_keys(self, p, g, y, x=None):
        """Set known keys"""
        self.p = p
        self.g = g
        self.y = y
        self.x = x

    def encrypt(self, message, public_key=None):
        """Encrypt a message using ElGamal"""
        if public_key:
            p, g, y = public_key
        else:
            p, g, y = self.p, self.g, self.y

        # Convert message to integer if it's a string
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')

        # Generate random k
        k = random.randint(1, p - 2)
        
        # Calculate c1 = g^k mod p
        c1 = pow(g, k, p)
        
        # Calculate c2 = m * y^k mod p
        c2 = (message * pow(y, k, p)) % p
        
        return (c1, c2)

    def decrypt(self, ciphertext, private_key=None):
        """Decrypt a message using ElGamal"""
        if private_key is None:
            private_key = self.x
            
        c1, c2 = ciphertext
        
        # Calculate s = c1^x mod p
        s = pow(c1, private_key, self.p)
        
        # Calculate m = c2 * s^(-1) mod p
        s_inv = mod_inverse(s, self.p)
        m = (c2 * s_inv) % self.p
        
        # Try to convert back to string
        try:
            return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
        except:
            return str(m)

def measure_performance(message, key_size=256):
    """Measure ElGamal performance metrics"""
    start_time = time.time()
    elgamal = ElGamalCipher(key_size)
    keys = elgamal.generate_keys()
    key_gen_time = time.time() - start_time

    start_time = time.time()
    encrypted = elgamal.encrypt(message)
    encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted = elgamal.decrypt(encrypted)
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
    # Example 1: Basic ElGamal encryption/decryption
    elgamal = ElGamalCipher()
    keys = elgamal.generate_keys()
    
    message = "Confidential Data"
    print("\nElGamal Example:")
    print(f"Original message: {message}")
    
    # Encrypt
    encrypted = elgamal.encrypt(message)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = elgamal.decrypt(encrypted)
    print(f"Decrypted: {decrypted}")

    # Example 2: Using known keys from lab exercise
    p = 7919
    g = 2
    h = 6465
    x = 2999
    
    elgamal = ElGamalCipher()
    elgamal.set_keys(p, g, h, x)
    
    message = "Asymmetric Algorithms"
    print("\nElGamal with Known Keys:")
    print(f"Original message: {message}")
    
    encrypted = elgamal.encrypt(message)
    decrypted = elgamal.decrypt(encrypted)
    
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

    # Example 3: Performance measurement
    print("\nPerformance Metrics:")
    test_sizes = [256, 512, 1024]
    test_message = "Performance testing message" * 10
    
    for size in test_sizes:
        metrics = measure_performance(test_message, size)
        print(f"\nKey size: {size} bits")
        print(f"Key generation time: {metrics['key_generation_time']:.4f} seconds")
        print(f"Encryption time: {metrics['encryption_time']:.4f} seconds")
        print(f"Decryption time: {metrics['decryption_time']:.4f} seconds")