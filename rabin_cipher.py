import random
import math
import time
from typing import List, Tuple

class RabinCipher:
    def __init__(self, key_size=1024):
        """Initialize Rabin cipher with specified key size"""
        self.key_size = key_size
        self.p = None  # First prime
        self.q = None  # Second prime
        self.n = None  # Public modulus
        
    def generate_prime(self, bits: int) -> int:
        """Generate a prime p where p ≡ 3 (mod 4)"""
        while True:
            # Generate random number
            p = random.getrandbits(bits)
            # Ensure p ≡ 3 (mod 4)
            p = p - (p % 4) + 3
            # Check if prime
            if self._is_prime(p):
                return p

    def _is_prime(self, n: int, k: int = 128) -> bool:
        """Miller-Rabin primality test"""
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False
        
        # Write n as 2^r * d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = (x * x) % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    def generate_keys(self) -> dict:
        """Generate public and private keys"""
        # Generate p and q where p,q ≡ 3 (mod 4)
        half_size = self.key_size // 2
        self.p = self.generate_prime(half_size)
        self.q = self.generate_prime(half_size)
        self.n = self.p * self.q

        return {
            'public_key': self.n,
            'private_key': (self.p, self.q)
        }

    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean Algorithm"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def encrypt(self, message: int, public_key: int = None) -> int:
        """Encrypt a message using Rabin"""
        if public_key is None:
            public_key = self.n
            
        if isinstance(message, str):
            message = int.from_bytes(message.encode(), 'big')
            
        return pow(message, 2, public_key)

    def decrypt(self, ciphertext: int, private_key: Tuple[int, int] = None) -> List[int]:
        """Decrypt ciphertext using Chinese Remainder Theorem
        Returns list of possible messages (four square roots)"""
        if private_key is None:
            p, q = self.p, self.q
        else:
            p, q = private_key
            
        # Compute square roots mod p and q
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)
        
        # Use extended GCD to find coefficients
        _, yp, yq = self.extended_gcd(p, q)
        
        # Calculate four square roots using Chinese Remainder Theorem
        r1 = (yp * p * mq + yq * q * mp) % (p * q)
        r2 = (p * q - r1)
        r3 = (yp * p * mq - yq * q * mp) % (p * q)
        r4 = (p * q - r3)
        
        roots = [r1, r2, r3, r4]
        
        # Try to convert each root back to string
        messages = []
        for root in roots:
            try:
                msg = root.to_bytes((root.bit_length() + 7) // 8, 'big').decode()
                messages.append(msg)
            except:
                messages.append(str(root))
                
        return messages

def measure_performance(message, key_size=1024):
    """Measure Rabin cipher performance metrics"""
    start_time = time.time()
    rabin = RabinCipher(key_size)
    keys = rabin.generate_keys()
    key_gen_time = time.time() - start_time

    start_time = time.time()
    encrypted = rabin.encrypt(message)
    encryption_time = time.time() - start_time

    start_time = time.time()
    decrypted = rabin.decrypt(encrypted)
    decryption_time = time.time() - start_time

    return {
        'key_generation_time': key_gen_time,
        'encryption_time': encryption_time,
        'decryption_time': decryption_time,
        'key_size': key_size,
        'message_size': len(str(message))
    }

if __name__ == "__main__":
    # Example 1: Basic Rabin encryption/decryption
    rabin = RabinCipher(key_size=1024)
    keys = rabin.generate_keys()
    
    message = "Hello, Rabin cryptosystem!"
    print("\nRabin Example:")
    print(f"Original message: {message}")
    
    # Encrypt
    encrypted = rabin.encrypt(message)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted_messages = rabin.decrypt(encrypted)
    print("Possible decrypted messages:")
    for i, msg in enumerate(decrypted_messages, 1):
        print(f"{i}. {msg}")

    # Example 2: Performance measurement
    print("\nPerformance Metrics:")
    test_sizes = [1024, 2048, 4096]
    test_message = "Performance testing message" * 10
    
    for size in test_sizes:
        metrics = measure_performance(test_message, size)
        print(f"\nKey size: {size} bits")
        print(f"Key generation time: {metrics['key_generation_time']:.4f} seconds")
        print(f"Encryption time: {metrics['encryption_time']:.4f} seconds")
        print(f"Decryption time: {metrics['decryption_time']:.4f} seconds")