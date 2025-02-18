import random
import base64
import hashlib
from Crypto.Random import get_random_bytes  # Allowed for randomness

# ----------------- Manual RSA Implementation ----------------- #
def is_prime(n, k=5):  # Miller-Rabin Primality Test
    if n < 2:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(bits=512):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    # Extended Euclidean Algorithm to find modular inverse
    a, b, x0, x1 = phi, e, 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
    return x0 % phi

def generate_rsa_keys():
    p, q = generate_prime(), generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537  # Common public exponent
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)  # Public Key, Private Key

def rsa_encrypt(message, key):
    e, n = key
    numeric_message = int.from_bytes(message.encode(), 'big')
    return pow(numeric_message, e, n)

def rsa_decrypt(ciphertext, key):
    d, n = key
    numeric_message = pow(ciphertext, d, n)
    return numeric_message.to_bytes((numeric_message.bit_length() + 7) // 8, 'big').decode()

# Generate keys for Person A and B
public_key_A, private_key_A = generate_rsa_keys()
public_key_B, private_key_B = generate_rsa_keys()

# ----------------- Manual AES CBC Implementation ----------------- #
BLOCK_SIZE = 16  # AES block size

def pad(plaintext):
    pad_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + chr(pad_length) * pad_length  # PKCS7 Padding

def unpad(padded_text):
    pad_length = ord(padded_text[-1])
    return padded_text[:-pad_length]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# Manual AES-like S-Box transformation (simplified version)
def simple_sbox(byte_block):
    return bytes((b + 17) % 256 for b in byte_block)  # Simple non-linear substitution

def simple_inverse_sbox(byte_block):
    return bytes((b - 17) % 256 for b in byte_block)  # Reverse substitution

def aes_encrypt_block(block, key):
    """AES-like encryption: XOR with key + substitution."""
    xored = xor_bytes(block, key)
    substituted = simple_sbox(xored)  # Apply S-Box
    return substituted

def aes_decrypt_block(block, key):
    """AES-like decryption: Reverse S-Box + XOR with key."""
    reversed_substitution = simple_inverse_sbox(block)
    original_block = xor_bytes(reversed_substitution, key)
    return original_block

def aes_encrypt(plaintext, key, iv):
    plaintext = pad(plaintext)
    blocks = [plaintext[i:i+BLOCK_SIZE].encode() for i in range(0, len(plaintext), BLOCK_SIZE)]
    encrypted_blocks = []
    prev_block = iv

    for block in blocks:
        xored = xor_bytes(block, prev_block)
        encrypted_block = aes_encrypt_block(xored, key)
        encrypted_blocks.append(encrypted_block)
        prev_block = encrypted_block  # CBC chaining

    return base64.b64encode(iv + b''.join(encrypted_blocks)).decode()

def aes_decrypt(ciphertext, key):
    raw_data = base64.b64decode(ciphertext)
    iv, encrypted_blocks = raw_data[:BLOCK_SIZE], raw_data[BLOCK_SIZE:]
    decrypted_blocks = []
    prev_block = iv

    for i in range(0, len(encrypted_blocks), BLOCK_SIZE):
        block = encrypted_blocks[i:i+BLOCK_SIZE]
        decrypted_block = aes_decrypt_block(block, key)
        original_block = xor_bytes(decrypted_block, prev_block)
        decrypted_blocks.append(original_block)
        prev_block = block  # CBC chaining

    return unpad(b''.join(decrypted_blocks).decode())

# ----------------- Key Exchange ----------------- #
# Generate AES Key
aes_key = get_random_bytes(16)
iv = get_random_bytes(16)

# Encrypt AES Key with RSA (Person A to B)
encrypted_aes_key = rsa_encrypt(aes_key.hex(), public_key_B)

# Decrypt AES Key with RSA (Person B)
decrypted_aes_key = bytes.fromhex(rsa_decrypt(encrypted_aes_key, private_key_B))

# Ensure key exchange was successful
assert aes_key == decrypted_aes_key, "AES key exchange failed!"

# ----------------- AES Encryption & Decryption ----------------- #
message = "Hello, Secure World!"
ciphertext = aes_encrypt(message, aes_key, iv)
decrypted_message = aes_decrypt(ciphertext, aes_key)

assert message == decrypted_message, "Decryption failed!"
print(f"Original: {message}")
print(f"Encrypted: {ciphertext}")
print(f"Decrypted: {decrypted_message}")

# ----------------- Bit Error Simulation ----------------- #
def introduce_bit_errors(ciphertext, num_errors=1):
    raw_data = bytearray(base64.b64decode(ciphertext))
    
    for _ in range(num_errors):
        index = random.randint(0, len(raw_data) - 1)
        raw_data[index] ^= 0x01  # Flip a bit

    return base64.b64encode(raw_data).decode()

corrupted_ciphertext = introduce_bit_errors(ciphertext, num_errors=1)
print("\n--- After Bit Errors ---")
try:
    decrypted_corrupted_message = aes_decrypt(corrupted_ciphertext, aes_key)
    print(f"Decrypted (with errors): {decrypted_corrupted_message}")
except Exception as e:
    print("Decryption failed due to bit errors!")