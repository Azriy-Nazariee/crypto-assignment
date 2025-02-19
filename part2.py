import random
import base64
import hashlib
from Crypto.Random import get_random_bytes
import time

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

def generate_rsa_keys():
    p, q = generate_prime(), generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    d = pow(e, -1, phi)
    
    return (e, n), (d, n)

def rsa_encrypt(message, key):
    e, n = key
    numeric_message = int.from_bytes(message, 'big')  # Ensure it's bytes, not string
    return pow(numeric_message, e, n)

def rsa_decrypt(ciphertext, key):
    d, n = key
    numeric_message = pow(ciphertext, d, n)
    return numeric_message.to_bytes((numeric_message.bit_length() + 7) // 8, 'big')

# ----------------- Manual AES CBC Implementation ----------------- #
BLOCK_SIZE = 16

# Stronger S-Box (simple example similar to AES S-Box behavior)
sbox = [i ^ (i << 1) % 256 for i in range(256)]
inv_sbox = [sbox.index(i) for i in range(256)]

def pad(plaintext):
    pad_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + chr(pad_length) * pad_length

def unpad(padded_text):
    pad_length = ord(padded_text[-1])
    if pad_length > BLOCK_SIZE:
        raise ValueError("Invalid padding detected")
    return padded_text[:-pad_length]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def substitute_bytes(byte_block, sbox):
    return bytes(sbox[b] for b in byte_block)

def aes_encrypt_block(block, key):
    xored = xor_bytes(block, key)
    substituted = substitute_bytes(xored, sbox)
    return substituted

def aes_decrypt_block(block, key):
    reversed_substitution = substitute_bytes(block, inv_sbox)
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
        prev_block = encrypted_block

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
        prev_block = block

    return unpad(b''.join(decrypted_blocks).decode())

# ----------------- Terminal Interface ----------------- #
def display_header():
    print("---------------------------------------------------------")
    print("RSA & AES Encryption Tool")
    print("---------------------------------------------------------")

def main():
    display_header()

    plaintext = input("Enter Plaintext: ")

    print("\nGenerating RSA Keys...")
    public_key, private_key = generate_rsa_keys()
    print(f"RSA Public Key: (e={public_key[0]}, n={public_key[1]})")

    print("\nGenerating AES Key... [Auto-Generated]")
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    encrypted_aes_key = rsa_encrypt(aes_key, public_key)
    print(f"Encrypted AES Key (RSA Encrypted): {encrypted_aes_key}")

    print("\nEncrypting Message using AES...")
    start_time = time.time()
    ciphertext = aes_encrypt(plaintext, aes_key, iv)
    encryption_time = time.time() - start_time

    print("\nDecrypting ciphertext...")
    start_time = time.time()
    decrypted_aes_key = rsa_decrypt(encrypted_aes_key, private_key)

    try:
        decrypted_text = aes_decrypt(ciphertext, decrypted_aes_key)
        decryption_time = time.time() - start_time
        print("\nDecryption successful.")
        print(f"Expected: \"{plaintext}\"")
        print(f"Received: \"{decrypted_text}\"")
    except Exception as e:
        decryption_time = time.time() - start_time
        print("\nDecryption failed: Data corruption detected.")
        print(f"Error: {e}")

    print(f"\nEncryption Time: {encryption_time:.4f}s")
    print(f"Decryption Time: {decryption_time:.4f}s")
    print("---------------------------------------------------------")

if __name__ == "__main__":
    main()
