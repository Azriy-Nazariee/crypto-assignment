from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad  # Import padding utilities
from Crypto.Random import get_random_bytes
import base64
import random

# Step 1: RSA Key Generation (Public & Private Keys)
def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate 2048-bit RSA key
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Generate RSA Key Pairs for Person A & B
private_key_A, public_key_A = generate_rsa_keys()
private_key_B, public_key_B = generate_rsa_keys()

# Step 2: AES Key Generation
def generate_aes_key():
    return get_random_bytes(32)  # 256-bit AES key

# Step 3: Securely Exchange AES Key using RSA
def encrypt_aes_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key

def decrypt_aes_key(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    return decrypted_key

# Person A generates AES key and encrypts it using Person B's public key
aes_key = generate_aes_key()
encrypted_aes_key = encrypt_aes_key(aes_key, public_key_B)

# Person B decrypts AES key using their private key
decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key_B)

# Ensure the key is correctly exchanged
assert aes_key == decrypted_aes_key, "AES key exchange failed!"

# Step 4: AES Encryption and Decryption (Fixed)
def encrypt_message(plaintext, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)  # AES in CBC mode
    iv = cipher.iv  # Initialization Vector
    padded_text = pad(plaintext.encode(), AES.block_size)  # Proper padding
    ciphertext = cipher.encrypt(padded_text)
    return base64.b64encode(iv + ciphertext).decode()  # Store IV + ciphertext

def decrypt_message(ciphertext, aes_key):
    raw_data = base64.b64decode(ciphertext)
    iv = raw_data[:16]  # Extract IV
    cipher_text = raw_data[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        decrypted_text = unpad(cipher.decrypt(cipher_text), AES.block_size).decode()  # Remove padding safely
        return decrypted_text
    except ValueError:
        print("Warning: Padding error detected! Decryption may be corrupted.")
        return "(Decryption failed due to padding error)"

# Example usage
message = "Hello, Secure World!"
ciphertext = encrypt_message(message, decrypted_aes_key)
decrypted_message = decrypt_message(ciphertext, decrypted_aes_key)

# Ensure the message is correctly encrypted and decrypted
assert message == decrypted_message, "Decryption failed!"
print(f"Original: {message}")
print(f"Encrypted: {ciphertext}")
print(f"Decrypted: {decrypted_message}")

# Step 5: Simulating Bit Errors in Ciphertext
def introduce_bit_errors(ciphertext, num_errors=1):
    raw_data = bytearray(base64.b64decode(ciphertext))
    
    for _ in range(num_errors):
        index = random.randint(0, len(raw_data) - 1)  # Choose random byte to flip
        raw_data[index] ^= 0x01  # Flip a bit (XOR with 1)

    return base64.b64encode(raw_data).decode()

# Introduce bit error in ciphertext
corrupted_ciphertext = introduce_bit_errors(ciphertext, num_errors=1)

print("\n--- After Bit Errors ---")
decrypted_corrupted_message = decrypt_message(corrupted_ciphertext, decrypted_aes_key)
print(f"Decrypted (with errors): {decrypted_corrupted_message}")
