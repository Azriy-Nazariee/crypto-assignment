import random
import base64
import os
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

#1) Padding
def pad(plaintext):
    pad_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + chr(pad_length) * pad_length

def unpad(padded_text):
    pad_length = ord(padded_text[-1])
    if pad_length > BLOCK_SIZE:
        raise ValueError("Invalid padding detected")
    return padded_text[:-pad_length]

#2) Key Expansion
RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def rot_word(word):
    """Rotates a word (4 bytes) left."""
    return word[1:] + word[:1]

def sub_word(word, sbox):
    """Applies the S-box substitution to a word (4 bytes)."""
    return bytes(sbox[b] for b in word)

def key_expansion(key):
    """Expands the AES key into multiple round keys."""
    key_size = len(key)
    assert key_size in [16, 24, 32], "Invalid key size. Use 128-bit, 192-bit, or 256-bit keys."
    
    Nk = key_size // 4  # Number of words in the key
    Nr = {16: 10, 24: 12, 32: 14}[key_size]  # Number of rounds
    expanded_key = bytearray(key)
    
    for i in range(Nk, 4 * (Nr + 1)):
        temp = expanded_key[-4:]
        if i % Nk == 0:
            temp = xor_bytes(sub_word(rot_word(temp), sbox), bytes([RCON[i//Nk-1], 0, 0, 0]))
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp, sbox)
        expanded_key.extend(xor_bytes(expanded_key[-Nk * 4:-Nk * 4 + 4], temp))
    
    return [expanded_key[i:i+16] for i in range(0, len(expanded_key), 16)]

# S-Box and Inverse S-Box
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

inv_sbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Encryption Steps ------------------------------------------------------------------

# Step 1: Substitute Bytes
def substitute_bytes(byte_block, sbox):
    return bytes(sbox[b] for b in byte_block)  # Corrected to match S-Box

# Step 2: Shift Rows
def shift_rows(state):
    """Performs the AES ShiftRows transformation."""
    return bytes([
        state[0],  state[5],  state[10], state[15],  # Row 0 (unchanged)
        state[4],  state[9],  state[14], state[3],   # Row 1 (shift left by 1)
        state[8],  state[13], state[2],  state[7],   # Row 2 (shift left by 2)
        state[12], state[1],  state[6],  state[11]   # Row 3 (shift left by 3)
    ])

# Step 3: Mix Columns
# Galois field multiplication helper function
def gmul(a, b):
    """Galois Field (GF 2^8) multiplication of two bytes."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B  # AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p

# MixColumns transformation
def mix_columns(state):
    """Performs the AES MixColumns transformation."""
    mixed = bytearray(16)
    for i in range(4):  # Iterate over columns
        col = state[i::4]  # Extract column
        mixed[i::4] = [
            gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3],
            col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3],
            col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3),
            gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2)
        ]
    return bytes(mixed)

# Step 4 (for both): Add Round Key
def add_round_key(state, key):
    return xor_bytes(state, key)

# Decryption Steps -----------------------------------------------------------------

# Step 1 : Inverse Substitute Bytes
def inv_substitute_bytes(byte_block, inv_sbox):
    return bytes(inv_sbox[b] for b in byte_block)

# Step 2 : Inverse Shift Rows
def inv_shift_rows(state):
    """Performs the inverse AES ShiftRows transformation."""
    return bytes([
        state[0],  state[13], state[10], state[7],   # Row 0 (unchanged)
        state[4],  state[1],  state[14], state[11],  # Row 1 (shift right by 1)
        state[8],  state[5],  state[2],  state[15],  # Row 2 (shift right by 2)
        state[12], state[9],  state[6],  state[3]    # Row 3 (shift right by 3)
    ])

# Step 3 : Inverse Mix Columns
def inv_mix_columns(state):
    """Performs the AES Inverse MixColumns transformation."""
    mixed = bytearray(16)
    for i in range(4):  # Iterate over columns
        col = state[i::4]  # Extract column
        mixed[i::4] = [
            gmul(col[0], 14) ^ gmul(col[1], 11) ^ gmul(col[2], 13) ^ gmul(col[3], 9),
            gmul(col[0], 9) ^ gmul(col[1], 14) ^ gmul(col[2], 11) ^ gmul(col[3], 13),
            gmul(col[0], 13) ^ gmul(col[1], 9) ^ gmul(col[2], 14) ^ gmul(col[3], 11),
            gmul(col[0], 11) ^ gmul(col[1], 13) ^ gmul(col[2], 9) ^ gmul(col[3], 14)
        ]
    return bytes(mixed)

# AES Encryption and Decryption Rounds ------------------------------------------------

def aes_encrypt_block(block, key):
    round_keys = key_expansion(key)
    
    state = xor_bytes(block, round_keys[0])  # Initial AddRoundKey

    for i in range(1, len(round_keys) - 1):
        state = substitute_bytes(state, sbox)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[i])

    state = substitute_bytes(state, sbox)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[-1])  # Final round (no MixColumns)

    return state

def aes_decrypt_block(block, key):
    round_keys = key_expansion(key)

    state = xor_bytes(block, round_keys[-1])  # Initial AddRoundKey (last key)

    for i in range(len(round_keys) - 2, 0, -1):
        state = inv_shift_rows(state)
        state = inv_substitute_bytes(state, inv_sbox)
        state = add_round_key(state, round_keys[i])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = substitute_bytes(state, inv_sbox)
    state = add_round_key(state, round_keys[0])  # Final AddRoundKey

    return state

# AES Encryption and Decryption Functions -------------------------------------------
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
    print("----------------------------")
    print("RSA & AES Encryption Tool")
    print("----------------------------")

def main():
    display_header()

    plaintext = input("Enter Plaintext: ")

    print("\nGenerating RSA Keys...")
    public_key, private_key = generate_rsa_keys()
    print(f"RSA Public Key: (e={public_key[0]}, n={public_key[1]})")

    print("\nGenerating AES Key... [Auto-Generated]")
    aes_key = os.urandom(16)  # More reliable random bytes
    iv = os.urandom(16)

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
