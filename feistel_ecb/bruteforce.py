import hashlib
import itertools
import os
import random

ROUNDS = 16
BLOCKSIZE = 2  # 16-bit block (2 bytes)
SECRET = b"3f788083-77d3-4502-9d71-21319f1792b6"

# Define the 16-bit hash function
def simple_16bit_hash(message: bytes) -> int:
    hash_value = 0xABCD  # Starting with a constant initial value
    for byte in message:
        hash_value ^= byte  # XOR each byte
        hash_value = (hash_value << 3 | hash_value >> 13) & 0xFFFF  # Rotate left by 3 bits within 16 bits
    return hash_value

# Define the HMAC function using the 16-bit hash function
def hmac_16bit(key: bytes, message: bytes) -> int:
    block_size = 64  # Block size for HMAC, typically 64 bytes for many hash functions
    if len(key) > block_size:
        key = simple_16bit_hash(key).to_bytes(2, byteorder='big')
    key = key.ljust(block_size, b'\x00')
    o_key_pad = bytes((x ^ 0x5C) for x in key)
    i_key_pad = bytes((x ^ 0x36) for x in key)
    inner_hash = simple_16bit_hash(i_key_pad + message)
    hmac_result = simple_16bit_hash(o_key_pad + inner_hash.to_bytes(2, byteorder='big'))
    return hmac_result

# Encrypt message using either ECB or CBC mode based on crypt_mode
def encrypt_message(key: str, message: bytes, mode: str) -> bytes:
    ciphertext = b""
    n = BLOCKSIZE  # 2 bytes (16 bits) per block

    # Generate IV (Initialization Vector)
    iv = hashlib.md5(SECRET).digest()[:BLOCKSIZE]

    # Split message into 16-bit blocks
    message_blocks = [message[i:i + n] for i in range(0, len(message), n)]

    # Pad the last block if necessary
    length_of_last_block = len(message_blocks[-1])
    if length_of_last_block < BLOCKSIZE:
        message_blocks[-1] += bytes([BLOCKSIZE - length_of_last_block])
    else:
        # Add a full padding block
        message_blocks.append(bytes([BLOCKSIZE] * BLOCKSIZE))

    # Generate subkeys from the key
    subkeys = generate_key(key)

    # If using CBC mode, start with IV as previous block
    previous_block = iv if mode == "cbc" else None

    for block in message_blocks:
        # XOR with previous block if using CBC mode
        if mode == "cbc":
            block = xor_bytes(block, previous_block)

        L, R = block[:BLOCKSIZE//2], block[BLOCKSIZE//2:]

        for i in range(ROUNDS):
            L, R = R, xor_bytes(L, feistel_function(R, subkeys[i]))

        ciphertext_block = L + R

        # Update previous block for CBC mode
        if mode == "cbc":
            previous_block = ciphertext_block

        ciphertext += ciphertext_block

    return ciphertext

# Decrypt ciphertext using either ECB or CBC mode based on crypt_mode
def decrypt_cipher(key: str, ciphertext: bytes, mode: str) -> bytes:
    message = b""
    n = BLOCKSIZE  # 2 bytes (16 bits) per block

    # Split ciphertext into 16-bit blocks
    ciphertext_blocks = [ciphertext[i:i + n] for i in range(0, len(ciphertext), n)]

    subkeys = generate_key(key)
    iv = hashlib.md5(SECRET).digest()[:BLOCKSIZE]

    if mode == "cbc":
        previous_block = iv

    for block in ciphertext_blocks:
        L, R = block[:BLOCKSIZE//2], block[BLOCKSIZE//2:]

        for i in range(ROUNDS-1, -1, -1):
            L, R = xor_bytes(R, feistel_function(L, subkeys[i])), L

        decrypted_block = L + R

        if mode == "cbc":
            decrypted_block = xor_bytes(decrypted_block, previous_block)
            previous_block = block

        message += decrypted_block

    # Remove padding if present
    pad_len = message[-1]
    if pad_len < BLOCKSIZE and all(p == pad_len for p in message[-pad_len:]):
        message = message[:-pad_len]

    return message

# Generate subkeys from the key
def generate_key(key: str):
    key = bytes.fromhex(key)
    hash_key = hashlib.sha256(key + SECRET).digest()
    subkeys = [hash_key[i:i + 2] for i in range(0, len(hash_key), 2)]
    return subkeys[:ROUNDS]

# Feistel function
def feistel_function(right: bytes, subkey: bytes) -> bytes:
    right_int = int.from_bytes(right, byteorder='big')
    subkey_int = int.from_bytes(subkey, byteorder='big')
    result = (right_int * subkey_int) % (2**16)
    return result.to_bytes(2, byteorder='big')

# XOR operation on bytes
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(_a ^ _b for _a, _b in zip(a, b))

def find_hash_collision():
    seen_hashes = {}
    while True:
        message = os.urandom(4)  # Generate random 4-byte message
        hash_value = simple_16bit_hash(message)
        if hash_value in seen_hashes:
            print(f"Collision found:\nMessage 1: {seen_hashes[hash_value]}\nMessage 2: {message}")
            print(f"with hash value:{hash_value}")
            break
        seen_hashes[hash_value] = message

def find_hmac_collision(key: str):
    seen_hmacs = {}
    key_bytes = bytes.fromhex(key)
    while True:
        message = os.urandom(4)  # Generate random 4-byte message
        hmac_value = hmac_16bit(key_bytes, message)
        if hmac_value in seen_hmacs:
            print(f"HMAC Collision found:\nMessage 1: {seen_hmacs[hmac_value]}\nMessage 2: {message}")
            print(f"with hmac value:{hmac_value}")
            break
        seen_hmacs[hmac_value] = message

def main():
    # option = input("Do you want to encrypt or decrypt? (encrypt/decrypt): ").strip().lower()
    # if option not in ("encrypt", "decrypt"):
    #     print("Invalid option")
    #     return
    # input_file = input("Enter input file name: ").strip()
    # if not os.path.isfile(input_file):
    #     print("Invalid input file")
    #     return
    key = input("Enter 32-bit key (8 hex characters): ").strip()
    # if not is_valid_hex_key(key):
    #     print("Invalid key. Please enter 8 hexadecimal characters.")
    #     return
    # output_file = input("Enter output file name: ").strip()
    # with open(input_file, "rb") as f:
    #     input_data = f.read()

    # # Print hash and HMAC of input data
    # hash_value = simple_16bit_hash(input_data)
    # hmac_value = hmac_16bit(bytes.fromhex(key), input_data)
    # print(f"Hash of input data: {hash_value:04x}")
    # print(f"HMAC of input data: {hmac_value:04x}")

    # # Determine mode automatically based on plaintext length
    # crypt_mode = "cbc" if len(input_data) > BLOCKSIZE else "ecb"

    # if option == "encrypt":
    #     if crypt_mode == "ecb":
    #         print("Using ECB mode for plaintext with length less than or equal to 32 bits.")
    #     else:
    #         print("Using CBC mode for plaintext longer than 32 bits.")
    #     output = encrypt_message(key, input_data, crypt_mode)
    #     with open(output_file, 'wb') as fw:
    #         fw.write(output)  # Write output here for encryption
    # elif option == "decrypt":
    #     output = decrypt_cipher(key, input_data, crypt_mode)
    #     with open(output_file, 'wb') as fw:
    #         fw.write(output)  # Write output here for decryption

    collision_option = input("Do you want to find collisions? (yes/no): ").strip().lower()
    if collision_option == "yes":
        collision_type = input("Find hash collision or HMAC collision? (hash/hmac): ").strip().lower()
        if collision_type == "hash":
            find_hash_collision()
        elif collision_type == "hmac":
            find_hmac_collision(key)
        else:
            print("Invalid collision type")

def is_valid_hex_key(key: str) -> bool:
    try:
        bytes.fromhex(key)
        return len(key) == 8    
    except ValueError:
        return False

if __name__ == "__main__":
    main()
