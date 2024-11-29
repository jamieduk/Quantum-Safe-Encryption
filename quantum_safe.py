# Created By J~Net (c) 2024
#
# quantum_safe.py
#
import random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Convert string to binary
def string_to_binary(string):
    return ''.join(format(ord(c), '08b') for c in string)

# Convert binary back to string
def binary_to_string(binary):
    binary_values=[binary[i:i + 8] for i in range(0, len(binary), 8)]
    return ''.join(chr(int(bv, 2)) for bv in binary_values)

# RSA Key Generation for Asymmetric Encryption (Public/Private Key Pair)
def generate_rsa_keypair():
    key=RSA.generate(2048)
    private=key.export_key()
    public_key=key.publickey().export_key()
    return private, public_key

# AES Encryption and Decryption (Symmetric Encryption)
def aes_encrypt(data, key):
    data=apply_padding(data, AES.block_size)  # Ensure padding before encryption
    cipher=AES.new(key, AES.MODE_CBC)
    ct_bytes=cipher.encrypt(data)
    return cipher.iv, ct_bytes

def aes_decrypt(ct_bytes, key, iv):
    if key is None:
        print("Error: AES key is None!")
        return None  # Exit early if the AES key is invalid

    print(f"Using AES key: {b64encode(key).decode()}")
    cipher=AES.new(key, AES.MODE_CBC, iv)
    try:
        pt=cipher.decrypt(ct_bytes)
        print(f"Decrypted data (before padding removal): {b64encode(pt).decode()}")
        return remove_padding(pt)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None

# RSA Encryption (For securely exchanging AES keys)
def rsa_encrypt(public_key, data):
    # If public_key is already an RsaKey object, no need to import it again
    if isinstance(public_key, RSA.RsaKey):
        recipient_key=public_key
    else:
        recipient_key=RSA.import_key(public_key)  # Import the public key if it's not an RsaKey object
    cipher_rsa=PKCS1_OAEP.new(recipient_key)
    encrypted_data=cipher_rsa.encrypt(data)
    return encrypted_data

def rsa_decrypt(private, encrypted_data):
    # Ensure private is an RsaKey object, if it's not already
    if isinstance(private, RSA.RsaKey):
        rsa_key=private  # Corrected this line
    else:
        rsa_key=RSA.import_key(private)  # Corrected this line

    # Debug: Print the private key and encrypted data to verify
    print(f"Private Key: {b64encode(rsa_key.export_key()).decode()}")
    print(f"Encrypted Data: {b64encode(encrypted_data).decode()}")

    # Create a cipher object for RSA decryption using PKCS1_OAEP
    cipher=PKCS1_OAEP.new(rsa_key)

    try:
        # Decrypt the data
        decrypted_data=cipher.decrypt(encrypted_data)
        print(f"Decrypted AES Key: {b64encode(decrypted_data).decode()}")
        return decrypted_data
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None

# Lattice Encryption (example RSA-based encryption)
def encrypt_lattice(public_key, binary_message):
    rsa_key=RSA.import_key(public_key)
    cipher=PKCS1_OAEP.new(rsa_key)
    encrypted_data=cipher.encrypt(binary_message.encode())
    return encrypted_data

# Generate HMAC using SHA-256
def generate_hmac(key, data):
    """
    Generate HMAC using SHA-256
    :param key: HMAC key
    :param data: Data to be hashed (must be bytes)
    :return: HMAC digest
    """
    hmac=SHA256.new(key + data)  # No need to call .encode() on 'data' because it's already bytes
    return hmac.digest()

# Function to apply padding and handle binary data
def apply_padding(data, block_size):
    padding_length=block_size - len(data) % block_size
    padding=bytes([padding_length] * padding_length)
    return data + padding

def remove_padding(data):
    if data is None:
        print("Error: No data to remove padding!")
        return None
    padding_length=data[-1]
    return data[:-padding_length]

# Debugging utility to trace every stage of encryption and decryption
def debug_encryption_stage(stage, data):
    print(f"{stage}: {b64encode(data).decode()}")

def debug_decryption_stage(stage, data):
    print(f"{stage}: {b64encode(data).decode()}")

# Extract key and message from encrypted file (handles key sections)
def extract_key_and_data_from_encrypted_file(data):
    """
    Extracts both the key and data from the encrypted input, expecting public/private key markers
    and possibly data encoded between them.
    :param data: The encrypted data, which may contain a message and keys in a specific format.
    :return: Tuple of (key, encrypted_data)
    """
    # Check for the key boundaries
    if "-----BEGIN PUBLIC KEY-----" in data:
        key_data=data.split("-----BEGIN PUBLIC KEY-----")[1].split("-----END PUBLIC KEY-----")[0].strip()
        key=RSA.import_key(key_data)
    elif "-----BEGIN PRIVATE KEY-----" in data:
        key_data=data.split("-----BEGIN PRIVATE KEY-----")[1].split("-----END PRIVATE KEY-----")[0].strip()
        key=RSA.import_key(key_data)
    else:
        raise ValueError("No key found in the provided data.")
    
    # Now look for the encrypted data (assuming the message is separated from the key)
    encrypted_data=data.split("-----END PUBLIC KEY-----")[-1].strip()
    
    return key, encrypted_data

# Decrypt the encrypted message using RSA private key
def rsa_decrypt_message(private, encrypted_data):
    """
    Decrypts the message using the provided RSA private key
    :param private: The RSA private key used for decryption
    :param encrypted_data: The encrypted data to be decrypted
    :return: Decrypted message
    """
    # Ensure the private is in the correct format
    private=RSA.import_key(private)
    
    # Decrypt the message using RSA
    cipher_rsa=PKCS1_OAEP.new(private)
    decrypted_data=cipher_rsa.decrypt(encrypted_data.encode())  # Assuming data is a string
    
    return decrypted_data.decode('utf-8')

# Debugging utility to trace every stage of encryption and decryption
def debug_encryption_stage(stage, data):
    """
    Utility to trace encryption stages with base64 encoding
    :param stage: The stage of encryption
    :param data: Data being processed
    """
    print(f"{stage}: {b64encode(data).decode()}")

def debug_decryption_stage(stage, data):
    """
    Utility to trace decryption stages with base64 encoding
    :param stage: The stage of decryption
    :param data: Data being processed
    """
    print(f"{stage}: {b64encode(data).decode()}")

# Extract key and message from encrypted file (handles key sections)
def extract_key_and_data_from_encrypted_file(data):
    """
    Extracts both the key and data from the encrypted input, expecting public/private key markers
    and possibly data encoded between them.
    :param data: The encrypted data, which may contain a message and keys in a specific format.
    :return: Tuple of (key, encrypted_data)
    """
    # Check for the key boundaries
    if "-----BEGIN PUBLIC KEY-----" in data:
        key_data=data.split("-----BEGIN PUBLIC KEY-----")[1].split("-----END PUBLIC KEY-----")[0].strip()
        key=RSA.import_key(key_data)
    elif "-----BEGIN PRIVATE KEY-----" in data:
        key_data=data.split("-----BEGIN PRIVATE KEY-----")[1].split("-----END PRIVATE KEY-----")[0].strip()
        key=RSA.import_key(key_data)
    else:
        raise ValueError("No key found in the provided data.")
    
    # Now look for the encrypted data (assuming the message is separated from the key)
    encrypted_data=data.split("-----END PUBLIC KEY-----")[-1].strip()
    
    return key, encrypted_data

# Decrypt the encrypted message using RSA private key
def rsa_decrypt_message(private, encrypted_data):
    """
    Decrypts the message using the provided RSA private key
    :param private: The RSA private key used for decryption
    :param encrypted_data: The encrypted data to be decrypted
    :return: Decrypted message
    """
    # Ensure the private is in the correct format
    private=RSA.import_key(private)
    
    # Decrypt the message using RSA
    cipher_rsa=PKCS1_OAEP.new(private)
    decrypted_data=cipher_rsa.decrypt(encrypted_data.encode())  # Assuming data is a string
    
    return decrypted_data.decode('utf-8')

# Hash message using SHA256
def sha256_hash(message):
    """
    Hashes the input message using SHA-256
    :param message: Message to hash
    :return: SHA-256 hash of the message
    """
    h=SHA256.new()
    h.update(message.encode('utf-8'))  # Update the hash object with the message
    return h.hexdigest()

# HMAC with SHA256
def generate_hmac(key, data):
    """
    Generate HMAC using SHA-256
    :param key: HMAC key (bytes)
    :param data: Data to be hashed (bytes)
    :return: HMAC digest (bytes)
    """
    hmac=SHA256.new(key + data)  # Combine key and data for HMAC
    return hmac.digest()

# Key Derivation Function (KDF)
def derive_key(password, salt):
    """
    Derives a key using Scrypt KDF.
    :param password: The password to be used for derivation
    :param salt: The salt to be used in the KDF
    :return: Derived key
    """
    key=scrypt(password.encode('utf-8'), salt=salt, key_len=32, N=2**14, r=8, p=1)
    return key

# Encrypt a message with AES and RSA, step-by-step encryption example
def encrypt_message_with_keys(message, password, rsa_public_key):
    """
    Encrypts a message using AES encryption, then encrypts the AES key using RSA.
    :param message: Message to encrypt
    :param password: Password to derive AES key
    :param rsa_public_key: RSA public key to encrypt AES key
    :return: Tuple of (encrypted_message, encrypted_AES_key, iv)
    """
    salt=get_random_bytes(16)
    aes_key=derive_key(password, salt)  # Derive AES key from password and salt

    # Encrypt the message with AES
    iv, encrypted_message=aes_encrypt(message.encode(), aes_key)

    # Encrypt the AES key with RSA
    encrypted_aes_key=rsa_encrypt(rsa_public_key, aes_key)

    return encrypted_message, encrypted_aes_key, iv

# Decrypt a message with AES and RSA, step-by-step decryption example
def decrypt_message_with_keys(encrypted_message, encrypted_aes_key, iv, rsa_private_key, password):
    """
    Decrypts a message using RSA decryption of AES key, then AES decryption of message.
    :param encrypted_message: The encrypted message to decrypt
    :param encrypted_aes_key: Encrypted AES key to decrypt
    :param iv: Initialization vector used in AES encryption
    :param rsa_private_key: RSA private key to decrypt AES key
    :param password: Password used to derive AES key
    :return: Decrypted message
    """
    # Decrypt the AES key with RSA
    aes_key=rsa_decrypt(rsa_private_key, encrypted_aes_key)

    # If decryption fails (i.e., aes_key is None), return None
    if aes_key is None:
        print("Error: AES key decryption failed!")
        return None

    # Decrypt the message with AES
    decrypted_message=aes_decrypt(encrypted_message, aes_key, iv)

    # If AES decryption fails, return None
    if decrypted_message is None:
        print("Error: AES decryption failed!")
        return None

    return decrypted_message.decode()

