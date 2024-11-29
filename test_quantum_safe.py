# Created By J~Net (c) 2024
#
# test_quantum_safe.py
#
from quantum_safe import (
    generate_rsa_keypair, rsa_encrypt, rsa_decrypt,
    aes_encrypt, aes_decrypt, generate_hmac,
    apply_padding, remove_padding
)
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES  # Import the AES module

def debug_encryption_stage(stage_name, data):
    print(f"{stage_name} (Base64): {b64encode(data).decode()}")

def debug_decryption_stage(stage_name, data):
    print(f"{stage_name} (Base64): {b64encode(data).decode()}")

def test_quantum_safe_encryption():
    # Step 1: Generate RSA keys (For secure AES key exchange)
    private_key, public_key=generate_rsa_keypair()
    print(f"RSA Private Key (Base64): {b64encode(private_key).decode()}")
    print(f"RSA Public Key (Base64): {b64encode(public_key).decode()}")

    # Step 2: AES Key Generation and Encryption
    aes_key=get_random_bytes(32)  # AES-256 key size
    print(f"AES Key (Base64): {b64encode(aes_key).decode()}")

    message="This is a secure message.".encode()
    print(f"Original Message (Base64): {b64encode(message).decode()}")

    # Step 3: Apply padding to the message
    padded_message=apply_padding(message, AES.block_size)
    debug_encryption_stage("Padded Message", padded_message)

    # Step 4: Encrypt Message with AES
    iv, encrypted_message=aes_encrypt(padded_message, aes_key)
    debug_encryption_stage("Encrypted Message", encrypted_message)

    # Step 5: Encrypt AES Key with RSA
    encrypted_aes_key=rsa_encrypt(public_key, aes_key)
    debug_encryption_stage("Encrypted AES Key", encrypted_aes_key)

    # Step 6: Encrypt everything (message, AES key) together
    encrypted_data=encrypted_aes_key + iv + encrypted_message
    debug_encryption_stage("Encrypted Data (Full)", encrypted_data)

    # Step 7: Add HMAC for integrity check (signed with RSA)
    hmac_key=get_random_bytes(16)
    hmac_value=generate_hmac(hmac_key, encrypted_data)
    print(f"HMAC (SHA256): {b64encode(hmac_value).decode()}")

    # Step 8: Decryption Process

    # Step 8.1: Split encrypted data to retrieve AES key, IV, and encrypted message
    decrypted_aes_key=rsa_decrypt(private_key, encrypted_data[:256])
    iv=encrypted_data[256:272]
    encrypted_message=encrypted_data[272:]

    debug_decryption_stage("Decrypted AES Key", decrypted_aes_key)
    debug_decryption_stage("IV", iv)
    debug_decryption_stage("Encrypted Message", encrypted_message)

    # Step 8.2: Decrypt message with AES
    decrypted_message=aes_decrypt(encrypted_message, decrypted_aes_key, iv)
    debug_decryption_stage("Decrypted Message (Raw)", decrypted_message)

    # Step 8.3: Remove padding and verify integrity
    original_message=remove_padding(decrypted_message)
    print(f"Original Message (Decoded): {original_message.decode()}")

    # Step 9: Compare hashes to verify message integrity
    original_hash=SHA256.new(message).hexdigest()
    decrypted_hash=SHA256.new(original_message).hexdigest()

    print(f"Original Hash: {original_hash}")
    print(f"Decrypted Hash: {decrypted_hash}")

    assert original_message == message, "Decryption failed: messages do not match!"
    assert original_hash == decrypted_hash, "Integrity check failed: hashes do not match!"

    print("Encryption and Decryption successful!")

if __name__ == "__main__":
    test_quantum_safe_encryption()

