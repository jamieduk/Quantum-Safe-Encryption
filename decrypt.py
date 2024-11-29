# Created By J~Net (c) 2024
#
# python decrypt.py encrypted_output.txt plaintext.txt
#
import sys
import os
import logging
from base64 import b64decode
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA as PyCryptoRSA
from Crypto.Cipher import AES as PyCryptoAES
from Crypto.Cipher import PKCS1_OAEP
from quantum_safe import rsa_decrypt, aes_decrypt, generate_hmac, remove_padding

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Number of rounds for decryption (230 rounds)
ROUNDS=230

def load_private_key(private_key_file):
    with open(private_key_file, 'rb') as file:
        private_key=PyCryptoRSA.import_key(file.read())
    return private_key

def decrypt_data(input_file, private_key, output_file):
    with open(input_file, 'r') as file:
        encrypted_message_b64=file.readline().strip().split(": ")[1]
        public_key_b64=file.readline().strip().split(": ")[1]

    encrypted_message=b64decode(encrypted_message_b64)
    public_key=b64decode(public_key_b64)

    encrypted_aes_key=encrypted_message[:private_key.size_in_bytes()]
    iv=encrypted_message[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
    encrypted_data=encrypted_message[private_key.size_in_bytes() + 16:-64]
    encrypted_data_hmac=encrypted_message[-64:].decode('utf-8')

    aes_key=rsa_decrypt(private_key, encrypted_aes_key)
    expected_hmac=generate_hmac(aes_key, encrypted_data).hex()

    if expected_hmac != encrypted_data_hmac:
        logging.error("Data integrity check failed!")
        sys.exit(1)

    decrypted_data=aes_decrypt(encrypted_data, aes_key, iv)

    for _ in range(ROUNDS):
        decrypted_data=aes_decrypt(decrypted_data, aes_key, iv)

    decrypted_data=remove_padding(decrypted_data)

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

    logging.info(f"Data decrypted and saved to '{output_file}'.")

def main():
    if len(sys.argv) == 3:  # Decrypt a file
        input_file=sys.argv[1]
        private_key_file='private.pem'
        output_file=sys.argv[2]
        private_key=load_private_key(private_key_file)
        decrypt_data(input_file, private_key, output_file)
    else:
        logging.error("Usage: python decrypt.py <input_file> <output_file>")
        sys.exit(1)

if __name__ == "__main__":
    main()

