# Created By J~Net (c) 2024
#
# python encrypt.py input_file.txt encrypted_output.txt
#
import sys
import os
import logging
from base64 import b64encode
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from quantum_safe import generate_rsa_keypair, aes_encrypt, rsa_encrypt, generate_hmac, apply_padding

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Number of rounds for encryption (230 rounds)
ROUNDS=230

def generate_rsa_keys():
    private, public_key=generate_rsa_keypair()
    with open('private.pem', 'wb') as private_file:
        private_file.write(private)
    with open('public.pem', 'wb') as public_file:
        public_file.write(public_key)
    logging.info("RSA key pair generated and saved to 'private.pem' and 'public.pem'.")

def load_public_key(public_key_file):
    with open(public_key_file, 'rb') as file:
        public_key=file.read()
    return RSA.import_key(public_key)

def encrypt_data(input_data, public_key, output_file):
    aes_key=get_random_bytes(32)  # AES-256 (32 bytes)
    iv=get_random_bytes(16)  # Random 128-bit IV
    padded_data=apply_padding(input_data.encode('utf-8'), AES.block_size)
    cipher=AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted_data=cipher.encrypt(padded_data)

    encrypted_aes_key=rsa_encrypt(public_key, aes_key)

    for _ in range(ROUNDS):
        cipher=AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_data=cipher.encrypt(apply_padding(encrypted_data, AES.block_size))

    encrypted_data_hmac=generate_hmac(aes_key, encrypted_data).hex()
    encrypted_message=encrypted_aes_key + iv + encrypted_data + encrypted_data_hmac.encode('utf-8')
    encrypted_message_b64=b64encode(encrypted_message).decode('utf-8')

    with open(output_file, 'w') as file:
        file.write(f"Encrypted Message: {encrypted_message_b64}\n")
        file.write(f"Public Key: {b64encode(public_key.export_key()).decode('utf-8')}\n")

    logging.info(f"Data encrypted and saved to '{output_file}'.")

def main():
    if not os.path.exists('private.pem') or not os.path.exists('public.pem'):
        generate_rsa_keys()

    if len(sys.argv) == 3:  # Encrypt a file
        input_file=sys.argv[1]
        output_file=sys.argv[2]
        with open(input_file, 'r') as file:
            input_data=file.read()
        public_key_file='public.pem'
        public_key=load_public_key(public_key_file)
        encrypt_data(input_data, public_key, output_file)
    elif len(sys.argv) == 2:  # Encrypt a string
        input_string=sys.argv[1]
        public_key_file='public.pem'
        output_file='encrypted_output.txt'
        public_key=load_public_key(public_key_file)
        encrypt_data(input_string, public_key, output_file)
    else:
        logging.error("Usage: python encrypt.py <input_file or string> <output_file>")
        sys.exit(1)

if __name__ == "__main__":
    main()

