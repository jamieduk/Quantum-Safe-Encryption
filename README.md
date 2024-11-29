 # Quantum-Safe Encryption and Decryption

This project provides a secure encryption and decryption mechanism using AES for symmetric encryption and RSA for asymmetric key exchange. The implementation includes robust error handling, logging, and modular code for better maintainability.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## Features

- **AES Encryption**: Symmetric encryption using AES-256 in CBC mode.
- **RSA Key Exchange**: Asymmetric encryption using RSA for secure key exchange.
- **HMAC Integrity Check**: HMAC with SHA-256 for data integrity verification.
- **Modular Code**: Code is broken down into smaller, manageable functions for better readability and maintainability.
- **Error Handling**: Robust error handling to catch and handle exceptions gracefully.
- **Logging**: Logging for better debugging and monitoring.

## Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/yourusername/quantum-safe-encryption.git
   cd quantum-safe-encryption
Install Dependencies:

pip install -r requirements.txt
Usage
Encryption
To encrypt a file or a string, use the encrypt.py script:


python encrypt.py <input_file_or_string> <output_file>
<input_file_or_string>: The path to the input file or the string to be encrypted.
<output_file>: The path to the output file where the encrypted data will be saved.
Decryption
To decrypt a file, use the decrypt.py script:


python decrypt.py <input_file> <output_file>
<input_file>: The path to the input file containing the encrypted data.
<output_file>: The path to the output file where the decrypted data will be saved.
Configuration
The number of encryption/decryption rounds and other settings can be configured by modifying the constants in the encrypt.py and decrypt.py scripts.

Security Considerations
RSA Key Size: The RSA key size is set to 2048 bits, which is considered secure against classical attacks. However, RSA is not quantum-safe.
AES Key Size: The AES key size is set to 256 bits, which provides strong security against both classical and quantum attacks.
HMAC: HMAC with SHA-256 is used for data integrity verification.
Quantum Safety
The current implementation using RSA and AES is not considered quantum-safe. To achieve quantum safety, consider transitioning to post-quantum cryptographic algorithms or using hybrid approaches that combine classical and post-quantum algorithms.

Contributing
Contributions are welcome! Please follow these steps to contribute:

Fork the repository.
Create a new branch (git checkout -b feature-branch).
Make your changes and commit them (git commit -am 'Add new feature').
Push to the branch (git push origin feature-branch).
Create a new Pull Request.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Contact
For any questions or issues, please open an issue on the GitHub repository or contact the maintainer directly.
