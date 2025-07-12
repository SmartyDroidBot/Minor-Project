# Secure Chat Application

This project is a secure, end-to-end encrypted chat application implemented in Python. It features a GUI, user authentication, and strong cryptography for secure communication between users.

## Hybrid X3DH-Kyber Security

- This chat application uses a hybrid key exchange protocol combining the classical X3DH (Extended Triple Diffie-Hellman) with the post-quantum Kyber KEM for key exchange, providing strong security even against quantum computers.
- The protocol combines the X3DH protocol with post-quantum cryptography (via liboqs-python and x3dh modules) to ensure future-proof, end-to-end encrypted messaging.
- All key exchanges and message encryptions are designed to resist both classical and quantum attacks.

## Features

- End-to-end encryption using Hybrid X3DH-Kyber and AES-GCM
- User authentication and key management
- GUI for easy chat experience
- Secure key exchange and message encryption
- User database management (JSON-based)

## Project Structure

- `chat_api.py`: Core chat API, encryption negotiation, and message handling
- `chat_gui.py`: Graphical user interface for chat
- `chat_logic.py`: Chat logic and event handling
- `encryption.py`: Encryption manager and cryptographic operations
- `networking.py`: Networking and socket communication
- `userdb.py`: User database management
- `user.py`: User model
- `crypt/`: AES-GCM implementation and tests
- `hybrid_x3dh_kyber/`: Hybrid X3DH-Kyber key exchange implementation

## Usage

1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
2. Run the chat application:
   ```sh
   python chat_gui.py
   ```
3. Follow the GUI prompts to create users, connect, and chat securely.

## Requirements

- Python 3.10+
- See `requirements.txt` for dependencies
- Requires liboqs-python and x3dh for post-quantum security

## Security Notes

- All messages are encrypted end-to-end.
- Key exchange uses Hybrid X3DH-Kyber for post-quantum security (liboqs-python, x3dh).
- AES-GCM is used for symmetric encryption.

