import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from crypt.aes_gcm import encrypt

# Message Sending Function
def send_secure_message(host, port, message, encryption_choice):
    if encryption_choice == "1":  # AES-GCM
        key_hex = input("Enter a 32-byte key (hex): ").strip()
        key = bytes.fromhex(key_hex)  # Convert hex key to bytes
        encrypted_message = encrypt(key, message.encode())  # Encrypt message
    else:
        encrypted_message = message.encode()  # Send plaintext if no encryption
    
    # Establish connection and send message
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(encrypted_message)
        print("Message sent securely.")

# Main execution
if __name__ == "__main__":
    host = input("Enter receiver's IP address: ").strip()
    port = int(input("Enter receiver's port: ").strip())
    message = input("Enter your message: ").strip()

    print("Select Encryption Method:")
    print("1. AES-GCM")
    print("2. No Encryption")
    encryption_choice = input("Enter choice (1-2): ").strip()

    send_secure_message(host, port, message, encryption_choice)

