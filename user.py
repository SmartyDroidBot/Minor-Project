import socket
import os
from cryptography.hazmat.backends import default_backend
from crypt.aes_gcm import encrypt, decrypt
import threading
import time

def send_secure_message():
    host = input("Enter receiver's IP address: ").strip() or "127.0.0.1"
    port = int(input("Enter receiver's port: ").strip() or "12345")
    message = input("Enter your message: ").strip()

    key_hex = input("Enter a 32-byte key (hex) or press Enter to generate one: ").strip()
    if not key_hex:
        key = os.urandom(32)  # Generate a random 32-byte key
        key_hex = key.hex()
        print(f"Generated key (hex): {key_hex}")
    else:
        key = bytes.fromhex(key_hex)  # Convert hex key to bytes
    
    encrypted_message = encrypt(key, message.encode())  # Encrypt message

    
    # Establish connection and send message
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(encrypted_message)
            print("Message sent successfully.")
    except Exception as e:
        print(f"Error sending message: {e}")

def start_receiver():
    host = input("Enter IP address to listen on (default: 127.0.0.1): ").strip() or "127.0.0.1"
    port = int(input("Enter port to listen on (default: 12345): ").strip() or "12345")
    
    print(f"Listening on {host}:{port}...")
    print("(Press Ctrl+C to return to the main menu)")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            
            # Set a timeout so we can catch KeyboardInterrupt
            s.settimeout(1.0)
            
            while True:
                try:
                    conn, addr = s.accept()
                    with conn:
                        print(f"\nConnection from {addr}")
                        data = conn.recv(1024)
                        print("Received Message (Raw Hex):", data.hex())  # Print raw data

                        key_hex = input("Enter the 32-byte key (hex) for decryption: ").strip()
                        key = bytes.fromhex(key_hex)  # Convert hex key to bytes
                        try:
                            decrypted_message = decrypt(key, data)
                            print("Decrypted Message:", decrypted_message.decode())
                        except Exception as e:
                            print("Decryption failed:", e)
                except socket.timeout:
                    # This is just to allow for keyboard interrupt
                    continue
    except KeyboardInterrupt:
        print("\nStopping receiver...")
    except Exception as e:
        print(f"Error in receiver: {e}")

def main_menu():
    while True:
        print("\n=== Secure Messaging Application ===")
        print("1. Send a message")
        print("2. Receive messages")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            send_secure_message()
        elif choice == "2":
            start_receiver()
        elif choice == "3":
            print("Exiting application...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    print("Welcome to the Secure Messaging Application")
    main_menu()
