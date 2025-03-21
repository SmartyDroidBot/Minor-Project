import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AES-GCM Decryption Function
def decrypt(key, ciphertext):
    nonce = ciphertext[:12]  # First 12 bytes = nonce
    tag = ciphertext[12:28]  # Next 16 bytes = authentication tag
    actual_ciphertext = ciphertext[28:]  # Remaining = encrypted data
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext

# Start Receiver Function
def start_receiver(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Receiver listening on {host}:{port}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(1024)
            print("Received Message (Raw Hex):", data.hex())  # Print raw data

            # Ask if encryption was used
            is_encrypted = input("Was this message encrypted? (y/n): ").strip().lower()
            
            if is_encrypted == "y":
                key_hex = input("Enter the 32-byte key (hex) for decryption: ").strip()
                key = bytes.fromhex(key_hex)  # Convert hex key to bytes
                try:
                    decrypted_message = decrypt(key, data)
                    print("Decrypted Message:", decrypted_message.decode())
                except Exception as e:
                    print("Decryption failed:", e)
            else:
                print("Message (decoded):", data.decode(errors='ignore'))

if __name__ == "__main__":
    host = "0.0.0.0"  # globaltesting
    port = 12345  # Choose a free port
    start_receiver(host, port)

