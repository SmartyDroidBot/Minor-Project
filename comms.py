import os
import socket
import argparse
import threading
import sys
from oqs import KeyEncapsulation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(key, plaintext):
    # Generate a random 12-byte nonce (IV for GCM)
    nonce = os.urandom(12)
    # Create a Cipher object using the key and nonce with GCM mode
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    # Encrypt the plaintext (no padding needed for GCM)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Return the nonce, ciphertext, and authentication tag
    return nonce + encryptor.tag + ciphertext

def decrypt(key, ciphertext):
    # Extract the nonce and authentication tag from the beginning of the ciphertext
    nonce = ciphertext[:12]
    tag = ciphertext[12:28]  # GCM tag is 16 bytes
    actual_ciphertext = ciphertext[28:]
    # Create a Cipher object using the key, nonce and tag with GCM mode
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    # Decrypt the ciphertext and verify the authentication tag
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return plaintext


# Helper function to send data over socket
def send_data(sock, data):
    # First send the length of the data as 4 bytes
    length = len(data)
    sock.sendall(length.to_bytes(4, byteorder='big'))
    # Then send the actual data
    sock.sendall(data)

# Helper function to receive data from socket
def receive_data(sock):
    # First receive the length of the data
    length_bytes = sock.recv(4)
    if not length_bytes:
        return None
    length = int.from_bytes(length_bytes, byteorder='big')
    # Then receive the actual data
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), 4096))
        if not chunk:
            raise ConnectionError("Connection broken while receiving data")
        data += chunk
    return data

# Server function to handle key exchange and communication
def server_mode(host='0.0.0.0', port=12345):
    # Create server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind((host, port))
        server_sock.listen(1)
        
        print(f"[*] Server listening on {host}:{port}")
        print("[*] Waiting for client connection...")
        
        client_sock, client_addr = server_sock.accept()
        print(f"[+] Connection established with {client_addr[0]}:{client_addr[1]}")
        
        # Perform Kyber key exchange (server initiates)
        print("[*] Initiating Kyber key exchange...")
        
        # Generate server's Kyber keypair
        server_kem = KeyEncapsulation("Kyber512")
        server_public_key = server_kem.generate_keypair()
        server_secret_key = server_kem.export_secret_key()
        print("[-] DEBUG Server public key",server_public_key.hex())
        print("[-] DEBUG Server secret key",server_secret_key.hex())
        # Send server's public key to client
        send_data(client_sock, server_public_key)
        
        # Receive client's ciphertext
        client_ciphertext = receive_data(client_sock)

        print("[-] DEBUG Recieved Client ciphertext",client_ciphertext.hex())
        
        # Decapsulate shared secret using server's secret key
        server_kem = KeyEncapsulation("Kyber512", server_secret_key)
        shared_secret = server_kem.decap_secret(client_ciphertext)
        
        # Use first 32 bytes of shared secret as AES key
        aes_key = shared_secret[:32]
        print("[+] Secure key exchange completed successfully")
        print("[-] DEBUG AES KEY ESTABLISHED",aes_key.hex())
        # Start encrypted communication
        handle_communication(client_sock, aes_key, "Server")
        
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        server_sock.close()

# Client function to handle key exchange and communication
def client_mode(host, port):
    # Create client socket
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"[*] Connecting to server at {host}:{port}...")
        client_sock.connect((host, port))
        print("[+] Connected to server")
        
        # Perform Kyber key exchange
        print("[*] Participating in Kyber key exchange...")
        
        # Receive server's public key
        server_public_key = receive_data(client_sock)
        print("[-] DEBUG Recieved Server public key",server_public_key.hex())
        # Generate client's ciphertext and shared secret
        client_kem = KeyEncapsulation("Kyber512")
        ciphertext, shared_secret = client_kem.encap_secret(server_public_key)
        print("[-] DEBUG Client ciphertext",ciphertext.hex())
        # Send ciphertext to server
        send_data(client_sock, ciphertext)
        
        # Use first 32 bytes of shared secret as AES key
        aes_key = shared_secret[:32]
        print("[+] Secure key exchange completed successfully")
        print("[-] DEBUG AES KEY ESTABLISHED",aes_key.hex())
        # Start encrypted communication
        handle_communication(client_sock, aes_key, "Client")
        
    except KeyboardInterrupt:
        print("\n[!] Client shutting down...")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client_sock.close()

# Function to handle encrypted communication
def handle_communication(sock, aes_key, role):
    print(f"\n[*] Starting secure communication ({role})")
    print("[*] Type messages to send or press Ctrl+C to exit")
    
    # Thread function to receive messages
    def receive_messages():
        try:
            while True:
                encrypted_msg = receive_data(sock)
                print("[-] Debug Encrypted message:",encrypted_msg.hex())
                if not encrypted_msg:
                    print("\n[!] Connection closed by peer")
                    os._exit(0)  # Force exit to terminate the program
                
                # Decrypt the message
                try:
                    decrypted_msg = decrypt(aes_key, encrypted_msg)
                    print(f"\n[Received]: {decrypted_msg.decode('utf-8')}")
                    print("[You]: ", end="", flush=True)
                except Exception as e:
                    print(f"\n[!] Failed to decrypt message: {e}")
        except ConnectionError:
            print("\n[!] Connection lost")
            os._exit(0)
        except Exception as e:
            print(f"\n[!] Error in receiving: {e}")
            os._exit(0)
    
    # Start the receiving thread
    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()
    
    # Main thread handles sending messages
    try:
        while True:
            msg = input("[You]: ")
            if msg:
                encrypted_msg = encrypt(aes_key, msg.encode('utf-8'))
                send_data(sock, encrypted_msg)
    except KeyboardInterrupt:
        print("\n[!] Terminating connection...")
    except Exception as e:
        print(f"\n[!] Error in sending: {e}")

def main():
    parser = argparse.ArgumentParser(description="Secure communication with Kyber key exchange and AES encryption")
    parser.add_argument("--server", action="store_true", help="Run in server mode")
    parser.add_argument("--client", action="store_true", help="Run in client mode")
    parser.add_argument("--host", help="Host IP for client to connect to")
    parser.add_argument("--port", type=int, default=12345, help="Port number (default: 12345)")
    
    args = parser.parse_args()
    
    if not (args.server or args.client):
        # No mode specified, ask user
        mode = input("Run as (s)erver or (c)lient? ").lower()
        if mode.startswith('s'):
            args.server = True
        elif mode.startswith('c'):
            args.client = True
        else:
            print("Invalid choice. Exiting.")
            return
    
    if args.server and args.client:
        print("Cannot run as both server and client. Please choose one.")
        return
    
    if args.server:
        server_mode(port=args.port)
    elif args.client:
        if not args.host:
            args.host = input("Enter server IP address: ")
        client_mode(args.host, args.port)

if __name__ == "__main__":
    main()
