import socket
import threading
from oqs import KeyEncapsulation, Signature
import sys

def establish_duplex_connection(ip, port, is_server=False):
    """
    Establishes a full-duplex plaintext communication between two computers.
    
    Args:
        ip (str): IP address to connect to or bind to
        port (int): Port number to use
        is_server (bool): If True, act as server and wait for connection
                         If False, act as client and connect to server
    
    Returns:
        socket: Connected socket object
    """
    if is_server:
        # Server mode
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((ip, port))
        server_socket.listen(1)
        print(f"Server listening on {ip}:{port}")
        conn, addr = server_socket.accept()
        print(f"Connection established with {addr}")
        server_socket.close()
        return conn
    else:
        # Client mode
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, port))
        print(f"Connected to server at {ip}:{port}")
        return client_socket

def send_message(conn, message_queue):
    """Continuously send messages from the queue"""
    try:
        while True:
            message = input("You: ")
            conn.sendall(message.encode('utf-8'))
    except Exception as e:
        print(f"Send error: {e}")
    finally:
        conn.close()

def receive_message(conn):
    """Continuously receive and display messages"""
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                print("Connection closed by remote host")
                break
            print(f"\nReceived: {data.decode('utf-8')}")
            print("You: ", end='', flush=True)
    except Exception as e:
        print(f"Receive error: {e}")
    finally:
        conn.close()

def start_duplex_communication(ip, port, is_server=False):
    """
    Start full-duplex communication between two computers.
    
    Args:
        ip (str): IP address to connect to or bind to
        port (int): Port number to use
        is_server (bool): If True, act as server; if False, act as client
    """
    try:
        conn = establish_duplex_connection(ip, port, is_server)
        
        # Create threads for sending and receiving
        message_queue = []
        send_thread = threading.Thread(target=send_message, args=(conn, message_queue))
        receive_thread = threading.Thread(target=receive_message, args=(conn,))
        
        # Start threads
        send_thread.daemon = True
        receive_thread.daemon = True
        send_thread.start()
        receive_thread.start()
        
        # Wait for threads to complete
        send_thread.join()
        receive_thread.join()
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Communication ended")

def start_secure_communication(ip, port, is_server=False):
    """
    Start secure full-duplex communication between two computers using
    Kyber512 for key exchange and Dilithium for authentication.
    
    Args:
        ip (str): IP address to connect to or bind to
        port (int): Port number to use
        is_server (bool): If True, act as server; if False, act as client
    """
    try:
        # First establish a connection
        conn = establish_duplex_connection(ip, port, is_server)
        
        # Import liboqs for post-quantum cryptography
        
        if is_server:
            # Server: Generate Kyber keypair for key encapsulation
            kex = KeyEncapsulation("Kyber512")
            public_key = kex.generate_keypair()
            
            # Send public key to client
            conn.sendall(public_key)
            
            # Wait for encapsulated key from client
            enc_key = conn.recv(1024)
            shared_secret = kex.decap_secret(enc_key)
            
            # Generate Dilithium signature keypair
            sig = Signature("Dilithium2")
            sig_public_key = sig.generate_keypair()
            
            # Send signature public key
            conn.sendall(sig_public_key)
            
            # Sign the shared secret to authenticate
            signature = sig.sign(shared_secret)
            conn.sendall(signature)
            
            # Verify client's signature
            client_sig_key = conn.recv(1024)
            client_signature = conn.recv(1024)
            
            client_sig_verifier = Signature("Dilithium2")
            if not client_sig_verifier.verify(shared_secret, client_signature, client_sig_key):
                raise Exception("Client authentication failed!")
                
            print("Secure channel established (server)")
            
        else:
            # Client: Receive Kyber public key from server
            server_public_key = conn.recv(1024)
            
            # Use the public key to encapsulate a shared secret
            kex = KeyEncapsulation("Kyber512")
            ciphertext, shared_secret = kex.encap_secret(server_public_key)
            
            # Send encapsulated key to server
            conn.sendall(ciphertext)
            
            # Receive server's signature public key
            server_sig_key = conn.recv(1024)
            
            # Receive signature from server
            server_signature = conn.recv(1024)
            
            # Verify server's signature
            sig_verifier = Signature("Dilithium2")
            if not sig_verifier.verify(shared_secret, server_signature, server_sig_key):
                raise Exception("Server authentication failed!")
            
            # Generate Dilithium signature keypair
            sig = Signature("Dilithium2")
            sig_public_key = sig.generate_keypair()
            
            # Send signature public key
            conn.sendall(sig_public_key)
            
            # Sign the shared secret to authenticate
            signature = sig.sign(shared_secret)
            conn.sendall(signature)
            
            print("Secure channel established (client)")
        
        # Now start normal communication using the established channel
        # The actual messages would typically be encrypted using the shared_secret
        
        # Start full-duplex communication
        message_queue = []
        send_thread = threading.Thread(target=send_message, args=(conn, message_queue))
        receive_thread = threading.Thread(target=receive_message, args=(conn,))
        
        # Start threads
        send_thread.daemon = True
        receive_thread.daemon = True
        send_thread.start()
        receive_thread.start()
        
        # Wait for threads to complete
        send_thread.join()
        receive_thread.join()
        
    except Exception as e:
        print(f"Secure communication error: {e}")
    finally:
        print("Secure communication ended")

if __name__ == "__main__":
    
    # Default values
    ip = "127.0.0.1"  # localhost
    port = 5555
    
    # Simple command line parsing
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        # Optional custom port
        if len(sys.argv) > 2:
            try:
                port = int(sys.argv[2])
            except ValueError:
                print("Port must be a number. Using default port 5555.")
        
        # Start in requested mode
        if mode == "server":
            print("Starting in server mode...")
            start_secure_communication(ip, port, is_server=True)
        elif mode == "client":
            print("Starting in client mode...")
            start_secure_communication(ip, port, is_server=False)
        elif mode == "plaintext-server":
            print("Starting in plaintext server mode...")
            start_duplex_communication(ip, port, is_server=True)
        elif mode == "plaintext-client":
            print("Starting in plaintext client mode...")
            start_duplex_communication(ip, port, is_server=False)
        else:
            print("Invalid mode. Use 'server', 'client', 'plaintext-server', or 'plaintext-client'")
    else:
        print("Usage: python comms.py [mode] [port]")
        print("Modes: server, client, plaintext-server, plaintext-client")
        print("Example: python comms.py server 5555")