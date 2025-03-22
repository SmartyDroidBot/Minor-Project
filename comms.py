import socket
import threading
from oqs import KeyEncapsulation, Signature
import sys
import urllib.request

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

        
def get_ip_addresses():
    """Get both local and public IP addresses"""
    # Get local IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    
    # Get public IP
    try:
        public_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
    except Exception:
        public_ip = "Unable to determine public IP"
    
    return local_ip, public_ip

if __name__ == "__main__":
    local_ip, public_ip = get_ip_addresses()
    
    print(f"Local IP address: {local_ip}")
    print(f"Public IP address: {public_ip}")
    
    if len(sys.argv) < 3:
        print("Usage: python comms.py [server|client] [port] [ip_address (for client only)]")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    port = int(sys.argv[2])
    
    if mode == "server":
        print(f"Starting server on port {port}")
        print(f"Others can connect using your local IP ({local_ip}) if on the same network")
        print(f"Or using your public IP ({public_ip}) if on different networks")
        start_duplex_communication("0.0.0.0", port, is_server=True)
    elif mode == "client":
        if len(sys.argv) < 4:
            print("Error: IP address required for client mode")
            sys.exit(1)
        ip = sys.argv[3]
        print(f"Connecting to server at {ip}:{port}")
        start_duplex_communication(ip, port, is_server=False)
    else:
        print("Invalid mode. Use 'server' or 'client'")
        sys.exit(1)