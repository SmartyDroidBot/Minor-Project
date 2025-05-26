import threading
import time
from userdb import UserDB
from networking import ChatClient, ChatServer
from chat_api import ChatAPI
from chat_logic import exchange_usernames

# Dummy test usernames
SERVER_USERNAME = "Alice"
CLIENT_USERNAME = "Bob"
PORT = 54321
IP = "127.0.0.1"

# Shared state for test
results = {"server": None, "client": None, "error": []}

# Server thread
def server_thread():
    try:
        print("[SERVER] Starting server thread")
        userdb = UserDB(SERVER_USERNAME)
        api = ChatAPI(SERVER_USERNAME, userdb, use_encryption=True)
        server = ChatServer(IP, PORT, use_encryption=True)
        addr = server.start()
        # Wait for client_sock to be ready
        for _ in range(20):
            if server.client_sock is not None:
                break
            time.sleep(0.05)
        if server.client_sock is None:
            raise Exception("Server did not accept client in time.")
        print("[SERVER] Server started, waiting for negotiation")
        # Encryption negotiation
        if not api.negotiate_encryption(server, is_server=True):
            print("[SERVER] Encryption negotiation failed (mismatch)")
            results["server"] = "encryption_mismatch"
            return
        print("[SERVER] Negotiation succeeded, exchanging usernames")
        # Username exchange
        peer_username = exchange_usernames(server, SERVER_USERNAME, is_server=True)
        print(f"[SERVER] Username exchange complete, peer: {peer_username}")
        # PQXDH handshake
        print("[SERVER] Starting handshake")
        api.handshake(server, is_server=True)
        print("[SERVER] Handshake complete")
        results["server"] = peer_username
    except Exception as e:
        print(f"[SERVER] Exception: {e}")
        results["error"].append(f"server: {e}")

# Client thread
def client_thread():
    try:
        time.sleep(0.5)  # Ensure server is listening
        print("[CLIENT] Starting client thread")
        userdb = UserDB(CLIENT_USERNAME)
        api = ChatAPI(CLIENT_USERNAME, userdb, use_encryption=True)
        client = ChatClient(IP, PORT, use_encryption=True)
        client.connect()
        print("[CLIENT] Connected, starting negotiation")
        # Encryption negotiation
        if not api.negotiate_encryption(client, is_server=False):
            print("[CLIENT] Encryption negotiation failed (mismatch)")
            results["client"] = "encryption_mismatch"
            return
        print("[CLIENT] Negotiation succeeded, exchanging usernames")
        # Username exchange
        peer_username = exchange_usernames(client, CLIENT_USERNAME, is_server=False)
        print(f"[CLIENT] Username exchange complete, peer: {peer_username}")
        # PQXDH handshake
        print("[CLIENT] Starting handshake")
        api.handshake(client, is_server=False)
        print("[CLIENT] Handshake complete")
        results["client"] = peer_username
    except Exception as e:
        print(f"[CLIENT] Exception: {e}")
        results["error"].append(f"client: {e}")

def run_test():
    t1 = threading.Thread(target=server_thread)
    t2 = threading.Thread(target=client_thread)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    print("Test Results:")
    print("Server peer username:", results["server"])
    print("Client peer username:", results["client"])
    print("Errors:", results["error"])

if __name__ == "__main__":
    run_test()
