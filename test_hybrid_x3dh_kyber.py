import threading
import time
from userdb import UserDB
from networking import ChatClient, ChatServer
from chat_api import ChatAPI
from chat_logic import exchange_usernames

SERVER_USERNAME = "Alice"
CLIENT_USERNAME = "Bob"
PORT = 54321
IP = "127.0.0.1"

results = {"server": None, "client": None, "error": [], "server_msg": None}

def server_thread():
    try:
        print("[SERVER] Starting server thread")
        userdb = UserDB(SERVER_USERNAME)
        api = ChatAPI(SERVER_USERNAME, userdb, use_encryption=True)
        server = ChatServer(IP, PORT, use_encryption=True)
        print("[SERVER] Calling server.start()...")
        addr = server.start()
        print(f"[SERVER] server.start() returned, addr: {addr}")
        for i in range(20):
            if getattr(server, 'client_sock', None) is not None:
                print(f"[SERVER] client_sock accepted at iteration {i}")
                break
            time.sleep(0.05)
        if getattr(server, 'client_sock', None) is None:
            print("[SERVER] ERROR: Server did not accept client in time.")
            raise Exception("Server did not accept client in time.")
        print("[SERVER] Server started, waiting for negotiation")
        print("[SERVER] Calling api.negotiate_encryption...")
        if not api.negotiate_encryption(server, is_server=True):
            print("[SERVER] Encryption negotiation failed (mismatch)")
            results["server"] = "encryption_mismatch"
            return
        print("[SERVER] Negotiation succeeded, exchanging usernames")
        print("[SERVER] Calling exchange_usernames...")
        peer_username = exchange_usernames(server, SERVER_USERNAME, is_server=True)
        print(f"[SERVER] Username exchange complete, peer: {peer_username}")
        print("[SERVER] Starting handshake")
        print("[SERVER] Calling api.handshake...")
        api.handshake(server, is_server=True)
        print("[SERVER] Handshake complete")
        for i in range(3):
            print(f"[SERVER] Waiting for encrypted message {i+1}...")
            encrypted_data = server.receive()
            print(f"[SERVER] Received encrypted data {i+1}: {encrypted_data[:32]}... (truncated)")
            decrypted = api.decrypt(encrypted_data)
            print(f"[SERVER] Decrypted message {i+1}: {decrypted.decode('utf-8', errors='replace')}")
            results[f"server_msg_{i+1}"] = decrypted.decode('utf-8', errors='replace')
            # Server replies
            reply = f"Hello from Alice! ({i+1})"
            print(f"[SERVER] Sending reply {i+1}: {reply}")
            encrypted_reply = api.encrypt(reply.encode('utf-8'))
            server.send(encrypted_reply)
            time.sleep(3)
        results["server"] = peer_username
    except Exception as e:
        print(f"[SERVER] Exception: {e}")
        results["error"].append(f"server: {e}")

def client_thread():
    try:
        time.sleep(0.5)
        print("[CLIENT] Starting client thread")
        userdb = UserDB(CLIENT_USERNAME)
        api = ChatAPI(CLIENT_USERNAME, userdb, use_encryption=True)
        print("[CLIENT] Creating ChatClient...")
        client = ChatClient(IP, PORT, use_encryption=True)
        print("[CLIENT] Calling client.connect()...")
        client.connect()
        print("[CLIENT] Connected, starting negotiation")
        print("[CLIENT] Calling api.negotiate_encryption...")
        if not api.negotiate_encryption(client, is_server=False):
            print("[CLIENT] Encryption negotiation failed (mismatch)")
            results["client"] = "encryption_mismatch"
            return
        print("[CLIENT] Negotiation succeeded, exchanging usernames")
        print("[CLIENT] Calling exchange_usernames...")
        peer_username = exchange_usernames(client, CLIENT_USERNAME, is_server=False)
        print(f"[CLIENT] Username exchange complete, peer: {peer_username}")
        print("[CLIENT] Starting handshake")
        print("[CLIENT] Calling api.handshake...")
        api.handshake(client, is_server=False)
        print("[CLIENT] Handshake complete")
        for i in range(3):
            msg = f"Hello from Bob! ({i+1})"
            print(f"[CLIENT] Sending message {i+1}: {msg}")
            encrypted = api.encrypt(msg.encode('utf-8'))
            client.send(encrypted)
            print(f"[CLIENT] Waiting for reply {i+1}...")
            encrypted_reply = client.receive()
            print(f"[CLIENT] Received encrypted reply {i+1}: {encrypted_reply[:32]}... (truncated)")
            decrypted_reply = api.decrypt(encrypted_reply)
            print(f"[CLIENT] Decrypted reply {i+1}: {decrypted_reply.decode('utf-8', errors='replace')}")
            results[f"client_reply_{i+1}"] = decrypted_reply.decode('utf-8', errors='replace')
            time.sleep(3)
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
    print("Server received message:", results.get("server_msg"))

if __name__ == "__main__":
    run_test()
