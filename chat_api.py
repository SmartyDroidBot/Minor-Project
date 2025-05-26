# chat_api.py
from encryption import EncryptionManager

class ChatAPI:
    def __init__(self, username, userdb, use_encryption):
        self.username = username
        self.userdb = userdb
        self.use_encryption = use_encryption
        self.encryption_manager = None
        if use_encryption:
            self.encryption_manager = EncryptionManager()
            if not self.userdb.get_bundle() or not self.userdb.get_private_keys_bundle():
                self.encryption_manager.save_bundle_to_userdb(self.userdb)
            else:
                self.encryption_manager.load_bundle_from_userdb(self.userdb)

    def negotiate_encryption(self, connection, is_server):
        # Set a short timeout for negotiation to avoid indefinite blocking
        import socket
        orig_timeout = None
        # Use correct socket: ChatServer.client_sock (preferred), else ChatClient.sock
        sock = getattr(connection, 'client_sock', None)
        if sock is None:
            sock = getattr(connection, 'sock', None)
        print(f"[NEGOTIATE] Using socket: {sock}, is_server={is_server}")
        try:
            if sock:
                orig_timeout = sock.gettimeout()
                sock.settimeout(5)
            if is_server:
                print("[NEGOTIATE] Server waiting to receive 1 byte...")
                peer_enc = sock.recv(1)
                print(f"[NEGOTIATE] Server received: {peer_enc}")
                sock.send(b'1' if self.use_encryption else b'0')
                print(f"[NEGOTIATE] Server sent: {b'1' if self.use_encryption else b'0'}")
            else:
                print("[NEGOTIATE] Client sending 1 byte...")
                sock.send(b'1' if self.use_encryption else b'0')
                print(f"[NEGOTIATE] Client sent: {b'1' if self.use_encryption else b'0'}")
                peer_enc = sock.recv(1)
                print(f"[NEGOTIATE] Client received: {peer_enc}")
            if not peer_enc:
                raise Exception("Peer disconnected during encryption negotiation.")
            peer_enc = peer_enc == b'1'
            print(f"[NEGOTIATE] Negotiation result: peer_enc={peer_enc}, self.use_encryption={self.use_encryption}")
            return peer_enc == self.use_encryption
        except socket.timeout:
            print("[NEGOTIATE] Timed out during encryption negotiation.")
            raise Exception("Timed out during encryption negotiation.")
        finally:
            # Restore original timeout after negotiation
            if sock and orig_timeout is not None:
                sock.settimeout(orig_timeout)
                print(f"[NEGOTIATE] Restored original timeout: {orig_timeout}")
            elif sock:
                sock.settimeout(None)  # Remove timeout (blocking mode)
                print("[NEGOTIATE] Removed timeout, set to blocking mode")

    def handshake(self, connection, is_server, chat_callback=None, debug_mode=False):
        if self.use_encryption:
            sock = getattr(connection, 'client_sock', None)
            if sock is None:
                sock = getattr(connection, 'sock', None)
            self.encryption_manager.perform_key_exchange(sock, is_server, chat_callback, debug_mode=debug_mode)

    def encrypt(self, data: bytes) -> bytes:
        if self.use_encryption:
            return self.encryption_manager.encrypt(data)
        return data

    def decrypt(self, data: bytes) -> bytes:
        if self.use_encryption:
            return self.encryption_manager.decrypt(data)
        return data
