import os
import base64
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend

# Placeholder for encryption logic (to be implemented later)
class EncryptionManager:
    def __init__(self):
        self.session_key = None
        self.bundle = None
        self.private_keys = None
        self.peer_bundle = None

    @staticmethod
    def generate_bundle():
        # X25519
        x25519_priv = x25519.X25519PrivateKey.generate()
        x25519_pub = x25519_priv.public_key()
        x25519_pub_bytes = x25519_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        x25519_priv_bytes = x25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        # Kyber1024
        kyber = oqs.KeyEncapsulation('Kyber1024')
        kyber_pub = kyber.generate_keypair()
        kyber_priv = kyber.export_secret_key()
        # Dilithium2
        dilithium = oqs.Signature('Dilithium2')
        dilithium_pub = dilithium.generate_keypair()
        dilithium_priv = dilithium.export_secret_key()
        # Sign X25519 pub and Kyber pub with Dilithium2
        signed_x25519 = dilithium.sign(x25519_pub_bytes)
        signed_kyber = dilithium.sign(kyber_pub)
        bundle = {
            'x25519_identity': base64.b64encode(x25519_pub_bytes).decode(),
            'x25519_signed_prekey': base64.b64encode(x25519_pub_bytes).decode(),
            'x25519_signed_prekey_sig': base64.b64encode(signed_x25519).decode(),
            'x25519_prekeys': [],  # For simplicity, not using one-time prekeys
            'kyber1024_identity': base64.b64encode(kyber_pub).decode(),
            'kyber1024_signed_prekey': base64.b64encode(kyber_pub).decode(),
            'kyber1024_signed_prekey_sig': base64.b64encode(signed_kyber).decode(),
            'kyber1024_prekeys': [],
            'dilithium2': base64.b64encode(dilithium_pub).decode()
        }
        private_keys = {
            'x25519': x25519_priv_bytes,
            'kyber1024': kyber_priv,
            'dilithium2': dilithium_priv
        }
        return bundle, private_keys

    def save_bundle_to_userdb(self, userdb):
        bundle, private_keys = self.generate_bundle()
        userdb.set_bundle(bundle, private_keys)
        self.bundle = bundle
        self.private_keys = private_keys

    def load_bundle_from_userdb(self, userdb):
        self.bundle = userdb.get_bundle()
        self.private_keys = userdb.get_private_keys_bundle()

    def export_bundle(self):
        return self.bundle

    def import_peer_bundle(self, bundle):
        self.peer_bundle = bundle

    def perform_key_exchange(self, sock, is_server: bool, chat_callback=None):
        import json
        import socket
        sock.settimeout(10)  # Set a timeout for handshake
        def recv_all(sock, n):
            data = b''
            while len(data) < n:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    raise Exception('Socket connection broken')
                data += chunk
            return data
        def recv_msg(sock):
            length_bytes = recv_all(sock, 4)
            if not length_bytes or len(length_bytes) < 4:
                raise Exception('Connection closed or invalid length header')
            length = int.from_bytes(length_bytes, byteorder='big')
            if length == 0:
                raise Exception('Received empty message')
            return recv_all(sock, length)
        def send_msg(sock, data: bytes):
            length = len(data)
            sock.sendall(length.to_bytes(4, byteorder='big'))
            sock.sendall(data)
        print(f"[HANDSHAKE] is_server={is_server} starting bundle exchange")
        print(f"[HANDSHAKE] Using socket: {sock}, fileno={sock.fileno()}, laddr={sock.getsockname()}, raddr={sock.getpeername()}")
        if is_server:
            peer_bundle_json = recv_msg(sock).decode('utf-8')
            print(f"[HANDSHAKE] Server received bundle: {peer_bundle_json[:60]}...")
            if not peer_bundle_json.strip():
                raise Exception('Received empty bundle from peer')
            send_msg(sock, json.dumps(self.bundle).encode('utf-8'))
            print(f"[HANDSHAKE] Server sent bundle")
        else:
            send_msg(sock, json.dumps(self.bundle).encode('utf-8'))
            print(f"[HANDSHAKE] Client sent bundle")
            peer_bundle_json = recv_msg(sock).decode('utf-8')
            print(f"[HANDSHAKE] Client received bundle: {peer_bundle_json[:60]}...")
            if not peer_bundle_json.strip():
                raise Exception('Received empty bundle from peer')
        peer_bundle = json.loads(peer_bundle_json)
        self.import_peer_bundle(peer_bundle)
        # Verify signatures
        peer_dilithium_pub = base64.b64decode(peer_bundle['dilithium2'])
        peer_dilithium = oqs.Signature('Dilithium2')
        x25519_signed_prekey = base64.b64decode(peer_bundle['x25519_signed_prekey'])
        x25519_signed_prekey_sig = base64.b64decode(peer_bundle['x25519_signed_prekey_sig'])
        kyber_signed_prekey = base64.b64decode(peer_bundle['kyber1024_signed_prekey'])
        kyber_signed_prekey_sig = base64.b64decode(peer_bundle['kyber1024_signed_prekey_sig'])
        if not peer_dilithium.verify(x25519_signed_prekey, x25519_signed_prekey_sig, peer_dilithium_pub):
            raise Exception('Peer X25519 signed prekey signature invalid!')
        if not peer_dilithium.verify(kyber_signed_prekey, kyber_signed_prekey_sig, peer_dilithium_pub):
            raise Exception('Peer Kyber1024 signed prekey signature invalid!')
        # Hybrid DH: X25519 + Kyber1024
        my_x25519_priv = x25519.X25519PrivateKey.from_private_bytes(self.private_keys['x25519'])
        peer_x25519_pub = x25519.X25519PublicKey.from_public_bytes(base64.b64decode(peer_bundle['x25519_identity']))
        x25519_secret = my_x25519_priv.exchange(peer_x25519_pub)
        my_kyber = oqs.KeyEncapsulation('Kyber1024')
        my_kyber._secret_key = self.private_keys['kyber1024']
        peer_kyber_pub = base64.b64decode(peer_bundle['kyber1024_identity'])
        if is_server:
            print(f"[HANDSHAKE] Server waiting for Kyber ciphertext...")
            ct = recv_msg(sock)
            print(f"[HANDSHAKE] Server received Kyber ciphertext: {ct[:16].hex()}...")
            kyber_secret = my_kyber.decap_secret(ct)
        else:
            print(f"[HANDSHAKE] Client sending Kyber ciphertext...")
            ct, kyber_secret = my_kyber.encap_secret(peer_kyber_pub)
            send_msg(sock, ct)
            print(f"[HANDSHAKE] Client sent Kyber ciphertext: {ct[:16].hex()}...")
        concat_secret = x25519_secret + kyber_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pqxdh-session',
            backend=default_backend()
        )
        self.session_key = hkdf.derive(concat_secret)
        print(f"[HANDSHAKE] Session key established: {self.session_key[:8].hex()}...")
        if chat_callback:
            chat_callback('[Key Exchange] Secure channel established (PQXDH)')
        return True

    def encrypt(self, data: bytes) -> bytes:
        if not self.session_key:
            return data
        from crypt.aes_gcm import encrypt
        return encrypt(self.session_key, data)

    def decrypt(self, data: bytes) -> bytes:
        if not self.session_key:
            return data
        from crypt.aes_gcm import decrypt
        return decrypt(self.session_key, data)
