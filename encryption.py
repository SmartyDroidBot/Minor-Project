import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import x3dh
from hybrid_x3dh_kyber.core import HybridX3DHKyberCore
from hybrid_x3dh_kyber.serialize import (
    hybrid_x3dh_kyber_bundle_to_wire, hybrid_x3dh_kyber_bundle_from_wire,
    hybrid_x3dh_kyber_peer_bundle_to_wire, hybrid_x3dh_kyber_peer_bundle_from_wire
)

class EncryptionManager:
    def __init__(self):
        self.pqxdh = HybridX3DHKyberCore()
        self.session_key = None

    @staticmethod
    def generate_bundle():
        bundle, private_keys = HybridX3DHKyberCore.generate_bundle()
        return hybrid_x3dh_kyber_bundle_to_wire(bundle, private_keys)

    def save_bundle_to_userdb(self, userdb):
        bundle, private_keys = self.generate_bundle()
        userdb.set_bundle(bundle, private_keys)
        self.load_bundle_from_userdb(userdb)

    def load_bundle_from_userdb(self, userdb):
        bundle = userdb.get_bundle()
        priv = userdb.get_private_keys_bundle()
        bndl, privd = hybrid_x3dh_kyber_bundle_from_wire(bundle, priv)
        self.pqxdh.load_bundle(bndl, privd)

    def export_bundle(self):
        bundle, kyber_pub = self.pqxdh.export_bundle()
        return hybrid_x3dh_kyber_peer_bundle_to_wire(bundle, kyber_pub)

    def import_peer_bundle(self, bundle):
        peer_bundle = hybrid_x3dh_kyber_peer_bundle_from_wire(bundle)
        self.pqxdh.import_peer_bundle(peer_bundle)

    def perform_key_exchange(self, sock, is_server: bool, chat_callback=None, debug_mode=False):
        def recv_msg():
            length_bytes = sock.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                raise Exception('Connection closed or invalid length header')
            length = int.from_bytes(length_bytes, byteorder='big')
            if length == 0:
                raise Exception('Received empty message')
            return sock.recv(length)
        def send_msg(data: bytes):
            length = len(data)
            sock.sendall(length.to_bytes(4, byteorder='big'))
            sock.sendall(data)
        import json
        my_bundle = self.export_bundle()
        if is_server:
            peer_bundle_json = recv_msg().decode('utf-8')
            send_msg(json.dumps(my_bundle).encode('utf-8'))
        else:
            send_msg(json.dumps(my_bundle).encode('utf-8'))
            peer_bundle_json = recv_msg().decode('utf-8')
        peer_bundle = json.loads(peer_bundle_json)
        self.import_peer_bundle(peer_bundle)
        def pqxdh_send(data):
            send_msg(data)
        def pqxdh_recv():
            return recv_msg()
        # Do NOT reset socket timeout after handshake
        result = self.pqxdh.perform_key_exchange(pqxdh_send, pqxdh_recv, is_server, chat_callback, debug_mode=debug_mode)
        self.session_key = self.pqxdh.session_key
        return result

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
