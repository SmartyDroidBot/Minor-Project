import base64
import oqs
import x3dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class PQXDHCore:
    """
    Pure PQXDH core: bundle generation, serialization helpers, and hybrid key exchange (X3DH + Kyber).
    No JSON, no I/O, no networking. All data is bytes or python objects.
    """
    class _State(x3dh.State):
        def _publish_bundle(self, bundle):
            pass
        def _encode_public_key(self, fmt, key):
            return key

    def __init__(self):
        self.session_key = None
        self.x3dh_state = None
        self.kyber_priv = None
        self.kyber_pub = None
        self.peer_bundle = None
        self.peer_kyber_pub = None

    @staticmethod
    def generate_bundle():
        identity_key_format = x3dh.types.IdentityKeyFormat.CURVE_25519
        hash_function = x3dh.crypto_provider.HashFunction.SHA_256
        info = b"pqxdh-app"
        state = PQXDHCore._State.create(identity_key_format, hash_function, info)
        bundle = state.bundle
        kyber = oqs.KeyEncapsulation('Kyber1024')
        kyber_pub = kyber.generate_keypair()
        kyber_priv = kyber.export_secret_key()
        state_json = state.json
        return {
            'x3dh_state': state_json,
            'x3dh_bundle': {
                'identity_key': bundle.identity_key,
                'signed_pre_key': bundle.signed_pre_key,
                'signed_pre_key_sig': bundle.signed_pre_key_sig,
                'pre_keys': list(bundle.pre_keys),
            },
            'kyber1024_identity': kyber_pub,
        }, {
            'x3dh_state': state_json,
            'kyber1024': kyber_priv,
        }

    def load_bundle(self, bundle, priv):
        state_json = priv['x3dh_state']
        identity_key_format = x3dh.types.IdentityKeyFormat.CURVE_25519
        hash_function = x3dh.crypto_provider.HashFunction.SHA_256
        info = b"pqxdh-app"
        self.x3dh_state, _ = PQXDHCore._State.from_json(state_json, identity_key_format, hash_function, info)
        self.kyber_priv = priv['kyber1024']
        self.kyber_pub = bundle['kyber1024_identity']

    def export_bundle(self):
        return self.x3dh_state.bundle, self.kyber_pub

    def import_peer_bundle(self, bundle):
        self.peer_bundle = bundle['x3dh_bundle']
        self.peer_kyber_pub = bundle['kyber1024_identity']

    def get_peer_x3dh_bundle(self):
        return self.peer_bundle

    def get_peer_kyber_pub(self):
        return self.peer_kyber_pub

    def perform_key_exchange(self, send_func, recv_func, is_server: bool, chat_callback=None, debug_mode=False):
        """
        send_func/recv_func: user-supplied callables for sending/receiving bytes objects.
        All serialization/deserialization is the caller's responsibility.
        """
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # Exchange bundles externally before calling this method!
        peer_bundle_obj = x3dh.types.Bundle(
            identity_key=self.peer_bundle['identity_key'],
            signed_pre_key=self.peer_bundle['signed_pre_key'],
            signed_pre_key_sig=self.peer_bundle['signed_pre_key_sig'],
            pre_keys=frozenset(self.peer_bundle['pre_keys'])
        )
        def trunc(b):
            if not isinstance(b, (bytes, bytearray)):
                return str(b)
            s = b.hex() if len(b) < 32 else b.hex()[:16] + '...'
            return s
        if is_server:
            header_bytes = recv_func()
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] Received header: {trunc(header_bytes)}")
            header = self.deserialize_header(header_bytes)
            header_obj = x3dh.types.Header(
                identity_key=header['identity_key'],
                ephemeral_key=header['ephemeral_key'],
                signed_pre_key=header['signed_pre_key'],
                pre_key=header['pre_key']
            )
            x3dh_secret, _, _ = loop.run_until_complete(self.x3dh_state.get_shared_secret_passive(header_obj))
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] X3DH shared secret: {trunc(x3dh_secret)}")
        else:
            x3dh_secret, _, header_obj = loop.run_until_complete(self.x3dh_state.get_shared_secret_active(peer_bundle_obj))
            header_bytes = self.serialize_header(header_obj)
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] Sending header: {trunc(header_bytes)}")
            send_func(header_bytes)
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] X3DH shared secret: {trunc(x3dh_secret)}")
        my_kyber = oqs.KeyEncapsulation('Kyber1024', secret_key=self.kyber_priv)
        if is_server:
            ct = recv_func()
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] Received Kyber ciphertext: {trunc(ct)}")
            kyber_secret = my_kyber.decap_secret(ct)
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] Kyber shared secret: {trunc(kyber_secret)}")
        else:
            ct, kyber_secret = my_kyber.encap_secret(self.peer_kyber_pub)
            if debug_mode and chat_callback:
                chat_callback(f"[Debug] Sending Kyber ciphertext: {trunc(ct)}")
                chat_callback(f"[Debug] Kyber shared secret: {trunc(kyber_secret)}")
            send_func(ct)
        concat_secret = x3dh_secret + kyber_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'pqxdh-session',
            backend=default_backend()
        )
        self.session_key = hkdf.derive(concat_secret)
        if debug_mode and chat_callback:
            chat_callback(f"[Debug] Session key: {trunc(self.session_key)}")
        if chat_callback:
            chat_callback(f"[Key Exchange] Session key: {self.session_key.hex()[:16]}... (truncated)")
            chat_callback('[Key Exchange] Secure channel established (PQXDH)')
        return True

    @staticmethod
    def serialize_header(header_obj):
        # Returns a tuple of bytes in a fixed order
        fields = [header_obj.identity_key, header_obj.ephemeral_key, header_obj.signed_pre_key, header_obj.pre_key]
        return b'||'.join([f if f is not None else b'' for f in fields])

    @staticmethod
    def deserialize_header(header_bytes):
        # Returns a dict with the header fields
        parts = header_bytes.split(b'||')
        return {
            'identity_key': parts[0],
            'ephemeral_key': parts[1],
            'signed_pre_key': parts[2],
            'pre_key': parts[3] if parts[3] else None
        }
