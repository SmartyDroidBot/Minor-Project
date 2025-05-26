import os
import json
from datetime import datetime
from typing import Dict, Any
import base64

def get_username_db_path(my_username: str) -> str:
    return f"{my_username}_db.json"

class UserDB:
    def __init__(self, my_username: str):
        self.my_username = my_username
        self.db_path = get_username_db_path(my_username)
        self.data = self._load()

    def _load(self) -> Dict[str, Any]:
        if not os.path.exists(self.db_path):
            with open(self.db_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "identity_key": {},
                    "private_keys": {},
                    "peers": {}
                }, f)
            return {"identity_key": {}, "private_keys": {}, "peers": {}}
        with open(self.db_path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return {"identity_key": {}, "private_keys": {}, "peers": {}}

    def save(self):
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)

    def set_identity_key(self, x25519_pub: bytes, kyber_pub: bytes, dilithium_pub: bytes):
        self.data["identity_key"] = {
            "x25519": base64.b64encode(x25519_pub).decode(),
            "kyber1024": base64.b64encode(kyber_pub).decode(),
            "dilithium2": base64.b64encode(dilithium_pub).decode()
        }
        self.save()

    def set_private_keys(self, x25519_priv: bytes, kyber_priv: bytes, dilithium_priv: bytes):
        self.data["private_keys"] = {
            "x25519": base64.b64encode(x25519_priv).decode(),
            "kyber1024": base64.b64encode(kyber_priv).decode(),
            "dilithium2": base64.b64encode(dilithium_priv).decode()
        }
        self.save()

    def get_identity_key(self) -> Dict[str, str]:
        return self.data.get("identity_key", {})

    def get_private_keys(self) -> Dict[str, str]:
        return self.data.get("private_keys", {})

    def add_peer_bundle(self, peer_username: str, bundle: dict):
        peers = self.data.setdefault("peers", {})
        peers[peer_username] = {
            "bundle": bundle,
            "first_connected": str(datetime.now())
        }
        self.save()

    def get_peer_bundle(self, peer_username: str) -> dict:
        return self.data.get("peers", {}).get(peer_username, {}).get("bundle", {})

    def get_all_peers(self) -> Dict[str, dict]:
        return self.data.get("peers", {})

    def set_bundle(self, bundle: dict, private_keys: dict):
        # For compatibility with existing code, store as identity_key/private_keys
        self.set_identity_key(
            base64.b64decode(bundle["x25519_identity"]),
            base64.b64decode(bundle["kyber1024_identity"]),
            base64.b64decode(bundle["dilithium2"])
        )
        self.set_private_keys(
            private_keys["x25519"],
            private_keys["kyber1024"],
            private_keys["dilithium2"]
        )
        self.save()

    def get_bundle(self) -> dict:
        # For compatibility, reconstruct a bundle from identity_key
        idk = self.get_identity_key()
        if not idk:
            return {}
        return {
            "x25519_identity": idk.get("x25519", ""),
            "kyber1024_identity": idk.get("kyber1024", ""),
            "dilithium2": idk.get("dilithium2", "")
        }

    def get_private_keys_bundle(self) -> dict:
        d = self.get_private_keys()
        return {k: base64.b64decode(v) for k, v in d.items()}
