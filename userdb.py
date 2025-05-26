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
                    "identity_keys": {},
                    "private_keys": {},
                    "users": {}
                }, f)
            return {"identity_keys": {}, "private_keys": {}, "users": {}}
        with open(self.db_path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return {"identity_keys": {}, "private_keys": {}, "users": {}}

    def save(self):
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)

    def set_identity_keys(self, x25519_pub: bytes, kyber_pub: bytes, dilithium_pub: bytes):
        self.data["identity_keys"] = {
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

    def get_identity_keys(self) -> Dict[str, str]:
        return self.data.get("identity_keys", {})

    def get_private_keys(self) -> Dict[str, str]:
        return self.data.get("private_keys", {})

    def add_user_bundle(self, peer_username: str, bundle: dict):
        users = self.data.setdefault("users", {})
        users[peer_username] = {
            "bundle": bundle,
            "first_connected": str(datetime.now())
        }
        self.save()

    def get_user_bundle(self, peer_username: str) -> dict:
        return self.data.get("users", {}).get(peer_username, {}).get("bundle", {})

    def get_all_users(self) -> Dict[str, dict]:
        return self.data.get("users", {})

    def clear_prekeys(self, peer_username: str):
        # Optionally clear used prekeys for a peer
        user = self.data.get("users", {}).get(peer_username, {})
        if user and "bundle" in user:
            user["bundle"]["x25519_prekeys"] = []
            user["bundle"]["kyber1024_prekeys"] = []
            self.save()

    def set_bundle(self, bundle: dict, private_keys: dict):
        self.data["pqxdh_bundle"] = bundle
        self.data["pqxdh_private_keys"] = {k: base64.b64encode(v).decode() for k, v in private_keys.items()}
        self.save()

    def get_bundle(self) -> dict:
        return self.data.get("pqxdh_bundle", {})

    def get_private_keys_bundle(self) -> dict:
        d = self.data.get("pqxdh_private_keys", {})
        return {k: base64.b64decode(v) for k, v in d.items()}
