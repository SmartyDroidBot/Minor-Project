import os
import json
from datetime import datetime
from typing import Dict, Any

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
                json.dump({"identity_key": "", "users": {}}, f)
            return {"identity_key": "", "users": {}}
        with open(self.db_path, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return {"identity_key": "", "users": {}}

    def save(self):
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2)

    def add_user(self, peer_username: str):
        users = self.data.setdefault("users", {})
        if peer_username not in users:
            users[peer_username] = {
                "first_connected": str(datetime.now()),
                "signed_prekey": "", # Placeholder for signed prekey
                "prekey": "",         # Placeholder for one-time prekey
                "x3dh_bundle": {},     # Placeholder for X3DH public bundle (optional)
                "other": {}            # Placeholder for any other X3DH-related fields
            }
            self.save()

    def get_identity_key(self) -> str:
        return self.data.get("identity_key", "")

    def set_identity_key(self, key: str):
        self.data["identity_key"] = key
        self.save()

    def get_user(self, peer_username: str) -> dict:
        return self.data.get("users", {}).get(peer_username, {})

    def get_all_users(self) -> Dict[str, dict]:
        return self.data.get("users", {})
