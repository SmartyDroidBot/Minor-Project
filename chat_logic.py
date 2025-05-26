import threading
import os
import json
from userdb import UserDB

# Username exchange and connection alert logic

def exchange_usernames(connection, my_username, is_server):
    """
    Exchange usernames between peers after connection is established.
    Returns the peer's username, and sends/receives in correct order for server/client.
    """
    if is_server:
        # Server receives first, then sends
        peer_username = connection.receive().decode('utf-8', errors='replace')
        connection.send(my_username.encode('utf-8'))
    else:
        # Client sends first, then receives
        connection.send(my_username.encode('utf-8'))
        peer_username = connection.receive().decode('utf-8', errors='replace')
    # Optionally, you could store peer bundles here using userdb.add_peer_bundle(peer_username, bundle)
    return peer_username

# Encrypted handshake logic (currently just alert and title update)
def handle_encrypted_handshake(app, is_server):
    app._append_chat(f"Alert : Connection established with {app.peer_username}")
    app.title(f"Python Chat App - Connected to {app.peer_username}")

# Chat message receiving logic
def start_receiving(app):
    def receive_loop():
        while app.connected:
            try:
                data = app.connection.receive()
                if not data:
                    break
                # Use API to decrypt if needed
                if hasattr(app, 'api') and hasattr(app.api, 'decrypt'):
                    try:
                        data = app.api.decrypt(data)
                    except Exception as e:
                        app.error_var.set(f"Decryption error: {e}")
                        break
                # Use peer's username in chat
                app._append_chat(f"[{app.peer_username}]: {data.decode('utf-8', errors='replace')}")
            except Exception as e:
                app.error_var.set(str(e))
                break
    threading.Thread(target=receive_loop, daemon=True).start()