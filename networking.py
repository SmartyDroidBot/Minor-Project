import socket
import threading
from encryption import EncryptionManager

class ConnectionError(Exception):
    pass

class ChatClient:
    def __init__(self, host, port, use_encryption=False):
        self.host = host
        self.port = port
        self.use_encryption = use_encryption
        self.sock = None
        self.running = False
        self.encryption_manager = EncryptionManager() if use_encryption else None

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.running = True
        except Exception as e:
            raise ConnectionError(str(e))

    def send(self, data: bytes):
        if self.use_encryption and self.encryption_manager:
            data = self.encryption_manager.encrypt(data)
        length = len(data)
        self.sock.sendall(length.to_bytes(4, byteorder='big'))
        self.sock.sendall(data)

    def receive(self):
        length_bytes = self.sock.recv(4)
        if not length_bytes:
            raise ConnectionError("No data received for length header.")
        length = int.from_bytes(length_bytes, byteorder='big')
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(min(length - len(data), 4096))
            if not chunk:
                raise ConnectionError("Connection broken while receiving data")
            data += chunk
        if self.use_encryption and self.encryption_manager:
            data = self.encryption_manager.decrypt(data)
        return data

    def close(self):
        self.running = False
        if self.sock:
            self.sock.close()

class ChatServer:
    def __init__(self, host, port, use_encryption=False):
        self.host = host
        self.port = port
        self.use_encryption = use_encryption
        self.sock = None
        self.client_sock = None
        self.running = False
        self.encryption_manager = EncryptionManager() if use_encryption else None

    def start(self, on_waiting_callback=None, on_abort_callback=None):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        # Show info dialog with IP/port for client to connect to
        if on_waiting_callback:
            on_waiting_callback(self.host, self.port)
        import threading
        self._accept_event = threading.Event()
        self._accept_result = None
        self._accept_abort = False
        def accept_thread():
            try:
                while not self._accept_abort:
                    self.sock.settimeout(0.5)
                    try:
                        self.client_sock, addr = self.sock.accept()
                        self.running = True
                        self._accept_result = addr
                        break
                    except socket.timeout:
                        continue
            except Exception as exc:
                self._accept_result = exc
            finally:
                self._accept_event.set()
        t = threading.Thread(target=accept_thread, daemon=True)
        t.start()
        self._accept_event.wait()
        if self._accept_abort:
            if on_abort_callback:
                on_abort_callback()
            raise ConnectionError("Server aborted waiting for connection.")
        if isinstance(self._accept_result, Exception):
            raise ConnectionError(str(self._accept_result))
        return self._accept_result

    def abort_waiting(self):
        self._accept_abort = True

    def send(self, data: bytes):
        if self.use_encryption and self.encryption_manager:
            data = self.encryption_manager.encrypt(data)
        length = len(data)
        self.client_sock.sendall(length.to_bytes(4, byteorder='big'))
        self.client_sock.sendall(data)

    def receive(self):
        length_bytes = self.client_sock.recv(4)
        if not length_bytes:
            raise ConnectionError("No data received for length header.")
        length = int.from_bytes(length_bytes, byteorder='big')
        data = b''
        while len(data) < length:
            chunk = self.client_sock.recv(min(length - len(data), 4096))
            if not chunk:
                raise ConnectionError("Connection broken while receiving data")
            data += chunk
        if self.use_encryption and self.encryption_manager:
            data = self.encryption_manager.decrypt(data)
        return data

    def close(self):
        self.running = False
        if self.client_sock:
            self.client_sock.close()
        if self.sock:
            self.sock.close()
