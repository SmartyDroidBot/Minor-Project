import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
from networking import ChatClient, ChatServer, ConnectionError

class ChatApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Python Chat App")
        self.geometry("600x500")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.connection = None
        self.is_server = None
        self.connected = False
        self.use_encryption = tk.BooleanVar(value=False)
        self.error_var = tk.StringVar(value="")
        self._build_startup_ui()

    def _build_startup_ui(self):
        for widget in self.winfo_children():
            widget.destroy()
        frame = ttk.Frame(self)
        frame.pack(expand=True)
        ttk.Label(frame, text="Start as:").grid(row=0, column=0, pady=10, sticky="e")
        self.mode_var = tk.StringVar(value="server")
        ttk.Radiobutton(frame, text="Server", variable=self.mode_var, value="server").grid(row=0, column=1)
        ttk.Radiobutton(frame, text="Client", variable=self.mode_var, value="client").grid(row=0, column=2)
        ttk.Label(frame, text="IP:").grid(row=1, column=0, sticky="e")
        self.ip_entry = ttk.Entry(frame)
        self.ip_entry.grid(row=1, column=1, columnspan=2, sticky="ew")
        self.ip_entry.insert(0, self._get_local_ip())
        ttk.Label(frame, text="Port:").grid(row=2, column=0, sticky="e")
        self.port_entry = ttk.Entry(frame)
        self.port_entry.grid(row=2, column=1, columnspan=2, sticky="ew")
        self.port_entry.insert(0, "12345")
        ttk.Checkbutton(frame, text="Enable Encryption (boilerplate)", variable=self.use_encryption).grid(row=3, column=0, columnspan=3, pady=10)
        ttk.Button(frame, text="Start", command=self._start_connection).grid(row=4, column=0, columnspan=3, pady=10)

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _start_connection(self):
        mode = self.mode_var.get()
        ip = self.ip_entry.get().strip()
        port = int(self.port_entry.get().strip())
        use_encryption = self.use_encryption.get()
        self.is_server = (mode == "server")
        self.error_var.set("")
        for widget in self.winfo_children():
            widget.destroy()
        if self.is_server:
            # Show waiting UI
            waiting_frame = ttk.Frame(self)
            waiting_frame.pack(expand=True, fill="both")
            self.waiting_label = ttk.Label(waiting_frame, text=f"Waiting for client to connect at {ip}:{port}", font=("Arial", 14))
            self.waiting_label.pack(pady=30)
            self.abort_btn = ttk.Button(waiting_frame, text="Abort", command=self._abort_server_wait)
            self.abort_btn.pack(pady=10)
            self.error_label = tk.Label(waiting_frame, textvariable=self.error_var, fg="red")
            self.error_label.pack(pady=5)
            self.connection = ChatServer(ip, port, use_encryption)
            def on_waiting_callback(host, port):
                self.waiting_label.config(text=f"Waiting for client to connect at {host}:{port}")
            def on_abort_callback():
                self.error_var.set("Server aborted waiting for connection.")
            def server_thread():
                try:
                    addr = self.connection.start(on_waiting_callback=on_waiting_callback, on_abort_callback=on_abort_callback)
                    if not self.connection._accept_abort:
                        self.connected = True
                        self._build_chat_ui(ip, port, addr)
                except Exception as e:
                    self.error_var.set(str(e))
            threading.Thread(target=server_thread, daemon=True).start()
        else:
            try:
                self.connection = ChatClient(ip, port, use_encryption)
                self.connection.connect()
                self.connected = True
                self._build_chat_ui(ip, port, (ip, port))
                if use_encryption:
                    self.connection.encryption_manager.perform_key_exchange(
                        self.connection.sock,
                        is_server=self.is_server,
                        chat_callback=self._append_chat
                    )
            except Exception as e:
                self.error_var.set(str(e))

    def _abort_server_wait(self):
        if self.connection:
            self.connection.abort_waiting()

    def _build_chat_ui(self, ip, port, addr):
        for widget in self.winfo_children():
            widget.destroy()
        self.title(f"Python Chat App - Connected to {addr[0]}:{addr[1]}")
        mainframe = ttk.Frame(self)
        mainframe.pack(fill="both", expand=True)
        self.chat_history = scrolledtext.ScrolledText(mainframe, state="disabled", wrap="word", height=20)
        self.chat_history.pack(fill="both", expand=True, padx=10, pady=(10,0))
        self.error_label = tk.Label(mainframe, textvariable=self.error_var, fg="red")
        self.error_label.pack(fill="x", padx=10, pady=(2,0))
        send_frame = ttk.Frame(mainframe)
        send_frame.pack(fill="x", padx=10, pady=10)
        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(send_frame, textvariable=self.msg_var)
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", lambda e: self._send_message())
        self.send_btn = ttk.Button(send_frame, text="Send", command=self._send_message)
        self.send_btn.pack(side="left", padx=(5,0))
        self.after(100, self._start_receiving)

    def _append_chat(self, msg):
        self.chat_history.configure(state="normal")
        self.chat_history.insert("end", msg + "\n")
        self.chat_history.see("end")
        self.chat_history.configure(state="disabled")

    def _send_message(self):
        msg = self.msg_var.get()
        if not msg:
            return
        try:
            self.connection.send(msg.encode('utf-8'))
            self._append_chat(f"[You]: {msg}")
            self.msg_var.set("")
            self.error_var.set("")
        except Exception as e:
            self.error_var.set(str(e))

    def _start_receiving(self):
        def receive_loop():
            while self.connected:
                try:
                    data = self.connection.receive()
                    if not data:
                        break
                    self._append_chat(f"[Peer]: {data.decode('utf-8', errors='replace')}")
                except Exception as e:
                    self.error_var.set(str(e))
                    break
        threading.Thread(target=receive_loop, daemon=True).start()

    def on_close(self):
        self.connected = False
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
        self.destroy()

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
