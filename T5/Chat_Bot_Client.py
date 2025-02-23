import tkinter as tk
from tkinter import messagebox
import socket
import threading
from cryptography.fernet import Fernet

# Encryption setup
key = b'8sSplj8Jqk_7vQ8pVkzW4X6Tdg9n4f6QZQkQeN0sW0A='
cipher_suite = Fernet(key)

class LoginWindow:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Chat Login")
        
        tk.Label(self.window, text="Username:").pack(pady=5)
        self.username = tk.Entry(self.window)
        self.username.pack(pady=5)
        
        tk.Label(self.window, text="Password:").pack(pady=5)
        self.password = tk.Entry(self.window, show="*")
        self.password.pack(pady=5)
        
        self.auth_type = tk.StringVar(value="login")
        tk.Radiobutton(self.window, text="Login", variable=self.auth_type, value="login").pack()
        tk.Radiobutton(self.window, text="Register", variable=self.auth_type, value="register").pack()
        
        tk.Button(self.window, text="Connect", command=self.connect).pack(pady=10)
    
    def connect(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 12346))
            auth_mode = self.auth_type.get()
            self.client_socket.send(auth_mode.encode())
            self.client_socket.send(self.username.get().encode())
            self.client_socket.send(self.password.get().encode())
            response = self.client_socket.recv(1024).decode()
            if "success" in response:
                self.window.destroy()
                ChatWindow(self.client_socket, self.username.get())
            else:
                messagebox.showerror("Error", response)
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {e}")

    def run(self):
        self.window.mainloop()

class ChatWindow:
    def __init__(self, sock, username):
        self.sock = sock
        self.username = username
        self.window = tk.Tk()
        self.window.title(f"Secure Chat - {username}")
        
        self.chat_log = tk.Text(self.window, width=50, height=20)
        self.chat_log.pack(padx=10, pady=10)
        
        self.msg_entry = tk.Entry(self.window, width=40)
        self.msg_entry.pack(side=tk.LEFT, padx=5, pady=5)
        
        tk.Button(self.window, text="Send", command=self.send_message).pack(side=tk.RIGHT, padx=5)
        
        self.msg_entry.bind("<Return>", lambda event: self.send_message())
        
        threading.Thread(target=self.receive_messages, daemon=True).start()
    
    def send_message(self):
        message = self.msg_entry.get()
        if message:
            encrypted = cipher_suite.encrypt(message.encode())
            self.sock.send(encrypted)
            self.msg_entry.delete(0, tk.END)
    
    def receive_messages(self):
        while True:
            try:
                encrypted_msg = self.sock.recv(1024)
                msg = cipher_suite.decrypt(encrypted_msg).decode()
                self.chat_log.insert(tk.END, f"{msg}\n")
                self.chat_log.see(tk.END)
            except:
                break

if __name__ == "__main__":
    login_app = LoginWindow()
    login_app.run()