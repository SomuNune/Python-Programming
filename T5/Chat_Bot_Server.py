import socket
import threading
import sqlite3
from cryptography.fernet import Fernet

# Encryption setup
key = b'8sSplj8Jqk_7vQ8pVkzW4X6Tdg9n4f6QZQkQeN0sW0A='
cipher_suite = Fernet(key)

# Database setup
conn = sqlite3.connect('chat.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password TEXT)''')
conn.commit()

clients = {}

def handle_client(client_socket, addr):
    try:
        auth_mode = client_socket.recv(1024).decode().strip()
        username = client_socket.recv(1024).decode().strip()
        password = client_socket.recv(1024).decode().strip()

        if auth_mode == 'login':
            c.execute("SELECT password FROM users WHERE username=?", (username,))
            row = c.fetchone()
            if row and row[0] == password:
                client_socket.send("Login successful".encode())
            else:
                client_socket.send("Login failed".encode())
                client_socket.close()
                return
        elif auth_mode == 'register':
            try:
                c.execute("INSERT INTO users VALUES (?, ?)", (username, password))
                conn.commit()
                client_socket.send("Registration successful".encode())
            except sqlite3.IntegrityError:
                client_socket.send("Username exists".encode())
                client_socket.close()
                return

        clients[username] = client_socket
        while True:
            encrypted_msg = client_socket.recv(1024)
            if not encrypted_msg:
                break
            msg = cipher_suite.decrypt(encrypted_msg).decode()
            for user, sock in clients.items():
                if sock != client_socket:
                    encrypted = cipher_suite.encrypt(msg.encode())
                    sock.send(encrypted)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        clients.pop(username, None)
        client_socket.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 12346))
server.listen(5)
print("Advanced chat server running on port 12346...")

while True:
    client, addr = server.accept()
    threading.Thread(target=handle_client, args=(client, addr)).start()