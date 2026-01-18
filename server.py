#!/usr/bin/env python3
import socket
import os
import base64
import getpass
import sys

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# --- CRYPTOGRAPHIC FUNCTIONS ---

def generate_salt():
    return os.urandom(16)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- CONFIGURATION ---
HOST = "127.0.0.1"
PORT = 65432

def main():
    print("=== Encrypted Chat Server ===")
    print("Type 'quit' or press Ctrl+C to exit.")

    password = getpass.getpass("Enter shared password: ")
    salt = generate_salt()
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            # Allow immediate reuse of the port after restart
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen(1)
            print(f"[*] Listening on {HOST}:{PORT}...")
            
            conn, addr = server.accept()
            with conn:
                print(f"[+] Connected by {addr}")
                conn.sendall(salt)

                while True:
                    # Receive data
                    encrypted_data = conn.recv(4096)
                    if not encrypted_data:
                        print("\n[-] Client disconnected.")
                        break

                    try:
                        message = fernet.decrypt(encrypted_data).decode()
                        if message.lower() in ['quit', 'exit']:
                            print("[!] Client requested to close connection.")
                            break
                        print(f"Client: {message}")
                    except InvalidToken:
                        print("[!] Decryption failed! Check if passwords match.")
                        break

                    # Send reply
                    reply = input("Server reply: ")
                    if reply.lower() in ['quit', 'exit']:
                        conn.sendall(fernet.encrypt(b"Server is closing..."))
                        break
                        
                    conn.sendall(fernet.encrypt(reply.encode()))

    except KeyboardInterrupt:
        print("\n[!] Server shutting down (Keyboard Interrupt).")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        print("=== Server Closed ===")
        sys.exit()

if __name__ == "__main__":
    main()
