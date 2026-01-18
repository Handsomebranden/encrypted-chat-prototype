#!/usr/bin/env python3
"""
Encrypted Chat Client
Purpose: Connects to the server, receives the salt, and starts chatting.
"""
import socket
import base64
import getpass
import sys

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# --- CRYPTOGRAPHIC FUNCTIONS ---

def derive_key(password, salt):
    """Derives the key using the salt received from the server."""
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
    print("=== Encrypted Chat Client ===")
    print("Type 'quit' to exit.")

    password = getpass.getpass("Enter shared password: ")

    try:
        # Note: We use .connect() here, NOT .bind()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            print(f"[*] Connecting to {HOST}:{PORT}...")
            client.connect((HOST, PORT))
            
            # 1. Receive the salt from the server (first 16 bytes)
            salt = client.recv(16)
            if not salt:
                print("[!] Failed to receive salt.")
                return

            # 2. Derive the key using the server's salt
            key = derive_key(password, salt)
            fernet = Fernet(key)
            print("[+] Connection established and encrypted.")

            while True:
                # Send a message
                message = input("Client message: ")
                if not message:
                    continue
                
                # Encrypt and send
                encrypted_message = fernet.encrypt(message.encode())
                client.sendall(encrypted_message)

                if message.lower() in ['quit', 'exit']:
                    break

                # Receive and decrypt reply
                encrypted_reply = client.recv(4096)
                if not encrypted_reply:
                    print("\n[-] Server closed the connection.")
                    break

                try:
                    reply = fernet.decrypt(encrypted_reply).decode()
                    print(f"Server: {reply}")
                except InvalidToken:
                    print("[!] Decryption error: Wrong password or corrupted data.")
                    break

    except ConnectionRefusedError:
        print("[!] Error: Could not connect. Is the server running?")
    except KeyboardInterrupt:
        print("\n[!] Exiting...")
    except Exception as e:
        print(f"\n[!] Unexpected Error: {e}")
    finally:
        print("=== Client Closed ===")
        sys.exit()

if __name__ == "__main__":
    main()
