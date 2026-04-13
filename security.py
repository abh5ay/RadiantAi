import base64
from cryptography.fernet import Fernet
import os

# Persistent Key logic
KEY_FILE = "secret.key"

def load_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print("🔐 Security: New system encryption key generated.")
        return key

cipher = Fernet(load_key())

def encrypt_data(data):
    if not data: return ""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(token):
    if not token: return ""
    try:
        return cipher.decrypt(token.encode()).decode()
    except:
        return "[ENCRYPTION_ERROR]"
