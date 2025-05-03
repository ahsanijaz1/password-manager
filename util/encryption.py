from cryptography.fernet import Fernet
import hashlib
import base64

def generate_key(master_password):
    password_clean = master_password.strip()  # <-- this removes spaces and newlines
    digest = hashlib.sha256(password_clean.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_password(password, master_password):
    key = generate_key(master_password)
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted

def decrypt_password(encrypted_password, master_password):
    key = generate_key(master_password)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password).decode()
    return decrypted
