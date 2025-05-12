from cryptography.fernet import Fernet
import config

cipher = Fernet(config.FERNET_KEY.encode())

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data.encode()).decode()
