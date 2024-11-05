from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY").encode()  

def hash_password(password, salt):
   
    combined_password = password + SECRET_KEY.decode()
    return PBKDF2(combined_password, salt, dkLen=32, count=200000)

def generate_salt():
   
    return os.urandom(16)

def encrypt_password(password, key, salt=None):
    salt = salt if salt else generate_salt()
    combined_key = PBKDF2(key + SECRET_KEY, salt, dkLen=32, count=200000)
    cipher = AES.new(combined_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode("utf-8"))
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode("utf-8")

def decrypt_password(encrypted_password, key):
    encrypted_data = base64.b64decode(encrypted_password)
    salt = encrypted_data[:16]  
    nonce = encrypted_data[16:32]
    tag = encrypted_data[32:48]
    ciphertext = encrypted_data[48:]
    combined_key = PBKDF2(key + SECRET_KEY, salt, dkLen=32, count=200000)
    cipher = AES.new(combined_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
