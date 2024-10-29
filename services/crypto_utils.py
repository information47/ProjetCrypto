from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64


def hash_password(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)


def encrypt_password(password, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode("utf-8"))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode("utf-8")


def decrypt_password(encrypted_password, key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")
