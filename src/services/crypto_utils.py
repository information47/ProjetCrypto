from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64

# Fonction de hachage pour le mot de passe utilisateur
def hash_password(password, salt):
    return PBKDF2(password, salt, dkLen=32, count=100000)

# Fonction pour chiffrer le mot de passe avec AES
def encrypt_password(password, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Fonction pour déchiffrer le mot de passe avec AES
def decrypt_password(encrypted_password, key):
    encrypted_data = base64.b64decode(encrypted_password)
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
