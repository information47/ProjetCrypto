from services.crypto_utils import decrypt_password
from models.password_entry import PasswordEntry

class PasswordEntryController:
    def __init__(self, password_entry: PasswordEntry):
        self.password_entry = password_entry

    def verify_password(self, password):
        key = bytes.fromhex(self.password_entry.salt)
        decrypted_password = decrypt_password(self.password_entry.password, key)
        return decrypted_password == password
