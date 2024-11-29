from models.coffre import Coffre
from services.crypto_utils import encrypt_password, decrypt_password
import os


class VaultController:
    def __init__(self, coffre: Coffre):
        self.coffre = coffre

    def add_password_entry(self, password_entry):
        self.coffre.password_entries.append(password_entry)

    def verify_password_coffre(self, password_coffre):
        return self.coffre.verify_password(password_coffre)

    def unlock_coffre(self, password_coffre):
        if not self.verify_password_coffre(password_coffre):
            raise ValueError("Mot de passe du coffre incorrect")

        decrypted_entries = []

        for entry in self.coffre.password_entries:
            try:
                entry_key = bytes.fromhex(entry.salt)
                decrypted_password = decrypt_password(entry.password, entry_key)
                decrypted_entries.append(
                    {
                        "login": entry.login,
                        "password": decrypted_password,
                        "url": entry.url,
                        "name": entry.name,
                        "Id_PasswordEntry": entry.Id_PasswordEntry,
                    }
                )
            except Exception as e:
                print(f"Erreur lors du déchiffrement de l'entrée {entry.name} :", e)

        return decrypted_entries
