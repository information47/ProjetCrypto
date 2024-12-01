from models.coffre import Coffre
from services.crypto_utils import encrypt_password, decrypt_password
import json


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
                    }
                )
            except Exception as e:
                print(f"Erreur lors du déchiffrement de l'entrée {entry.name} :", e)

        return decrypted_entries

    def export_coffre(self, file_path):
        try:
            exported_data = []

            for entry in self.coffre.password_entries:
                exported_data.append({
                    "login": entry.login,
                    "password": entry.password,  # Notez que c'est le mot de passe chiffré
                    "url": entry.url,
                    "name": entry.name,
                    "salt": entry.salt
                })

            with open(file_path, "w") as file:
                json.dump(exported_data, file, indent=4)

            return True

        except Exception as e:
            print(f"Erreur lors de l'exportation du coffre : {e}")
            return False

    def import_coffre(self, file_path):
        try:
            with open(file_path, "r") as file:
                entries = json.load(file)

            for entry in entries:
                self.coffre.password_entries.append(entry)

            return True

        except json.JSONDecodeError as jde:
            print(f"Erreur de format JSON lors de l'importation : {jde}")
            return False
        except Exception as e:
            print(f"Erreur lors de l'importation du coffre : {e}")
            return False