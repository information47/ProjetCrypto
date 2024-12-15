import json
import os
from database.base import session
from models.coffre import Coffre
from models.password_entry import PasswordEntry
from services.crypto_utils import decrypt_password, get_secret_key


class VaultController:
    """
    Contrôleur pour gérer les opérations sur un coffre-fort (Coffre) et ses entrées.

    Cette classe fournit des méthodes pour ajouter, supprimer, vérifier, déverrouiller,
    exporter et importer les données d'un coffre-fort.
    """

    def __init__(self, coffre: Coffre):
        self.coffre = coffre

    def add_password_entry(self, password_entry):
        """
        Ajoute une nouvelle entrée de mot de passe au coffre.

        Args:
            password_entry (PasswordEntry): L'entrée de mot de passe à ajouter.
        """
        self.coffre.password_entries.append(password_entry)

    def Delete_password_entry(self, password_entry):
        """
        Supprime une entrée de mot de passe du coffre.

        Args:
            password_entry (PasswordEntry): L'entrée de mot de passe à supprimer.
        """
        self.coffre.password_entries.remove(password_entry)

    def verify_password_coffre(self, password_coffre):
        """
        Vérifie si le mot de passe fourni correspond au mot de passe du coffre.

        Args:
            password_coffre (str): Le mot de passe à vérifier.

        Returns:
            bool: True si le mot de passe est correct, False sinon.
        """
        return self.coffre.verify_password(password_coffre)

    def unlock_coffre(self, password_coffre):
        """
        Déverrouille le coffre en vérifiant le mot de passe et retourne les entrées déchiffrées.

        Args:
            password_coffre (str): Le mot de passe du coffre.

        Returns:
            list[dict]: Une liste d'entrées déchiffrées contenant les informations
            (login, password, url, name, Id_PasswordEntry).

        Raises:
            ValueError: Si le mot de passe du coffre est incorrect.
        """
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

    def export_coffre(self):
        """
        Exporte les données du coffre dans un fichier JSON.

        Les données exportées incluent les informations sur les entrées de mot de passe,
        sous un format prêt à être importé.

        Returns:
            str: Le chemin du fichier exporté.
            None: En cas d'échec d'exportation.
        """
        try:
            downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
            file_path = os.path.join(
                downloads_folder, f"exported_vault_{self.coffre.Id_coffre}.json"
            )

            decrypted_entries = []

            exported_data = {
                "password_entries": decrypted_entries
            }

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



            with open(file_path, "w", encoding="utf-8") as file:
                json.dump(exported_data, file, indent=4)
            return file_path

        except Exception as e:
            print(f"Erreur lors de l'exportation du coffre : {e}")
            return None