from models.coffre import Coffre
from models.password_entry import PasswordEntry
from tkinter import Tk, filedialog
from services.crypto_utils import encrypt_password, decrypt_password
from database.base import session
import json
import os


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

        Les données exportées incluent les informations sur les entrées de mot de passe.

        Returns:
            str: Le chemin du fichier exporté.
            None: En cas d'échec d'exportation.
        """
        try:
            downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
            file_path = os.path.join(
                downloads_folder, f"exported_vault_{self.coffre.Id_coffre}.json"
            )
            exported_data = []
            for entry in self.coffre.password_entries:
                exported_data.append(
                    {
                        "login": entry.login,
                        "password": entry.password,
                        "url": entry.url,
                        "name": entry.name,
                        "salt": entry.salt,
                    }
                )

            with open(file_path, "w") as file:
                json.dump(exported_data, file, indent=4)
            return file_path

        except Exception as e:
            print(f"Erreur lors de l'exportation du coffre : {e}")
            return None

    def import_vault(self, user, file_path):
        """
        Importe un coffre à partir d'un fichier JSON donné pour un utilisateur spécifique
        et persiste dans la base de données.

        Args:
            user: Instance de l'utilisateur associé au coffre.
            file_path: Chemin du fichier JSON à importer.

        Returns:
            bool: True si l'importation est réussie, False sinon.
        """
        try:
            # Vérification si le fichier existe
            if not os.path.exists(file_path):
                print("Le fichier spécifié n'existe pas.")
                return False

            # Lecture du fichier JSON
            with open(file_path, "r", encoding="utf-8") as file:
                json_data = json.load(file)

            # Validation de la structure JSON
            required_fields = ["nom", "password_coffre", "password_entries"]
            if not all(field in json_data for field in required_fields):
                print("Certains champs requis sont manquants dans le fichier JSON.")
                return False

            # Étape 3 : Créer une instance de Coffre avec les données JSON
            try:
                new_coffre = Coffre(
                    nom_coffre=json_data["nom"],
                    password_coffre=json_data["password_coffre"],
                    user=user,  # Associe l'utilisateur au coffre
                )

                # Ajouter les entrées de mots de passe (password_entries)
                for entry in json_data["password_entries"]:
                    if all(key in entry for key in ["login", "password", "url", "name"]):
                        password_entry = PasswordEntry(
                            login=entry["login"],
                            password=entry["password"],
                            url=entry["url"],
                            name=entry["name"],
                            coffre=new_coffre,  # Associe l'entrée au coffre
                        )
                        new_coffre.password_entries.append(password_entry)
                    else:
                        print(f"Entrée incomplète trouvée : {entry}. Ignorée.")

                # Ajouter le coffre à l'utilisateur
                user.coffres.append(new_coffre)

                # Étape 4 : Ajouter le coffre à la base de données
                session.add(user)

                try:
                    session.commit()
                    print("Coffre importé et ajouté avec succès.")
                    return True
                except Exception as db_error:
                    session.rollback()
                    print(f"Erreur lors de l'ajout du coffre dans la base de données : {db_error}")
                    return False

            except Exception as e:
                print(f"Erreur lors de la création du coffre : {e}")
                return False

        except json.JSONDecodeError:
            print("Le fichier fourni n'est pas un fichier JSON valide.")
            return False
        except Exception as e:
            # Gérer toute autre exception inattendue
            print(f"Erreur inconnue lors de l'importation : {e}")
            return False
