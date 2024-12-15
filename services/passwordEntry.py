from services.crypto_utils import decrypt_password
from models.password_entry import PasswordEntry


class PasswordEntryController:
    """
    Contrôleur pour la gestion des objets `PasswordEntry`.

    Cette classe fournit des méthodes pour interagir avec une instance de
    `PasswordEntry`, notamment pour vérifier si un mot de passe déchiffré
    correspond au mot de passe fourni.
    """

    def __init__(self, password_entry: PasswordEntry):
        self.password_entry = password_entry

    def verify_password(self, password):
        """
        Vérifie si un mot de passe fourni correspond au mot de passe chiffré
        stocké dans l'objet `PasswordEntry`.

        Cette méthode utilise le sel (`salt`) stocké dans `PasswordEntry`
        pour déchiffrer le mot de passe chiffré. Une fois déchiffré, le mot
        de passe est comparé à celui fourni.

        Args:
            password (str): Le mot de passe en clair à vérifier.

        Returns:
            bool: True si le mot de passe fourni correspond au mot de passe
            déchiffré, False sinon.
        """
        key = bytes.fromhex(self.password_entry.salt)
        decrypted_password = decrypt_password(self.password_entry.password, key)
        return decrypted_password == password
