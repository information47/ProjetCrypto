import re
import hashlib
import requests
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import os


def mdp_fort(password):
    """
    Vérifie si un mot de passe est considéré comme fort.

    Un mot de passe est considéré comme fort s'il satisfait les conditions suivantes :
    - Au moins 8 caractères.
    - Contient au moins une lettre majuscule.
    - Contient au moins une lettre minuscule.
    - Contient au moins un chiffre.
    - Contient au moins un caractère spécial (!@#$%^&*(),.?":{}|<>).

    Args:
        password (str): Le mot de passe à vérifier.

    Returns:
        bool: True si le mot de passe est fort, False sinon.
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True


def check_password_leak(password):
    """
    Vérifie si un mot de passe a été compromis en utilisant l'API Pwned Passwords.

    Cette fonction utilise le hachage SHA-1 pour envoyer les 5 premiers caractères
    du hachage au service Pwned Passwords, qui retourne une liste de suffixes correspondant
    aux mots de passe compromis. La fonction compare ensuite les suffixes pour déterminer
    si le mot de passe a été compromis.On utilise l'api https://haveibeenpwned.com/API/v2

    Args:
        password (str): Le mot de passe à vérifier.

    Returns:
        bool: True si le mot de passe est compromis, False sinon.

    Raises:
        RuntimeError: Si une erreur se produit lors de l'appel à l'API Pwned Passwords.
    """
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(
            "Erreur lors de la vérification de la fuite du mot de passe."
        )
    hashes = (line.split(":") for line in response.text.splitlines())
    for hash_suffix, count in hashes:
        if hash_suffix == suffix:
            return True
    return False
