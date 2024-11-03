import unittest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.models.models import Base, Coffre, PasswordEntry
from src.services.vaults import create_coffre
from src.services.passwordEntry import add_password_entry

# Configuration de la base de données pour les tests
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class TestPasswordEntry(unittest.TestCase):

    def setUp(self):
        """Cette méthode est appelée avant chaque test."""
        # Créez toutes les tables définies dans les modèles
        Base.metadata.create_all(bind=engine)
        self.db = TestingSessionLocal()

        # Créer un utilisateur et un coffre pour le test
        self.user_id = 1
        self.nom_coffre = "Mon Coffre"
        self.password_coffre = "motDePasseCoffre"
        with patch('src.services.vaults.PBKDF2', return_value=b'hashed_password'):
            self.coffre = create_coffre(self.user_id, self.nom_coffre, self.password_coffre, db_session=self.db)

    def tearDown(self):
        """Cette méthode est appelée après chaque test."""
        self.db.close()
        Base.metadata.drop_all(bind=engine)

    @patch('src.services.passwordEntry.PBKDF2')
    @patch('src.services.passwordEntry.AES')
    def test_add_password_entry(self, mock_aes, mock_pbkdf2):
        # Configuration des mocks
        mock_pbkdf2.return_value = b'key_for_aes'
        mock_cipher = mock_aes.new.return_value
        mock_cipher.encrypt_and_digest.return_value = (b'ciphertext', b'tag')
        mock_cipher.nonce = b'nonce'

        # Données de test
        login = "test_login"
        password = "test_password"
        url = "http://test.url"
        name = "Test Name"

        # Appel de la méthode à tester
        new_entry = add_password_entry(self.coffre, login, password, url, name, db_session=self.db)

        # Mettre à jour l'appel attendu à PBKDF2 pour correspondre à la valeur réelle en bytes
        expected_hashed_password = b'hashed_password'  # Hexadécimal obtenu lors de la création

        # Assertions
        mock_pbkdf2.assert_called_once_with(expected_hashed_password, b'unique_salt_for_aes', dkLen=32)
        mock_aes.new.assert_called_once_with(b'key_for_aes', mock_aes.MODE_EAX)
        mock_cipher.encrypt_and_digest.assert_called_once_with(password.encode())
        self.assertEqual(new_entry.login, login)
        self.assertEqual(new_entry.password, b'ciphertext')
        self.assertEqual(new_entry.url, url)
        self.assertEqual(new_entry.name, name)
        self.assertEqual(new_entry.id_coffre, self.coffre.id)


if __name__ == "__main__":
    unittest.main()
