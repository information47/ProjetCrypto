# python
import unittest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from database.base import Base
from models.coffre import Coffre
from models.user import User
from models.password_entry import PasswordEntry
from services.vaults import VaultController

# Créer une base de données en mémoire pour les tests
engine = create_engine('sqlite:///:memory:')
Session = scoped_session(sessionmaker(bind=engine))
Base.metadata.create_all(engine)


class TestImportVault(unittest.TestCase):
    def setUp(self):
        self.session = Session()

        # Créer un utilisateur
        self.mock_user = User(email='import_test@example.com', password='import_password')
        self.session.add(self.mock_user)
        self.session.commit()

        # Créer un coffre
        self.mock_coffre = Coffre(
            nom_coffre='ImportCoffre',
            password_coffre='import_password',
            user=self.mock_user
        )
        self.session.add(self.mock_coffre)
        self.session.commit()

        self.vault_controller = VaultController(self.mock_coffre)

    @patch('services.vaults.open', new_callable=MagicMock)  # Simule l'ouverture de fichier
    @patch('services.vaults.json.load', return_value=[
        {'login': 'import_user', 'password': 'encrypted_import', 'url': 'http://import.com', 'name': 'ImportTest',
         'salt': 'abc'}
    ])  # Simule la lecture JSON
    def test_import_coffre(self, mock_json_load, mock_open):
        file_path = 'fake_path.json'
        # Tester l'importation réussie
        result = self.vault_controller.import_coffre(file_path)
        self.assertTrue(result)
        # Vérifier le contenu du coffre après importation
        self.assertEqual(len(self.mock_coffre.password_entries), 2)

    def tearDown(self):
        self.session.rollback()
        Session.remove()


if __name__ == '__main__':
    unittest.main()
