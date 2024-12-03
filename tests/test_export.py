# python
import unittest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from database.base import Base
from models.coffre import Coffre
from models.user import User
from services.vaults import VaultController

# Créer une base de données en mémoire pour les tests
engine = create_engine('sqlite:///:memory:')
Session = scoped_session(sessionmaker(bind=engine))
Base.metadata.create_all(engine)


class TestExportVault(unittest.TestCase):
    def setUp(self):
        # Crée une session pour la base de données en mémoire
        self.session = Session()

        # Crée et ajoute un utilisateur réel à la session
        self.mock_user = User(email='test@example.com', password='test_password')
        self.session.add(self.mock_user)
        self.session.commit()

        # Créer un coffre réel en utilisant l'utilisateur de la session
        self.mock_coffre = Coffre(
            nom_coffre='TestCoffre',
            password_coffre='test_password',
            user=self.mock_user
        )
        self.session.add(self.mock_coffre)
        self.session.commit()

        # Créer l'instance de VaultController
        self.vault_controller = VaultController(self.mock_coffre)

    @patch('builtins.open', new_callable=MagicMock)  # Simule l'ouverture de fichier
    @patch('json.dump')  # Simule l'écriture JSON
    def test_export_coffre(self, mock_json_dump, mock_open):
        file_path = 'fake_path.json'
        # Tester l'exportation réussie
        result = self.vault_controller.export_coffre(file_path)
        self.assertTrue(result)
        # Vérifier que les fonctions mockées ont été appelées
        mock_open.assert_called_with(file_path, 'w')
        mock_json_dump.assert_called()

    def tearDown(self):
        self.session.close()
        Base.metadata.drop_all(engine)


if __name__ == '__main__':
    unittest.main()
