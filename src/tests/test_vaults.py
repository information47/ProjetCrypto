import unittest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.models.models import Base
from src.services.vaults import create_coffre

# Configuration de la base de données pour les tests
DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class TestCreateCoffre(unittest.TestCase):

    def setUp(self):
        """Cette méthode est appelée avant chaque test."""
        Base.metadata.create_all(bind=engine)
        self.db = TestingSessionLocal()

    def tearDown(self):
        """Cette méthode est appelée après chaque test."""
        self.db.close()
        Base.metadata.drop_all(bind=engine)

    @patch('src.services.vaults.os.urandom')
    @patch('src.services.vaults.PBKDF2')
    def test_create_coffre(self, mock_pbkdf2, mock_urandom):
        # Configuration des mocks
        mock_urandom.return_value = b'unique_salt'
        mock_pbkdf2.return_value = b'hashed_password'

        # Données de test
        user_id = 1
        nom_coffre = "Mon Coffre"
        password_coffre = "motDePasseCoffre"

        # Appel de la fonction à tester et injection de la session de test
        result = create_coffre(user_id, nom_coffre, password_coffre, db_session=self.db)

        # Assertions pour vérifier que PBKDF2 a été appelé avec les bons arguments
        mock_pbkdf2.assert_called_once_with(password_coffre, b'unique_salt', dkLen=32)

        # Vérifier les autres aspects du résultat si nécessaire
        self.assertEqual(result.nom_coffre, nom_coffre)
        self.assertEqual(result.password_coffre, b'hashed_password'.hex())  # Si vous stockez en hex
        self.assertEqual(result.id_user, user_id)
        self.assertEqual(result.salt, b'unique_salt'.hex())  # Si vous stockez en hex


if __name__ == "__main__":
    unittest.main()
