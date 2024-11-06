# ProjetCrypto

Gestionnaire de mots de passes

python3 -m venv venv
source venv/bin/activate

### Installer les dépendances

pip install -r requirements.txt

### BDD

Créer sa base mysql, puis à la racine du dossier créer un fichier .env qui aura la forme:

DB_HOST=
DB_USER=
DB_PASSWORD=
DB_NAME=
SECRET_KEY=
SECRET_KEY_flask=

ou SECRET_KEY est la clé secret pour le hashage et le chiffrement (poivre)
SECRET_KEY_flask est la clé secrète de l'application flask

puis lancer le main à la racine:

python3 main.py
