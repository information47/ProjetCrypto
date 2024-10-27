from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from config.config import Config
from services.crypto_utils import hash_password, encrypt_password, decrypt_password
import os

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# Route pour tester le hachage d'un mot de passe
@app.route('/test_hash', methods=['POST'])
def test_hash():
    data = request.get_json()
    password = data.get('password')
    
    # Générer un sel aléatoire pour le hachage
    salt = os.urandom(16)
    hashed_password = hash_password(password, salt)

    return jsonify({
        "password": password,
        "salt": salt.hex(),
        "hashed_password": hashed_password.hex()
    })

# Route pour tester le chiffrement et le déchiffrement
@app.route('/test_encrypt_decrypt', methods=['POST'])
def test_encrypt_decrypt():
    data = request.get_json()
    password = data.get('password')
    
    # Générer une clé aléatoire pour AES
    key = os.urandom(32)  # Clé AES de 256 bits
    encrypted_password = encrypt_password(password, key)
    decrypted_password = decrypt_password(encrypted_password, key)

    return jsonify({
        "original_password": password,
        "encrypted_password": encrypted_password,
        "decrypted_password": decrypted_password
    })

if __name__ == '__main__':
    app.run(debug=True)
