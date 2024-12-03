import secrets

# Générer une clé pour SECRET_KEY
secret_key = secrets.token_hex(32)  # 64 caractères hexadécimaux

# Générer une clé pour SECRET_KEY_flask
flask_secret_key = secrets.token_urlsafe(32)  # Encodage sûr pour les URLs

print("SECRET_KEY =", secret_key)
print("SECRET_KEY_flask =", flask_secret_key)
