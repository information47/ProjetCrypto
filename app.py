import json

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    redirect,
    url_for,
    flash,
    session as flask_session,
    send_from_directory,
    make_response, session,
)
from database import session as db_session
from werkzeug.utils import secure_filename
from models.user import User
from models.coffre import Coffre
from models.password_entry import PasswordEntry
from services.vaults import VaultController
import os
from database.base import session as db_session
import secrets
from dotenv import load_dotenv
from datetime import timedelta
from services.pass_fonc import *
from functools import wraps


load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY_flask")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)

# Configuration pour le répertoire d'import
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"json"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Fonction utilitaire pour vérifier l'extension du fichier
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    """
    Redirige l'utilisateur vers la page de connexion.
    Returns:
        Response: Une redirection vers la route "/login".
    """
    return redirect(url_for("login"))


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        os.path.join(app.root_path, "static", "img"),
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    Gère l'enregistrement des nouveaux utilisateurs.
    - En cas de méthode GET, affiche la page d'enregistrement.
    - En cas de méthode POST, enregistre un utilisateur avec email et mot de passe.

    Returns:
        Response: Une page HTML ou une redirection vers la route "/register".
    """
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        if not mdp_fort(password):
            flash(
                "Le mot de passe doit comporter au moins 8 caractères, inclure une majuscule, une minuscule, un chiffre et un caractère spécial.",
                "error",
            )
            return redirect(url_for("register"))
        if check_password_leak(password):
            flash(
                "Le mot de passe est compromis, veuillez en choisir un autre.", "error"
            )
            return redirect(url_for("register"))

        existing_user = db_session.query(User).filter_by(email=email).first()
        if existing_user:
            flash("Un utilisateur avec cet email existe déjà.", "error")
            return redirect(url_for("register"))
        user = User(email=email, password=password)
        db_session.add(user)
        try:
            db_session.commit()
            flash("Utilisateur enregistré avec succès", "success")
            return redirect(url_for("register"))
        except Exception as e:
            db_session.rollback()
            flash(f"Erreur lors de l'enregistrement de l'utilisateur : {e}", "error")
            return redirect(url_for("register"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Gère la connexion des utilisateurs.
    - En cas de méthode GET, affiche la page de connexion.
    - En cas de méthode POST, vérifie les identifiants de l'utilisateur et crée une session.

    Returns:
        Response: Une redirection vers "/dashboard" ou "/login", ou la page de connexion.
    """
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = db_session.query(User).filter_by(email=email).first()

        if user and user.verify_password(password):
            session_token = secrets.token_hex(16)
            flask_session["user_id"] = str(user.Id_user)
            flask_session["session_token"] = session_token
            flask_session.permanent = True

            return redirect(url_for("dashboard"))
        else:
            flash("Adresse email ou mot de passe incorrect.", "error")
            return redirect(url_for("login"))

    flask_session.pop("user_id", None)
    flask_session.pop("session_token", None)

    return render_template("login.html")


@app.before_request
def make_session_permanent():
    flask_session.permanent = True


@app.route("/dashboard")
def dashboard():
    """
    Affiche le tableau de bord de l'utilisateur, avec les coffres associés.

    Returns:
        Response: Une page HTML contenant les coffres de l'utilisateur connecté.
    """
    if "user_id" not in flask_session or "session_token" not in flask_session:
        flash("Veuillez vous connecter pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))

    user_id = int(flask_session["user_id"])
    user = db_session.query(User).filter_by(Id_user=user_id).first()

    if not user:
        flash("Utilisateur non trouvé.", "error")
        return redirect(url_for("login"))

    coffres = user.coffres.all()

    return render_template("dashboard.html", user=user, coffres=coffres)


@app.route("/create-coffre", methods=["GET", "POST"])
def create_coffre():
    """
    Permet à un utilisateur connecté de créer un nouveau coffre.
    - En cas de méthode GET, affiche la page de création.
    - En cas de méthode POST, valide et enregistre les données du coffre.

    Returns:
        Response: Une redirection ou une page HTML.
    """
    if "user_id" not in flask_session:
        flash("Veuillez vous connecter pour créer un coffre.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        nom = request.form["nom"]
        password_coffre = request.form["password_coffre"]

        if not password_coffre:
            flash("Le mot de passe du coffre est obligatoire.", "error")
            return redirect(url_for("create_coffre"))

        if not mdp_fort(password_coffre):
            flash(
                "Le mot de passe du coffre doit comporter au moins 8 caractères, inclure une majuscule, une minuscule, un chiffre et un caractère spécial.",
                "error",
            )
            return redirect(url_for("create_coffre"))

        if check_password_leak(password_coffre):
            flash(
                "Le mot de passe du coffre est compromis, veuillez en choisir un autre.",
                "error",
            )
            return redirect(url_for("create_coffre"))

        user = (
            db_session.query(User)
            .filter_by(Id_user=int(flask_session["user_id"]))
            .first()
        )
        if not user:
            flash("Utilisateur non trouvé.", "error")
            return redirect(url_for("dashboard"))

        coffre = Coffre(nom_coffre=nom, password_coffre=password_coffre, user=user)
        db_session.add(coffre)

        try:
            db_session.commit()
            flash("Coffre créé avec succès.", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            db_session.rollback()
            flash(f"Erreur lors de la création du coffre : {str(e)}", "error")

    return render_template("create_coffre.html")


@app.route("/unlock-coffre/<int:coffre_id>", methods=["GET", "POST"])
def unlock_coffre(coffre_id):
    """
    Permet de déverrouiller un coffre avec un mot de passe.
    - En cas de méthode GET, affiche la page pour entrer le mot de passe.
    - En cas de méthode POST, tente de déverrouiller le coffre.

    Args:
        coffre_id (int): L'ID du coffre à déverrouiller.

    Returns:
        Response: Une page HTML ou une redirection.
    """
    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()

    if "user_id" not in flask_session or "session_token" not in flask_session:
        flash("Veuillez vous connecter pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))

    if not coffre:
        flash("Coffre non trouvé.", "error")
        return redirect(url_for("dashboard"))

    vault_manager = VaultController(coffre)

    if request.method == "POST":
        password_coffre = request.form["password_coffre"]

        try:
            decrypted_entries = vault_manager.unlock_coffre(password_coffre)
            return render_template(
                "view_entries.html", coffre=coffre, entries=decrypted_entries
            )
        except ValueError:
            flash("Mot de passe incorrect.", "error")
            return redirect(url_for("unlock_coffre", coffre_id=coffre_id))

    return render_template("unlock_coffre.html", coffre=coffre)


@app.route("/add-password-entry/<int:coffre_id>", methods=["POST"])
def add_password_entry(coffre_id):
    """
    Ajoute une entrée de mot de passe dans un coffre déverrouillé.

    Args:
        coffre_id (int): L'ID du coffre dans lequel ajouter l'entrée.

    Returns:
        Response: Une redirection vers la page du coffre déverrouillé.
    """
    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()

    if "user_id" not in flask_session or "session_token" not in flask_session:
        flash("Veuillez vous connecter pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))

    if not coffre:
        flash("Coffre non trouvé.", "error")
        return redirect(url_for("dashboard"))

    login = request.form["login"]
    password = request.form["password"]
    url = request.form["url"]
    name = request.form["name"]

    password_entry = PasswordEntry(
        login=login, password=password, url=url, name=name, coffre=coffre
    )
    db_session.add(password_entry)

    try:
        db_session.commit()
        flash("Entrée de mot de passe ajoutée avec succès.", "success")
    except Exception as e:
        db_session.rollback()
        flash(f"Erreur lors de l'ajout de l'entrée de mot de passe : {str(e)}", "error")

    return redirect(url_for("unlock_coffre", coffre_id=coffre_id))


@app.route(
    "/delete-password-entry/<int:password_entry_id>/<int:coffre_id>", methods=["POST"]
)
def delete_password_entry(password_entry_id, coffre_id):
    """
    Supprime une entrée de mot de passe dans un coffre.

    Args:
        password_entry_id (int): L'ID de l'entrée à supprimer.
        coffre_id (int): L'ID du coffre contenant l'entrée.

    Returns:
        Response: Une redirection vers la page du coffre déverrouillé.
    """
    if "user_id" not in flask_session or "session_token" not in flask_session:
        flash("Veuillez vous connecter pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))

    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()
    if not coffre:
        flash("Coffre non trouvé.", "error")
        return redirect(url_for("dashboard"))

    password_entry = (
        db_session.query(PasswordEntry)
        .filter_by(Id_PasswordEntry=password_entry_id, id_coffre=coffre_id)
        .first()
    )
    if not password_entry:
        flash("Entrée de mot de passe non trouvée.", "error")
        return redirect(url_for("unlock_coffre", coffre_id=coffre_id))

    db_session.delete(password_entry)
    try:
        db_session.commit()
        flash("Entrée de mot de passe supprimée avec succès.", "success")
    except Exception as e:
        db_session.rollback()
        flash(
            f"Erreur lors de la suppression de l'entrée de mot de passe : {str(e)}",
            "error",
        )

    return redirect(url_for("unlock_coffre", coffre_id=coffre_id))


@app.route(
    "/update-password-entry/<int:password_entry_id>/<int:coffre_id>", methods=["POST"]
)
def update_password_entry(password_entry_id, coffre_id):
    """
    Met à jour une entrée de mot de passe dans un coffre.

    Args:
        password_entry_id (int): L'ID de l'entrée à modifier.
        coffre_id (int): L'ID du coffre contenant l'entrée.

    Returns:
        Response: Une redirection vers la page du coffre déverrouillé.
    """
    if "user_id" not in flask_session or "session_token" not in flask_session:
        flash("Veuillez vous connecter pour accéder au tableau de bord.", "error")
        return redirect(url_for("login"))

    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()
    if not coffre:
        flash("Coffre non trouvé.", "error")
        return redirect(url_for("dashboard"))

    password_entry = (
        db_session.query(PasswordEntry)
        .filter_by(Id_PasswordEntry=password_entry_id, id_coffre=coffre_id)
        .first()
    )
    if not password_entry:
        flash("Entrée de mot de passe non trouvée.", "error")
        return redirect(url_for("unlock_coffre", coffre_id=coffre_id))

    new_password_entry = PasswordEntry(
        login=request.form.get("login", password_entry.login),
        password=request.form.get("password", password_entry.password),
        url=request.form.get("url", password_entry.url),
        name=request.form.get("name", password_entry.name),
        coffre=coffre,
    )

    db_session.delete(password_entry)
    db_session.add(new_password_entry)

    try:
        db_session.commit()
        flash("Entrée de mot de passe modifiée avec succès.", "success")
    except Exception as e:
        db_session.rollback()
        flash(f"Erreur lors de la modification de l'entrée : {str(e)}", "error")

    return redirect(url_for("unlock_coffre", coffre_id=coffre_id))


@app.route("/export/<int:coffre_id>", methods=["GET"])
def export_vault(coffre_id):
    """
    Exporte les données d'un coffre au format json.

    Args:
        coffre_id (int): L'ID du coffre à exporter.

    Returns:
        Response: Un fichier téléchargeable ou une erreur.
    """
    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()

    if coffre is None:
        return "Coffre introuvable", 404

    vault_manager = VaultController(coffre)

    file_path = vault_manager.export_coffre()

    if file_path:
        return send_file(file_path, as_attachment=True)
    else:
        return "Erreur lors de l'exportation", 500


@app.route("/vaults/import", methods=["GET", "POST"])
def import_vault():
    """
    Route Flask pour importer un coffre au format JSON et l'associer à un utilisateur existant.

    Returns:
        Redirige vers le tableau de bord ou retourne un message d'erreur.
    """
    try:
        # Vérifie que l'utilisateur est connecté
        user_id = session.get("user_id")
        if not user_id:
            flash("Vous devez être connecté pour importer un coffre.", "error")
            return redirect(url_for("login"))

        # Récupération de l'utilisateur (exemple avec SQLAlchemy)
        user = db_session.query(User).filter_by(Id_user=user_id).one_or_none()
        if not user:
            flash("Utilisateur introuvable.", "error")
            return redirect(url_for("login"))

        # Vérifie si un fichier a été envoyé
        if "vault_file" not in request.files:
            flash("Aucun fichier n'a été sélectionné.", "error")
            return redirect(url_for("create_coffre"))

        file = request.files["vault_file"]

        # Vérifie que le fichier a un nom valide
        if file.filename == "":
            flash("Aucun fichier sélectionné.", "error")
            return redirect(url_for("create_coffre"))

        # Vérifie l'extension du fichier
        if not allowed_file(file.filename):
            flash("Seuls les fichiers .json sont autorisés.", "error")
            return redirect(url_for("create_coffre"))

        # Assurez un nom de fichier sécurisé
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        # Crée le répertoire d'upload s'il n'existe pas
        if not os.path.exists(app.config["UPLOAD_FOLDER"]):
            os.makedirs(app.config["UPLOAD_FOLDER"])

        # Sauvegarde du fichier
        file.save(upload_path)

        # Appel au gestionnaire de coffre (VaultController) pour processus d'importation
        vault_manager = VaultController(None)
        success = vault_manager.import_vault(user, upload_path)

        # Résultat de l'importation
        if success:
            flash("Le fichier a été importé avec succès !", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Une erreur est survenue lors de l'importation.", "error")
            return redirect(url_for("create_coffre"))

    except json.JSONDecodeError:
        flash("Le fichier JSON est invalide.", "error")
        return redirect(url_for("create_coffre"))
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        flash("Une erreur inattendue s'est produite.", "error")
        return redirect(url_for("create_coffre"))


if __name__ == "__main__":
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"))
