import json
import secrets
from datetime import timedelta

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    send_file,
    redirect,
    url_for,
    flash,
    session as flask_session,
    send_from_directory,
    session,
)
from sqlalchemy.testing import db
from werkzeug.utils import secure_filename

from database.base import session as db_session
from models.coffre import Coffre
from models.password_entry import PasswordEntry
from models.user import User
from services.pass_fonc import *
from services.vaults import VaultController

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


@app.route("/delete-coffre/<int:coffre_id>", methods=["POST"])
def delete_coffre(coffre_id):
    """
    Supprime un coffre spécifié par son ID.

    Args:
        coffre_id (int): L'ID du coffre à supprimer.

    Returns:
        Response: Redirection vers le tableau de bord avec un message flash.
    """
    if "user_id" not in flask_session or "session_token" not in flask_session:
        flash("Veuillez vous connecter pour effectuer cette action.", "error")
        return redirect(url_for("login"))

    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()

    if not coffre:
        flash("Coffre introuvable.", "error")
        return redirect(url_for("dashboard"))

    try:
        db_session.delete(coffre)
        db_session.commit()
        flash("Coffre supprimé avec succès.", "success")
    except Exception as e:
        db_session.rollback()
        flash(f"Erreur lors de la suppression du coffre : {e}", "error")

    return redirect(url_for("dashboard"))


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
    db_session.commit()

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
    Exporte les données d'un coffre au format JSON dans le dossier Downloads
    et renvoie le fichier pour téléchargement.

    Args:
        coffre_id (int): L'ID du coffre à exporter.

    Returns:
        Response: Un fichier téléchargeable ou une erreur.
    """
    try:
        coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()
        if coffre is None:
            flash("Coffre introuvable.", "error")
            return "Coffre introuvable", 404

        vault_manager = VaultController(coffre)

        # Exportation des données
        file_path = vault_manager.export_coffre()

        # Vérification si le fichier a été généré avec succès
        if file_path and os.path.exists(file_path):
            return send_file(file_path, as_attachment=True)
        else:
            flash("Erreur lors de l'exportation. Fichier introuvable.", "error")
            return "Erreur lors de l'exportation", 500

    except FileNotFoundError as fnf_error:
        print(f"Erreur lors de l'exportation : Dossier ou fichier introuvable : {fnf_error}")
        flash("Problème avec l'emplacement du fichier exporté. Contactez l'administrateur.", "error")
        return "Erreur de chemin d'accès", 500
    except PermissionError as perm_error:
        print(f"Erreur lors de l'exportation : Problème de permissions : {perm_error}")
        flash("Permissions refusées lors de l'écriture du fichier. Contactez l'administrateur.", "error")
        return "Erreur de permission", 500
    except Exception as e:
        print(f"Erreur lors de l'exportation : {e}")
        flash("Une erreur inattendue s'est produite lors de l'exportation. Contactez l'administrateur.", "error")
        return "Une erreur s'est produite", 500

@app.route('/import/<int:coffre_id>', methods=['POST'])
def import_vault(coffre_id):
    uploaded_file = request.files.get('vault_file')
    if uploaded_file and uploaded_file.filename.endswith('.json'):
        try:
            coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()
            # Charger les données JSON
            data = json.load(uploaded_file)

            for entry in data.get('password_entries', []):

                new_entry = PasswordEntry(
                    name=entry['name'],
                    login=entry['login'],
                    password=entry['password'],
                    url=entry.get('url', ''),
                    coffre=coffre
                )
                db_session.add(new_entry)
            db_session.commit()
            flash("Importation réussie !", "success")
        except Exception as e:
            flash(f"Erreur lors de l'importation : {e}", "error")
    else:
        flash("Veuillez télécharger un fichier .json valide.", "error")
    return redirect(url_for("unlock_coffre", coffre_id=coffre_id))


if __name__ == "__main__":
    app.run(debug=True, ssl_context=("cert.pem", "key.pem"))
