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
    make_response,
)
from database import session as db_session
from models.user import User
from models.coffre import Coffre
from models.password_entry import PasswordEntry
from services.vaults import VaultController
import os
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



@app.route("/")
def home():
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

@app.route('/export/<int:coffre_id>', methods=['GET'])
def export_vault(coffre_id):
    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()

    if coffre is None:
        return 'Coffre introuvable', 404

    # Créer une instance de VaultController
    vault_manager = VaultController(coffre)

    # Chemin du fichier où exporter les données
    file_path = f"exported_vault_{coffre_id}.json"

    # Exporter le coffre
    success = vault_manager.export_coffre(file_path)

    if success:
        return send_file(file_path, as_attachment=True)
    else:
        return 'Erreur lors de l\'exportation', 500


@app.route('/import/<int:coffre_id>', methods=['POST'])
def import_vault(coffre_id):
    coffre = db_session.query(Coffre).filter_by(Id_coffre=coffre_id).first()

    if coffre is None:
        return 'Coffre introuvable', 404

    # Créer une instance de VaultController
    vault_manager = VaultController(coffre)

    # Chemin du fichier depuis lequel importer les données
    file_path = request.files['vault_file']

    # Importer le coffre
    success = vault_manager.import_coffre(file_path)

    if success:
        return 'Importation réussie', 200
    else:
        return 'Erreur lors de l\'importation', 500


if __name__ == "__main__":
    app.run(debug=True)
