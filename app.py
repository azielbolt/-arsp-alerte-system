
import os, sqlite3, hashlib, csv
from pathlib import Path
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, send_file

APP_NAME = "ARSP Alerte"
DB_FILE = "arsp_alerte.db"
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf","png","jpg","jpeg","gif","webp","doc","docx","xls","xlsx","mp3","wav","mp4","mov","avi"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "arsp-alerte-secret-key")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

PROVINCES = ["Kinshasa","Kongo Central","Kwango","Kwilu","Mai-Ndombe","Équateur","Mongala","Nord-Ubangi","Sud-Ubangi","Tshuapa","Haut-Katanga","Haut-Lomami","Lualaba","Tanganyika","Kasaï","Kasaï-Central","Kasaï-Oriental","Lomami","Sankuru","Maniema","Nord-Kivu","Sud-Kivu","Ituri","Bas-Uélé","Haut-Uélé","Tshopo"]
SECTEURS = ["Mines","BTP / Construction","Hydrocarbures","Transport","Télécommunications","Commerce","Industrie","Services","Autre"]
TYPES_ENTITE = ["Entreprise","Personne physique","Institution publique","Organisation","Autre"]
TYPES_SIGNALEMENT = ["Non-respect de la sous-traitance","Corruption","Fraude","Abus de pouvoir","Conflit d’intérêt","Marché irrégulier","Autre"]
STATUTS = ["Nouveau","En traitement","Résolu","Rejeté","Archivé"]
PRIORITES = ["Normale","Haute","Urgente"]

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS utilisateurs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'Administrateur',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS signalements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom_declarant TEXT,
        telephone TEXT,
        email TEXT,
        province_declarant TEXT,
        province_incident TEXT,
        ville_incident TEXT,
        secteur_activite TEXT,
        type_entite TEXT,
        type_signalement TEXT,
        nom_entite_concernee TEXT,
        titre TEXT,
        description TEXT NOT NULL,
        statut TEXT DEFAULT 'Nouveau',
        priorite TEXT DEFAULT 'Normale',
        observation_admin TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS fichiers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signalement_id INTEGER NOT NULL,
        nom_original TEXT NOT NULL,
        nom_stocke TEXT NOT NULL,
        chemin TEXT NOT NULL,
        type_mime TEXT,
        taille INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    cur.execute("SELECT COUNT(*) FROM utilisateurs")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO utilisateurs (nom, username, password_hash, role) VALUES (?, ?, ?, ?)",
                    ("Administrateur ARSP", "admin", hash_password("admin123"), "Administrateur"))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_globals():
    return dict(app_name=APP_NAME, current_user=session.get("user"), provinces=PROVINCES,
                secteurs=SECTEURS, types_entite=TYPES_ENTITE, types_signalement=TYPES_SIGNALEMENT,
                statuts=STATUTS, priorites=PRIORITES)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/soumettre", methods=["POST"])
def soumettre():
    data = {
        "nom_declarant": request.form.get("nom_declarant", "").strip(),
        "telephone": request.form.get("telephone", "").strip(),
        "email": request.form.get("email", "").strip(),
        "province_declarant": request.form.get("province_declarant", "").strip(),
        "province_incident": request.form.get("province_incident", "").strip(),
        "ville_incident": request.form.get("ville_incident", "").strip(),
        "secteur_activite": request.form.get("secteur_activite", "").strip(),
        "type_entite": request.form.get("type_entite", "").strip(),
        "type_signalement": request.form.get("type_signalement", "").strip(),
        "nom_entite_concernee": request.form.get("nom_entite_concernee", "").strip(),
        "titre": request.form.get("titre", "").strip(),
        "description": request.form.get("description", "").strip(),
        "priorite": request.form.get("priorite", "Normale").strip()
    }
    if not data["description"]:
        flash("Veuillez décrire le signalement.", "danger")
        return redirect(url_for("index"))
    conn = db()
    cur = conn.cursor()
    cur.execute('''
    INSERT INTO signalements (
        nom_declarant, telephone, email, province_declarant, province_incident,
        ville_incident, secteur_activite, type_entite, type_signalement,
        nom_entite_concernee, titre, description, priorite
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', tuple(data.values()))
    signalement_id = cur.lastrowid
    dossier = Path(app.config["UPLOAD_FOLDER"]) / f"signalement_{signalement_id}"
    dossier.mkdir(parents=True, exist_ok=True)
    for fichier in request.files.getlist("fichiers"):
        if fichier and fichier.filename and allowed_file(fichier.filename):
            original = secure_filename(fichier.filename)
            stored = datetime.now().strftime("%Y%m%d%H%M%S_") + original
            path = dossier / stored
            fichier.save(path)
            cur.execute('''
            INSERT INTO fichiers (signalement_id, nom_original, nom_stocke, chemin, type_mime, taille)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (signalement_id, original, stored, str(path), fichier.mimetype, path.stat().st_size))
    conn.commit()
    conn.close()
    return redirect(url_for("merci", signalement_id=signalement_id))

@app.route("/merci/<int:signalement_id>")
def merci(signalement_id):
    return render_template("merci.html", signalement_id=signalement_id)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        conn = db()
        user = conn.execute("SELECT * FROM utilisateurs WHERE username=? AND password_hash=?",
                            (username, hash_password(password))).fetchone()
        conn.close()
        if user:
            session["user"] = {"id": user["id"], "nom": user["nom"], "username": user["username"], "role": user["role"]}
            return redirect(url_for("dashboard"))
        flash("Identifiants incorrects.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin")
@login_required
def dashboard():
    conn = db()
    total = conn.execute("SELECT COUNT(*) FROM signalements").fetchone()[0]
    nouveau = conn.execute("SELECT COUNT(*) FROM signalements WHERE statut='Nouveau'").fetchone()[0]
    traitement = conn.execute("SELECT COUNT(*) FROM signalements WHERE statut='En traitement'").fetchone()[0]
    resolu = conn.execute("SELECT COUNT(*) FROM signalements WHERE statut='Résolu'").fetchone()[0]
    urgent = conn.execute("SELECT COUNT(*) FROM signalements WHERE priorite='Urgente'").fetchone()[0]
    par_province = conn.execute("SELECT province_incident, COUNT(*) total FROM signalements WHERE province_incident!='' GROUP BY province_incident ORDER BY total DESC LIMIT 8").fetchall()
    par_secteur = conn.execute("SELECT secteur_activite, COUNT(*) total FROM signalements WHERE secteur_activite!='' GROUP BY secteur_activite ORDER BY total DESC LIMIT 8").fetchall()
    derniers = conn.execute("SELECT s.*, COUNT(f.id) nb_fichiers FROM signalements s LEFT JOIN fichiers f ON f.signalement_id=s.id GROUP BY s.id ORDER BY s.created_at DESC LIMIT 10").fetchall()
    conn.close()
    return render_template("dashboard.html", total=total, nouveau=nouveau, traitement=traitement, resolu=resolu, urgent=urgent, par_province=par_province, par_secteur=par_secteur, derniers=derniers)

@app.route("/admin/signalements")
@login_required
def signalements():
    statut = request.args.get("statut", "")
    province = request.args.get("province", "")
    secteur = request.args.get("secteur", "")
    type_signalement = request.args.get("type_signalement", "")
    search = request.args.get("search", "")
    query = "SELECT s.*, COUNT(f.id) nb_fichiers FROM signalements s LEFT JOIN fichiers f ON f.signalement_id=s.id WHERE 1=1"
    params = []
    if statut:
        query += " AND s.statut=?"; params.append(statut)
    if province:
        query += " AND s.province_incident=?"; params.append(province)
    if secteur:
        query += " AND s.secteur_activite=?"; params.append(secteur)
    if type_signalement:
        query += " AND s.type_signalement=?"; params.append(type_signalement)
    if search:
        query += " AND (s.nom_declarant LIKE ? OR s.telephone LIKE ? OR s.email LIKE ? OR s.nom_entite_concernee LIKE ? OR s.ville_incident LIKE ?)"
        params += [f"%{search}%"] * 5
    query += " GROUP BY s.id ORDER BY s.created_at DESC"
    conn = db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return render_template("signalements.html", rows=rows, statut=statut, province=province, secteur=secteur, type_signalement=type_signalement, search=search)

@app.route("/admin/signalement/<int:id>", methods=["GET", "POST"])
@login_required
def detail_signalement(id):
    conn = db()
    if request.method == "POST":
        conn.execute("UPDATE signalements SET statut=?, priorite=?, observation_admin=? WHERE id=?",
                     (request.form.get("statut"), request.form.get("priorite"), request.form.get("observation_admin"), id))
        conn.commit()
        flash("Dossier mis à jour.", "success")
    signalement = conn.execute("SELECT * FROM signalements WHERE id=?", (id,)).fetchone()
    fichiers = conn.execute("SELECT * FROM fichiers WHERE signalement_id=? ORDER BY created_at DESC", (id,)).fetchall()
    conn.close()
    if not signalement:
        flash("Signalement introuvable.", "danger")
        return redirect(url_for("signalements"))
    return render_template("detail.html", signalement=signalement, fichiers=fichiers)

@app.route("/admin/fichier/<int:fichier_id>")
@login_required
def telecharger_fichier(fichier_id):
    conn = db()
    fichier = conn.execute("SELECT * FROM fichiers WHERE id=?", (fichier_id,)).fetchone()
    conn.close()
    if not fichier:
        flash("Fichier introuvable.", "danger")
        return redirect(url_for("signalements"))
    path = Path(fichier["chemin"])
    return send_from_directory(path.parent, path.name, as_attachment=True, download_name=fichier["nom_original"])

@app.route("/admin/export")
@login_required
def export_csv():
    conn = db()
    rows = conn.execute("SELECT * FROM signalements ORDER BY created_at DESC").fetchall()
    conn.close()
    file_name = "export_signalements_arsp.csv"
    columns = ["id","created_at","nom_declarant","telephone","email","province_declarant","province_incident","ville_incident","secteur_activite","type_entite","type_signalement","nom_entite_concernee","titre","description","statut","priorite","observation_admin"]
    with open(file_name, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([row[col] for col in columns])
    return send_file(file_name, as_attachment=True)

if __name__ == "__main__":
    init_db()
    Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
port = int(os.environ.get("PORT", 10000))
app.run(host="0.0.0.0", port=port)
