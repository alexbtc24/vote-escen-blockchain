import json
import os
import hashlib
from uuid import uuid4
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, g
from datetime import datetime, timezone 
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
import pandas as pd # NOUVEL IMPORT NÉCESSAIRE (pip install pandas openpyxl)
import tempfile # NOUVEL IMPORT: Pour une gestion sécurisée et multi-OS des fichiers temporaires
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc # Import nécessaire pour la gestion des erreurs de base de données

# --- CONFIGURATION INITIALE SIMPLIFIÉE ---
app = Flask(__name__)
# Utilisez une clé secrète forte en production !
app.secret_key = os.environ.get('FLASK_SECRET_KEY', str(uuid4())) 

# --- CORRECTION DE L'ERREUR JINJA : CONTEXTE-PROCESSEUR ---\
@app.context_processor
def inject_datetime():
    """Rend l'objet datetime disponible dans tous les templates Jinja2."""
    return {'datetime': datetime}
# ------------------------------------------------------------------

DATA_DIR = 'database'
os.makedirs(DATA_DIR, exist_ok=True)

# Fichiers
VOTERS_FILE = os.path.join(DATA_DIR, 'voters.json') 
CANDIDATES_FILE = os.path.join(DATA_DIR, 'candidates.json')
VOTE_CHAIN_FILE = os.path.join(DATA_DIR, 'vote_chain.json')
ADMIN_USERS_FILE = os.path.join(DATA_DIR, 'admin_users.json')

# Paramètres de l'élection
ELECTION_STATUS_FILE = os.path.join(DATA_DIR, 'election_status.json')
ELECTION_STATUS = {
    'status': 'PENDING', # PENDING, VOTING, PAUSED, FINISHED
    'results_visible': False,
    'start_time': None,
    'end_time': None
}

# HACHAGE des fichiers de données
def get_file_hash(filepath):
    """Calcule le hash SHA256 d'un fichier."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
    except FileNotFoundError:
        return None
    return hasher.hexdigest()

# Chargement des données (Utilisé pour l'initialisation des fichiers locaux)
def load_data(filepath, default_data):
    """Charge les données JSON ou utilise les données par défaut si le fichier n'existe pas."""
    if not os.path.exists(filepath):
        # Initialise le fichier avec les données par défaut (comme pour les utilisateurs admin)
        with open(filepath, 'w') as f:
            json.dump(default_data, f, indent=4)
        return default_data
    with open(filepath, 'r') as f:
        return json.load(f)

# Sauvegarde des données (pour les fichiers JSON hors BDD)
def save_data(filepath, data):
    """Sauvegarde les données dans un fichier JSON."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)


# --- Configuration de la Base de Données (PostgreSQL) ---
# Utilisation de la variable d'environnement DATABASE_URL de Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
# Assurez-vous que l'URL commence par 'postgresql://' pour SQLAlchemy 2.0
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Définition des Modèles de Base de Données
class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # CORRECTION CRUCIALE: db.String(256) pour supporter le hachage scrypt
    password_hash = db.Column(db.String(256), nullable=False) 
    role = db.Column(db.String(50), nullable=False) # Ex: ADMIN_INSTITUTION

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_numerique = db.Column(db.String(10), unique=True, nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    parcours = db.Column(db.String(100), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)
    date_inscription = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.String(10), unique=True, nullable=False)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    slogan = db.Column(db.Text, nullable=False)
    programme = db.Column(db.Text, nullable=False)
    photo_filename = db.Column(db.String(255), nullable=True)
    is_validated = db.Column(db.Boolean, default=False)
    date_candidature = db.Column(db.DateTime, default=datetime.now(timezone.utc))

class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    payload_json = db.Column(db.Text, nullable=False) # Le contenu de l'événement (vote, inscription, etc.)
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    nonce = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(50), nullable=False) # VOTE, VOTER_REGISTERED, CANDIDATE_REGISTERED, etc.
    

# Initialisation des données par défaut pour les fichiers JSON
DEFAULT_ADMINS = [
    {'username': 'admin_institution', 'password_hash': generate_password_hash('escen_admin_2024'), 'role': 'ADMIN_INSTITUTION'}
]
VOTERS = []
CANDIDATES = []
VOTE_CHAIN = []

# --- Système de Blockchain (Simplifié pour la démo) ---
class Blockchain:
    def __init__(self):
        # La chaîne est gérée par la base de données SQL.
        pass

    def hash_block(self, block):
        """Crée un hash SHA256 pour un bloc."""
        block_string = json.dumps({
            "index": block.index,
            "timestamp": block.timestamp.isoformat(),
            "payload": block.payload_json,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def proof_of_work(self, block):
        """Algorithme de Preuve de Travail simple (2 zéros en tête)."""
        difficulty = 2
        block.nonce = 0
        computed_hash = self.hash_block(block)
        while not computed_hash.startswith('0' * difficulty):
            block.nonce += 1
            computed_hash = self.hash_block(block)
        return computed_hash

    def get_latest_block(self):
        """Récupère le dernier bloc de la BDD."""
        return Block.query.order_by(Block.index.desc()).first()

    def create_genesis_block(self):
        """Crée le premier bloc de la chaîne (Block #0)."""
        genesis_payload = json.dumps({"message": "Bloc Genesis de l'élection ESCEN"})
        genesis_block = Block(
            index=0,
            timestamp=datetime.now(timezone.utc),
            payload_json=genesis_payload,
            previous_hash="0",
            hash="",
            nonce=0,
            type="GENESIS"
        )
        # Hacher le bloc Genesis (PoW non obligatoire pour le bloc 0, mais on le fait par cohérence)
        genesis_block.hash = self.proof_of_work(genesis_block)
        db.session.add(genesis_block)
        # La validation et le commit final sont gérés par la fonction initdb.
        return genesis_block

    def add_new_block(self, payload, type):
        """Ajoute un nouveau bloc à la chaîne après PoW."""
        latest_block = self.get_latest_block()
        if not latest_block:
             # Ne devrait pas arriver si create_genesis_block a été appelé, mais sécurité
             self.create_genesis_block()
             latest_block = self.get_latest_block()

        new_index = latest_block.index + 1
        new_block = Block(
            index=new_index,
            timestamp=datetime.now(timezone.utc),
            payload_json=json.dumps(payload, sort_keys=True),
            previous_hash=latest_block.hash,
            hash="", # sera calculé
            nonce=0,
            type=type
        )
        
        # Effectuer la preuve de travail
        new_block.hash = self.proof_of_work(new_block)
        
        db.session.add(new_block)
        db.session.commit()
        
        return new_block


blockchain = Blockchain()

# --- Fonctions de l'Élection ---
def get_election_status():
    """Récupère l'état de l'élection (hors BDD pour la simplicité)."""
    global ELECTION_STATUS
    if os.path.exists(ELECTION_STATUS_FILE):
        with open(ELECTION_STATUS_FILE, 'r') as f:
            ELECTION_STATUS = json.load(f)
    return ELECTION_STATUS

def save_election_status(new_status):
    """Sauvegarde l'état de l'élection."""
    global ELECTION_STATUS
    ELECTION_STATUS.update(new_status)
    with open(ELECTION_STATUS_FILE, 'w') as f:
        json.dump(ELECTION_STATUS, f, indent=4)


# --- Middlewares et Décorateurs ---
def login_required(f):
    """Décorateur pour exiger une session admin active."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def election_status_check(required_status):
    """Décorateur pour vérifier l'état de l'élection."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            status = get_election_status()['status']
            if status != required_status:
                return render_template('error_page.html', message=f"L'élection n'est pas au statut '{required_status}'. Statut actuel : {status}")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Commandes Flask CLI pour la Base de Données et l'Initialisation ---
@app.cli.command("initdb")
def init_db():
    """Initialise la base de données et crée l'utilisateur admin par défaut."""
    print("Création des tables de la base de données...")
    with app.app_context():
        
        # --- FIX TEMPORAIRE POUR CORRIGER LE SCHÉMA POSTGRESQL (VARCHAR(128) -> VARCHAR(256)) ---
        # Cette étape supprime la table 'admin_user' si elle existe, 
        # forçant sa recréation propre avec la taille de colonne corrigée (256).
        # À RETIRER UNE FOIS LE DÉPLOIEMENT RÉUSSI !
        try:
            # db.engine.has_table() nécessite SQLAlchemy 2.0. Utilisons metadata.tables
            if 'admin_user' in db.metadata.tables:
                db.metadata.tables['admin_user'].drop(db.engine)
                print("FIX TEMPORAIRE : Ancienne table 'admin_user' supprimée pour correction de schéma.")
            else:
                # Si la table n'est pas dans les metadata, elle n'est probablement pas dans la DB non plus.
                # On peut essayer de la droper directement si nécessaire, mais on s'arrête là pour la simplicité.
                print("FIX TEMPORAIRE : La table 'admin_user' n'existe pas ou n'est pas référencée. Pas d'action de suppression nécessaire.")
        except exc.NoSuchTableError:
            print("FIX TEMPORAIRE : La table 'admin_user' n'existait pas, c'est bon.")
        except Exception as e:
            # Cette erreur est capturée au cas où il y aurait des problèmes de permissions
            print(f"ATTENTION: Échec de la suppression temporaire de la table 'admin_user'. Erreur: {e}")
        # --------------------------------------------------------------------------------------
        
        db.create_all()
        
        # Création de l'utilisateur admin par défaut
        if AdminUser.query.filter_by(username='admin_institution').first() is None:
            print("Création de l'utilisateur admin par défaut (admin_institution)...")
            # Le mot de passe par défaut est 'escen_admin_2024'
            password = 'escen_admin_2024'
            # Note: generate_password_hash utilise par défaut 'scrypt', qui produit un long hash
            hashed_password = generate_password_hash(password) 
            
            admin = AdminUser(username='admin_institution', password_hash=hashed_password, role='ADMIN_INSTITUTION')
            db.session.add(admin)
            db.session.commit()
            print("Utilisateur admin créé avec succès.")

        # Création du bloc Genesis
        if Block.query.count() == 0:
            print("Création du bloc Genesis (Blockchain) si non existant...")
            blockchain.create_genesis_block()
            db.session.commit()
            print("Bloc Genesis créé.")
            
        print("Initialisation de la base de données terminée.")

# --- Routes Web ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/results')
def results():
    status_data = get_election_status()
    
    if not status_data['results_visible'] and status_data['status'] != 'FINISHED':
        status_message = "Les résultats sont actuellement cachés par l'administration."
        return render_template('results.html', 
                               election_status=status_data['status'], 
                               status_message=status_message,
                               total_votes=0,
                               results=[])
    
    # 1. Récupérer tous les blocs de vote
    vote_blocks = Block.query.filter_by(type='VOTE').all()
    
    # 2. Compter les votes
    vote_counts = {}
    for block in vote_blocks:
        payload = json.loads(block.payload_json)
        candidate_id = payload.get('candidate_id')
        if candidate_id:
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1

    total_votes = sum(vote_counts.values())
    
    # 3. Récupérer les candidats validés et former les résultats
    validated_candidates = Candidate.query.filter_by(is_validated=True).all()
    
    results_list = []
    if total_votes > 0:
        for candidate in validated_candidates:
            votes = vote_counts.get(candidate.candidate_id, 0)
            percentage = round((votes / total_votes) * 100, 2)
            results_list.append({
                'name': f"{candidate.nom} {candidate.prenom}",
                'votes': votes,
                'percentage': percentage,
                'photo': url_for('static', filename=f'uploads/{candidate.photo_filename}') if candidate.photo_filename else url_for('static', filename='uploads/default.png')
            })
    else:
        # Afficher les candidats avec 0 vote si aucun vote
        for candidate in validated_candidates:
            results_list.append({
                'name': f"{candidate.nom} {candidate.prenom}",
                'votes': 0,
                'percentage': 0.0,
                'photo': url_for('static', filename=f'uploads/{candidate.photo_filename}') if candidate.photo_filename else url_for('static', filename='uploads/default.png')
            })

    # Trier par nombre de votes (descendant)
    results_list.sort(key=lambda x: x['votes'], reverse=True)
    
    # Message de statut
    if status_data['status'] == 'VOTING':
        status_message = "Le vote est actuellement en cours."
    elif status_data['status'] == 'PENDING':
        status_message = "Le vote est en attente de démarrage."
    elif status_data['status'] == 'PAUSED':
        status_message = "Le vote est suspendu."
    elif status_data['status'] == 'FINISHED':
        # Après la fin, on peut rediriger vers la page des résultats finaux si on le souhaite
        return redirect(url_for('final_results'))
    else:
        status_message = "Statut indéfini."
        
    return render_template('results.html', 
                           election_status=status_data['status'],
                           status_message=status_message,
                           total_votes=total_votes,
                           results=results_list)

@app.route('/results/final')
def final_results():
    status_data = get_election_status()
    
    if status_data['status'] != 'FINISHED':
        # Rediriger vers la page des résultats en direct si l'élection n'est pas terminée
        return redirect(url_for('results')) 
        
    # Le calcul est le même que pour /results, mais on utilise le template final
    vote_blocks = Block.query.filter_by(type='VOTE').all()
    vote_counts = {}
    for block in vote_blocks:
        payload = json.loads(block.payload_json)
        candidate_id = payload.get('candidate_id')
        if candidate_id:
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1

    total_votes = sum(vote_counts.values())
    
    validated_candidates = Candidate.query.filter_by(is_validated=True).all()
    
    results_list = []
    if total_votes > 0:
        for candidate in validated_candidates:
            votes = vote_counts.get(candidate.candidate_id, 0)
            percentage = round((votes / total_votes) * 100, 2)
            results_list.append({
                'name': f"{candidate.nom} {candidate.prenom}",
                'votes': votes,
                'percentage': percentage,
                'photo': url_for('static', filename=f'uploads/{candidate.photo_filename}') if candidate.photo_filename else url_for('static', filename='uploads/default.png')
            })
    else:
        for candidate in validated_candidates:
            results_list.append({
                'name': f"{candidate.nom} {candidate.prenom}",
                'votes': 0,
                'percentage': 0.0,
                'photo': url_for('static', filename=f'uploads/{candidate.photo_filename}') if candidate.photo_filename else url_for('static', filename='uploads/default.png')
            })

    # Trier par nombre de votes (descendant)
    results_list.sort(key=lambda x: x['votes'], reverse=True)
    
    return render_template('results_final.html', 
                           total_votes=total_votes,
                           results=results_list)


# --- Routes d'Inscription Étudiant (Votant) ---

@app.route('/self_register_student', methods=['GET'])
def self_register_student_get():
    """Affiche la page d'auto-inscription des étudiants."""
    return render_template('self_register_student.html')


@app.route('/api/student/self_register', methods=['POST'])
@election_status_check('PENDING') # L'inscription des votants doit se faire avant le début du vote
def self_register_student_api():
    """API pour l'auto-inscription des étudiants."""
    data = request.get_json()
    nom = data.get('nom', '').strip().upper()
    prenom = data.get('prenom', '').strip().upper()
    parcours = data.get('parcours', '').strip().upper()
    
    if not nom or not prenom or not parcours:
        return jsonify({'error': 'Tous les champs sont requis.'}), 400
        
    # 1. Vérification d'éligibilité (logique simplifiée)
    # Dans un vrai système, on vérifierait dans une liste d'étudiants officielle.
    
    # 2. Vérification d'existence
    # On vérifie si un étudiant avec ce nom, prénom et parcours existe déjà
    existing_voter = Voter.query.filter(
        Voter.nom == nom,
        Voter.prenom == prenom,
        Voter.parcours == parcours
    ).first()

    if existing_voter:
        return jsonify({
            'error': f"Vous êtes déjà inscrit. Votre ID est : {existing_voter.id_numerique}."
        }), 409
        
    # 3. Génération de l'ID numérique (UUID tronqué)
    while True:
        # Générer un ID numérique unique de 10 caractères
        id_numerique = str(uuid4().hex[:10]).upper()
        if Voter.query.filter_by(id_numerique=id_numerique).first() is None:
            break
            
    # 4. Enregistrement dans la BDD
    try:
        new_voter = Voter(
            id_numerique=id_numerique,
            nom=nom,
            prenom=prenom,
            parcours=parcours
        )
        db.session.add(new_voter)
        
        # 5. Création du bloc de Blockchain (Événement d'Inscription)
        payload = {
            'id_numerique': id_numerique,
            'nom': nom, # Ces données ne seront pas visibles dans l'explorer public (anonymisation)
            'prenom': prenom,
            'parcours': parcours,
            'date': new_voter.date_inscription.isoformat()
        }
        blockchain.add_new_block(payload, type='VOTER_REGISTERED')
        
        # Le commit se fait dans blockchain.add_new_block
        
        return jsonify({
            'message': 'Inscription réussie.',
            'id_numerique': id_numerique
        }), 201

    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur lors de l'auto-inscription du votant: {e}")
        return jsonify({'error': 'Erreur serveur lors de l\'enregistrement.'}), 500


# --- Routes d'Inscription Candidat ---
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/self_register_candidate', methods=['GET'])
def self_register_candidate_get():
    """Affiche la page d'auto-inscription des candidats."""
    return render_template('self_register_candidate.html')

@app.route('/api/candidate/self_register', methods=['POST'])
@election_status_check('PENDING') # La candidature doit se faire avant le début du vote
def self_register_candidate_api():
    """API pour l'auto-inscription des candidats."""
    
    # 1. Validation des données du formulaire (multipart/form-data)
    nom = request.form.get('nom', '').strip().upper()
    prenom = request.form.get('prenom', '').strip().upper()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    photo = request.files.get('photo')
    
    if not all([nom, prenom, slogan, programme]):
        return jsonify({'error': 'Tous les champs de texte sont requis.'}), 400

    if len(slogan.split()) > 100 or len(programme.split()) < 300:
         return jsonify({'error': 'Le slogan doit faire max 100 mots et le programme min 300 mots.'}), 400
         
    # 2. Gestion du fichier
    filename = None
    if photo and allowed_file(photo.filename):
        # Créer le répertoire 'uploads' si non existant
        upload_dir = os.path.join('static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        
        # Générer un nom de fichier unique et sécurisé
        ext = photo.filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid4().hex}.{ext}"
        filename = secure_filename(unique_filename)
        photo.save(os.path.join(upload_dir, filename))
    elif photo and not allowed_file(photo.filename):
        return jsonify({'error': 'Format de fichier non supporté. Utilisez PNG, JPG ou JPEG.'}), 400
    elif not photo:
        return jsonify({'error': 'Une photo de profil est requise.'}), 400
        
    # 3. Génération de l'ID Candidat
    while True:
        # Générer un ID numérique unique de 10 caractères
        candidate_id = 'C' + str(uuid4().hex[:9]).upper()
        if Candidate.query.filter_by(candidate_id=candidate_id).first() is None:
            break
            
    # 4. Enregistrement dans la BDD (is_validated=False par défaut)
    try:
        new_candidate = Candidate(
            candidate_id=candidate_id,
            nom=nom,
            prenom=prenom,
            slogan=slogan,
            programme=programme,
            photo_filename=filename
        )
        db.session.add(new_candidate)
        
        # 5. Création du bloc de Blockchain (Événement de Candidature)
        payload = {
            'candidate_id': candidate_id,
            'nom': nom,
            'prenom': prenom,
            'date': new_candidate.date_candidature.isoformat()
        }
        blockchain.add_new_block(payload, type='CANDIDATE_REGISTERED')
        
        return jsonify({
            'message': 'Candidature enregistrée avec succès.',
            'candidate_id': candidate_id
        }), 201

    except Exception as e:
        db.session.rollback()
        # Supprimer le fichier si l'enregistrement BDD échoue
        if filename and os.path.exists(os.path.join('static', 'uploads', filename)):
            os.remove(os.path.join('static', 'uploads', filename))
            
        logging.error(f"Erreur lors de l'auto-inscription du candidat: {e}")
        return jsonify({'error': 'Erreur serveur lors de l\'enregistrement.'}), 500


# --- Routes d'Accès Votant ---
@app.route('/voter_login', methods=['GET'])
def voter_login():
    """Affiche la page de connexion pour les votants."""
    # Si l'utilisateur est déjà dans la session, le rediriger
    if session.get('voter_logged_in'):
        return redirect(url_for('voting_page'))
    return render_template('voter_login.html')

@app.route('/api/voter/login', methods=['POST'])
@election_status_check('VOTING') # Le vote doit être en cours
def voter_login_api():
    """API pour valider l'ID numérique du votant."""
    data = request.get_json()
    id_numerique = data.get('id_numerique', '').strip().upper()
    
    voter = Voter.query.filter_by(id_numerique=id_numerique).first()

    if not voter:
        return jsonify({'error': 'ID numérique invalide.'}), 401
    
    if voter.has_voted:
        return jsonify({'error': 'Vous avez déjà voté.'}), 403
    
    # Enregistrement en session (très simple pour la démo)
    session['voter_id_numerique'] = voter.id_numerique
    session['voter_logged_in'] = True
    
    return jsonify({
        'message': 'Connexion réussie.', 
        'redirect_url': url_for('voting_page')
    }), 200

@app.route('/voting_page')
def voting_page():
    """Affiche le bulletin de vote."""
    if not session.get('voter_logged_in'):
        return redirect(url_for('voter_login'))
        
    voter_id = session['voter_id_numerique']
    voter = Voter.query.filter_by(id_numerique=voter_id).first()
    
    if not voter or voter.has_voted:
        # Redirection si le votant a voté ou n'existe plus
        session.pop('voter_logged_in', None)
        session.pop('voter_id_numerique', None)
        return redirect(url_for('voter_login'))
        
    # Récupérer uniquement les candidats validés
    candidates = Candidate.query.filter_by(is_validated=True).all()
    
    if not candidates:
         return render_template('error_page.html', message="Aucun candidat validé pour l'instant.")
         
    return render_template('voting_page.html', candidates=candidates, voter_id=voter_id)

@app.route('/api/vote', methods=['POST'])
@election_status_check('VOTING') # Le vote doit être en cours
def vote_api():
    """API pour enregistrer un vote sur la Blockchain."""
    data = request.get_json()
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')

    # Vérification de session et d'ID
    if not session.get('voter_logged_in') or session.get('voter_id_numerique') != voter_id:
        return jsonify({'error': 'Accès non autorisé ou session expirée.'}), 401

    # Vérification du votant
    voter = Voter.query.filter_by(id_numerique=voter_id).first()
    if not voter or voter.has_voted:
        # Enlever les infos de session
        session.pop('voter_logged_in', None)
        session.pop('voter_id_numerique', None)
        return jsonify({'error': 'ID de votant invalide ou vote déjà enregistré.'}), 403

    # Vérification du candidat (doit être validé)
    candidate = Candidate.query.filter_by(candidate_id=candidate_id, is_validated=True).first()
    if not candidate:
        return jsonify({'error': 'Candidat invalide ou non validé.'}), 400
        
    # 1. Enregistrement du vote dans la Blockchain
    try:
        payload = {
            'voter_id': voter_id, # Cet ID sera anonymisé dans l'explorateur public
            'candidate_id': candidate_id,
        }
        new_block = blockchain.add_new_block(payload, type='VOTE')
        
        # 2. Marquer le votant comme ayant voté
        voter.has_voted = True
        db.session.commit()
        
        # 3. Vider la session du votant
        session.pop('voter_logged_in', None)
        session.pop('voter_id_numerique', None)
        
        return jsonify({
            'message': 'Vote enregistré avec succès.',
            'block_index': new_block.index
        }), 201

    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur lors de l'enregistrement du vote: {e}")
        return jsonify({'error': 'Erreur serveur lors de l\'enregistrement du vote.'}), 500


# --- Routes Administrateur ---
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = AdminUser.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password_hash, password):
            session['admin_logged_in'] = True
            session['admin_username'] = admin.username
            session['admin_role'] = admin.role
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Nom d\'utilisateur ou mot de passe invalide.')

    return render_template('admin_login.html')

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    # Récupérer les candidats en attente de validation
    pending_candidates = Candidate.query.filter_by(is_validated=False).order_by(Candidate.date_candidature.asc()).all()
    # Récupérer les 5 derniers votants inscrits
    recent_voters = Voter.query.order_by(Voter.date_inscription.desc()).limit(5).all()
    # Récupérer les informations sur la chaîne
    chain_length = Block.query.count()
    total_votes = Block.query.filter_by(type='VOTE').count()
    status_data = get_election_status()
    
    # Statistiques supplémentaires
    total_voters = Voter.query.count()
    voters_who_voted = Voter.query.filter_by(has_voted=True).count()
    validated_candidates_count = Candidate.query.filter_by(is_validated=True).count()
    
    stats = {
        'chain_length': chain_length,
        'total_votes': total_votes,
        'total_voters': total_voters,
        'voters_who_voted': voters_who_voted,
        'validated_candidates_count': validated_candidates_count
    }
    
    return render_template('admin_dashboard.html', 
                           admin_username=session.get('admin_username'),
                           pending_candidates=pending_candidates,
                           recent_voters=recent_voters,
                           status_data=status_data,
                           stats=stats)

@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@login_required
def admin_candidate_action(candidate_id):
    """API pour valider ou supprimer un candidat."""
    data = request.get_json()
    action = data.get('action')
    
    candidate = Candidate.query.filter_by(candidate_id=candidate_id).first()
    
    if not candidate:
        return jsonify({'error': 'Candidat introuvable.'}), 404

    try:
        if action == 'validate':
            candidate.is_validated = True
            db.session.commit()
            return jsonify({'success': f"Candidat {candidate.candidate_id} validé avec succès."}), 200
            
        elif action == 'delete':
            # Supprimer la photo
            if candidate.photo_filename:
                photo_path = os.path.join('static', 'uploads', candidate.photo_filename)
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            
            db.session.delete(candidate)
            db.session.commit()
            return jsonify({'success': f"Candidat {candidate.candidate_id} supprimé avec succès."}), 200
            
        else:
            return jsonify({'error': 'Action non reconnue.'}), 400

    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur d'action admin sur candidat: {e}")
        return jsonify({'error': 'Erreur serveur lors de l\'exécution de l\'action.'}), 500

@app.route('/api/admin/election_status', methods=['POST'])
@login_required
def admin_set_election_status():
    """API pour changer l'état de l'élection."""
    data = request.get_json()
    action = data.get('action') # start, pause, finish, results_show, results_hide
    
    status_data = get_election_status()
    
    new_status = {}
    
    try:
        if action == 'start' and status_data['status'] == 'PENDING':
            new_status = {'status': 'VOTING', 'start_time': datetime.now(timezone.utc).isoformat()}
            
        elif action == 'pause' and status_data['status'] == 'VOTING':
            new_status = {'status': 'PAUSED'}
            
        elif action == 'resume' and status_data['status'] == 'PAUSED':
            new_status = {'status': 'VOTING'}
            
        elif action == 'finish' and status_data['status'] in ['VOTING', 'PAUSED']:
            new_status = {'status': 'FINISHED', 'results_visible': True, 'end_time': datetime.now(timezone.utc).isoformat()}

        elif action == 'results_show' and status_data['status'] in ['VOTING', 'PAUSED', 'FINISHED']:
            new_status = {'results_visible': True}
            
        elif action == 'results_hide' and status_data['status'] in ['VOTING', 'PAUSED', 'FINISHED']:
            new_status = {'results_visible': False}
            
        else:
            return jsonify({'error': f"Transition d'état non autorisée pour l'action '{action}'."}), 400

        if new_status:
            save_election_status(new_status)
            return jsonify({'success': f"Statut de l'élection mis à jour. Nouvelle action: {action}."}), 200
            
        return jsonify({'error': 'Action non applicable dans l\'état actuel.'}), 400

    except Exception as e:
        logging.error(f"Erreur de changement de statut: {e}")
        return jsonify({'error': 'Erreur serveur lors de la mise à jour du statut.'}), 500

# --- Route de l'Explorateur Blockchain ---
@app.route('/explorer')
def explorer():
    """Affiche l'explorateur de la blockchain."""
    
    # Récupérer tous les blocs dans l'ordre
    full_chain = Block.query.order_by(Block.index.asc()).all()
    
    sanitized_chain = []
    
    for block in full_chain:
        # Conversion du modèle en dictionnaire
        sanitized_block = {
            'index': block.index,
            'timestamp': block.timestamp.isoformat(),
            'payload': json.loads(block.payload_json), # Déjà JSON ici
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce,
            'type': block.type
        }
        
        # Anonymiser les données sensibles pour l'affichage public
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            # Anonymiser l'ID du votant
            voter_id = sanitized_block['payload'].get('voter_id', 'N/A')
            anonymized_payload = sanitized_block['payload'].copy()
            # On conserve une partie de l'ID pour montrer que l'événement a eu lieu, mais on le tronque
            anonymized_payload['voter_id'] = f"ID_VOTANT ANONYMISÉ (Fin: {voter_id[-3:]})"
            # On conserve le candidat pour le comptage
            anonymized_payload['candidate_id'] = f"Candidat: {sanitized_block['payload'].get('candidate_id', 'N/A')}"
            # Ajouter un timestamp lisible
            anonymized_payload.pop('timestamp', None) # Supprimer l'ancien si présent
            anonymized_payload['date_block'] = sanitized_block.get('timestamp', 'N/A') 
            sanitized_block['payload'] = anonymized_payload
            
        # Anonymiser l'ID du votant lors de l'inscription pour l'événement (ID de 10 caractères)
        elif sanitized_block['type'] == 'VOTER_REGISTERED' and isinstance(sanitized_block['payload'], dict):
            sanitized_block['payload'] = sanitized_block['payload'].copy()
            # On conserve une partie de l'ID pour montrer que l'événement a eu lieu, mais on le tronque
            id_preview = sanitized_block['payload'].get('id_numerique', 'N/A')[:4] + '...'
            sanitized_block['payload']['id_numerique'] = f"ID_NUMÉ.: {id_preview}"
            # On masque le nom/prénom qui était aussi dans le payload
            sanitized_block['payload']['nom'] = 'NOM/PRÉNOM ANONYMISÉ'
            sanitized_block['payload']['prenom'] = 'NOM/PRÉNOM ANONYMISÉ'
            
        
        sanitized_chain.append(sanitized_block)
        
    return render_template('explorer_vote.html', blockchain_chain=sanitized_chain)


# --- Démarrage de l'Application ---
if __name__ == '__main__':
    # Initialisation des données locales (fichiers JSON) pour le développement
    load_data(ELECTION_STATUS_FILE, ELECTION_STATUS) # Assure que l'état de l'élection est chargé
    
    with app.app_context():
        # En mode développement, on peut forcer la création des tables si elles n'existent pas
        # db.create_all() 
        pass 
        
    app.run(debug=True)

# Pour Render, le démarrage se fait via gunicorn qui utilise le nom d'application 'app'
# si le fichier est nommé 'serveur_vote.py' et que la commande de démarrage est 'gunicorn serveur_vote:app'