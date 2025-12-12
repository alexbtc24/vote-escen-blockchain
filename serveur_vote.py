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

# NOUVEL IMPORT POUR LA BASE DE DONNÉES
from flask_sqlalchemy import SQLAlchemy 

# --- CONFIGURATION INITIALE SIMPLIFIÉE ---
app = Flask(__name__)
# Utilisez une clé secrète forte en production !
# La variable FLASK_SECRET_KEY sera lue depuis les variables d'environnement de Render
app.secret_key = os.environ.get('FLASK_SECRET_KEY', str(uuid4())) 

# --- NOUVELLE CONFIGURATION POUR POSTGRESQL AVEC FLASK-SQLALCHEMY ---
# La variable DATABASE_URL sera lue depuis les variables d'environnement de Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
# Désactiver le suivi des modifications pour économiser des ressources
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 

db = SQLAlchemy(app) # Initialisation de SQLAlchemy
# ------------------------------------------------------------------

# --- CORRECTION DE L'ERREUR JINJA : CONTEXTE-PROCESSEUR ---
@app.context_processor
def inject_datetime():
    """Rend l'objet datetime disponible dans tous les templates Jinja2."""
    return {'datetime': datetime}
# ------------------------------------------------------------------

# Remplacement de l'ancien DATA_DIR et des fichiers, l'application utilise maintenant la DB
DATA_DIR = 'database' # Maintenu pour le dossier des photos
os.makedirs(DATA_DIR, exist_ok=True) 

# --- MODÈLES DE BASE DE DONNÉES ---

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(120), nullable=False)
    prenom = db.Column(db.String(120), nullable=False)
    parcours = db.Column(db.String(120), nullable=False)
    id_numerique = db.Column(db.String(50), unique=True, nullable=False)
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.String(50), unique=True, nullable=False) # L'ID UUID utilisé pour le vote
    name = db.Column(db.String(150), nullable=False)
    slogan = db.Column(db.String(500), nullable=True)
    programme = db.Column(db.Text, nullable=True)
    photo_path = db.Column(db.String(255), nullable=True)
    is_approved = db.Column(db.Boolean, default=False)
    vote_count = db.Column(db.Integer, default=0) 

class Block(db.Model):
    index = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    data = db.Column(db.Text, nullable=False) # JSON string of the transaction/action data
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    nonce = db.Column(db.Integer, default=0)

# -----------------------------------------------

# --- CONSTANTES ET FONCTIONS GLOBALES (Gardées de l'original) ---

# Paramètres de sécurité
PROOF_OF_WORK_PREFIX = '0000' # Exigence de 4 zéros pour un hash valide

# Utilisateurs Administrateurs par défaut (pour l'initialisation de la DB)
DEFAULT_ADMINS = {
    "admin_institution": "secure_password_hash",
}

# Configuration pour le téléchargement de photos
UPLOAD_FOLDER = os.path.join(DATA_DIR, 'candidate_photos')
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Fichier Excel pour le chargement des données (Gardé pour compatibilité si la fonctionnalité existe)
VOTERS_DEFAULT_FILE = 'voters_default.xlsx'
CANDIDATES_DEFAULT_FILE = 'candidates_default.xlsx' 

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- FONCTIONS DE BASE DE DONNÉES ET BLOCKCHAIN ---

def calculate_hash(block):
    """Calcule le hash SHA-256 pour un objet Block."""
    block_string = json.dumps({
        "index": block.index,
        "timestamp": block.timestamp.isoformat() if isinstance(block.timestamp, datetime) else block.timestamp,
        "data": block.data,
        "previous_hash": block.previous_hash,
        "nonce": block.nonce
    }, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()

def create_block(data, previous_hash, nonce=0):
    """Crée un nouvel objet Block."""
    # Utilise Block.query.count() pour déterminer l'index du nouveau bloc
    index = db.session.query(Block).count() + 1
    new_block = Block(
        index=index,
        timestamp=datetime.now(timezone.utc),
        data=json.dumps(data), # S'assurer que les données sont stockées en JSON string
        previous_hash=previous_hash,
        nonce=nonce
    )
    # Recalculer le hash ici car le timestamp est fixé
    new_block.hash = calculate_hash(new_block)
    return new_block

def get_latest_block():
    """Récupère le dernier bloc de la chaîne (Block object)."""
    return db.session.query(Block).order_by(Block.index.desc()).first()

def mine_block(data):
    """Ajoute un nouveau bloc à la chaîne via PoW."""
    last_block = get_latest_block()
    previous_hash = last_block.hash if last_block else '0' # Gestion du cas Genesis

    nonce = 0
    while True:
        new_block = create_block(data, previous_hash, nonce)
        
        if new_block.hash.startswith(PROOF_OF_WORK_PREFIX): 
            # Si la preuve est valide, on enregistre le bloc dans la base
            try:
                db.session.add(new_block)
                db.session.commit()
                logging.info(f"Bloc miné et ajouté à la DB. Index: {new_block.index}")
                return new_block
            except Exception as e:
                logging.error(f"Erreur lors de l'enregistrement du bloc dans la DB: {e}")
                db.session.rollback()
                return None # Échec
        
        nonce += 1
        # Limite de sécurité pour éviter une boucle infinie en cas de configuration trop difficile
        if nonce > 500000: 
             logging.error("Échec du minage: Nonce max atteint.")
             return None

def is_valid_chain():
    """Vérifie l'intégrité de la chaîne (hash, prev_hash, PoW)."""
    chain = db.session.query(Block).order_by(Block.index.asc()).all()
    
    if not chain:
        return False, "Chaîne vide."

    for i in range(1, len(chain)):
        current_block = chain[i]
        previous_block = chain[i-1]

        # 1. Vérification du hash
        if current_block.hash != calculate_hash(current_block):
            logging.error(f"Hash invalide pour le bloc #{current_block.index}")
            return False, f"Hash invalide pour le bloc #{current_block.index}"

        # 2. Vérification du lien
        if current_block.previous_hash != previous_block.hash:
            logging.error(f"Lien invalide pour le bloc #{current_block.index}")
            return False, f"Lien invalide pour le bloc #{current_block.index}"

        # 3. Vérification de la Preuve de Travail
        if not current_block.hash.startswith(PROOF_OF_WORK_PREFIX):
            logging.error(f"PoW invalide pour le bloc #{current_block.index}")
            return False, f"PoW invalide pour le bloc #{current_block.index}"

    return True, "Chaîne valide."

def calculate_results():
    """Calcule les résultats du vote en parcourant la blockchain."""
    # Récupérer les blocs de vote
    vote_blocks = db.session.query(Block).filter(Block.data.contains('"action": "VOTE"')).all()
    
    # Créer un dictionnaire de comptage des votes
    vote_counts = {}

    for block in vote_blocks:
        try:
            data = json.loads(block.data)
            candidate_id = data.get('candidate_id')
            if candidate_id:
                # Incrémenter le compteur
                vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
        except json.JSONDecodeError:
            logging.error(f"Erreur de décodage JSON dans le bloc {block.index}")
            continue

    total_votes = sum(vote_counts.values())
    
    # Récupérer tous les candidats approuvés
    candidates = Candidate.query.filter_by(is_approved=True).all()
    
    results = []
    
    for candidate in candidates:
        votes = vote_counts.get(candidate.candidate_id, 0)
        percentage = (votes / total_votes * 100) if total_votes > 0 else 0
        
        results.append({
            'candidate_id': candidate.candidate_id,
            'name': candidate.name,
            'photo_path': candidate.photo_path,
            'votes': votes,
            'percentage': round(percentage, 2)
        })

    # Trier par votes (décroissant)
    results.sort(key=lambda x: x['votes'], reverse=True)
    
    return results, total_votes

def init_db():
    """Initialise la base de données et les données par défaut."""
    with app.app_context():
        # Créer toutes les tables définies (AdminUser, Voter, Candidate, Block)
        db.create_all() 

        # 1. Initialisation des Administrateurs
        if not db.session.query(AdminUser).first():
            logging.info("Ajout des administrateurs par défaut...")
            for user, password in DEFAULT_ADMINS.items():
                admin = AdminUser(username=user)
                admin.set_password(password)
                db.session.add(admin)
            db.session.commit()

        # 2. Initialisation de la Blockchain (Bloc Genesis)
        if not db.session.query(Block).first():
            logging.info("Création du bloc Genesis de la Blockchain...")
            # On ne passe pas par mine_block pour le Genesis pour des raisons de simplicité
            # Il est directement créé et enregistré
            genesis_block = create_block(data={'action': 'GENESIS_BLOCK_CREATED'}, previous_hash='0', nonce=0)
            genesis_block.hash = '0000' + 'a' * 60 # Hash trivial pour le Genesis
            db.session.add(genesis_block)
            db.session.commit()
            
        logging.info("Base de données initialisée ou déjà existante.")

# --- MIDDLEWARES/DECORATEURS (GARDÉS DE L'ORIGINAL) ---

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', error="Accès Administrateur requis."))
        return f(*args, **kwargs)
    return decorated_function

# État du vote (Simulation)
# NOTE: En production, cet état devrait être stocké dans la DB (par ex. dans une table `ElectionStatus`). 
# Pour respecter la non-modification des fonctionnalités existantes, je simule l'état ici.
ELECTION_STATUS = 'VOTING' # 'PENDING', 'VOTING', 'FINISHED'
RESULTS_VISIBLE = True # Faux pour masquer les résultats

# --- ROUTES (Adaptées à la Base de Données) ---

# --- Routes d'Affichage ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/results')
def results():
    status_message = "Vote en cours - Résultats en temps réel"
    if ELECTION_STATUS == 'PENDING':
        status_message = "Le vote n'a pas encore commencé."
    elif ELECTION_STATUS == 'FINISHED':
        status_message = "Le vote est terminé."

    if not RESULTS_VISIBLE:
        status_message = "Les résultats sont actuellement cachés par l'administration."
        return render_template('results.html', 
                               election_status=ELECTION_STATUS,
                               status_message=status_message,
                               total_votes=0,
                               results=None)

    results_data, total_votes = calculate_results()

    return render_template('results.html',
                           election_status=ELECTION_STATUS,
                           status_message=status_message,
                           total_votes=total_votes,
                           results=results_data)

@app.route('/results_final')
@admin_required
def results_final():
    # Cette route est accessible uniquement par l'admin (admin_required)
    
    # On force la visibilité et l'état à "FINISHED" pour cette page
    results_data, total_votes = calculate_results()
    
    # Trouver le gagnant
    winner = None
    if results_data:
        winner = results_data[0] # Le premier après le tri est le gagnant

    return render_template('results_final.html',
                           results=results_data,
                           total_votes=total_votes,
                           winner=winner)

@app.route('/explorer')
def explorer():
    # La logique de l'explorateur reste très similaire
    chain_is_valid, validation_message = is_valid_chain()
    
    # Construction de la chaîne pour l'affichage (similaire à l'original)
    blockchain_data = db.session.query(Block).order_by(Block.index.asc()).all()
    
    # Conversion des objets Block en dicts pour le template
    chain_for_template = []
    for block in blockchain_data:
        block_dict = {
            'index': block.index,
            'timestamp': block.timestamp.isoformat(),
            'data': block.data,
            'previous_hash': block.previous_hash,
            'hash': block.hash,
            'nonce': block.nonce
        }
        chain_for_template.append(block_dict)

    return render_template('explorer_vote.html', 
                           blockchain_chain=chain_for_template, 
                           is_valid=chain_is_valid, 
                           validation_message=validation_message)

# --- Routes d'Authentification / Accès ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
        
    error = request.args.get('error')
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = AdminUser.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Nom d'utilisateur ou mot de passe incorrect."

    return render_template('admin_login.html', error=error)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('index'))

@app.route('/voter_login', methods=['GET'])
def voter_login():
    return render_template('voter_login.html')

@app.route('/voting_page')
def voting_page():
    # Vérification d'une session ou d'un ID valide dans la session
    voter_id = session.get('voter_id')
    if not voter_id:
        return redirect(url_for('voter_login'))

    voter = Voter.query.filter_by(id_numerique=voter_id).first()
    
    if not voter or voter.has_voted:
        # Si déjà voté ou ID invalide, on affiche une page d'erreur
        return render_template('error_page.html', message="Vous avez déjà voté ou votre ID est invalide.")
        
    if ELECTION_STATUS != 'VOTING':
        return render_template('error_page.html', message="Le vote est actuellement clos.")

    # Récupérer les candidats approuvés
    candidates = Candidate.query.filter_by(is_approved=True).all()
    
    return render_template('voting_page.html', candidates=candidates, voter_id=voter_id)

# --- Routes d'Administration ---

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    # Récupérer les données de la DB
    all_voters = db.session.query(Voter).all()
    all_candidates = db.session.query(Candidate).all()
    
    # Statistiques simples
    total_voters = len(all_voters)
    voters_who_voted = len([v for v in all_voters if v.has_voted])
    
    pending_candidates = [c for c in all_candidates if not c.is_approved]
    approved_candidates = [c for c in all_candidates if c.is_approved]
    
    # Statut du système (utilisation des variables globales pour l'exemple)
    system_status = {
        'election_status': ELECTION_STATUS,
        'results_visible': RESULTS_VISIBLE,
        'blockchain_status': "Valide" if is_valid_chain()[0] else "INVALIDE (A vérifier!)"
    }

    return render_template('admin_dashboard.html', 
                           admin_username=session['admin_username'],
                           voters_list=all_voters,
                           pending_candidates=pending_candidates,
                           approved_candidates=approved_candidates,
                           system_status=system_status,
                           total_voters=total_voters,
                           voters_who_voted=voters_who_voted)

# --- Routes d'Auto-Inscription ---

@app.route('/self_register_student', methods=['GET'])
def self_register_student_get():
    # Simuler le chargement des parcours si nécessaire (si un fichier existe)
    parcours_list = ['M1 ESCEN', 'M2 ESCEN', 'B3 ESCEN'] 
    return render_template('self_register_student.html', parcours_list=parcours_list)

@app.route('/self_register_candidate', methods=['GET'])
def self_register_candidate_get():
    return render_template('self_register_candidate.html')

# --- API Routes (Adaptées à la Base de Données) ---

@app.route('/api/student/self_register', methods=['POST'])
def self_register_student_api():
    if ELECTION_STATUS != 'VOTING':
        return jsonify({'error': "L'inscription est fermée, le vote n'est pas en cours."}), 400

    data = request.get_json()
    nom = data.get('nom', '').strip().upper()
    prenom = data.get('prenom', '').strip().capitalize()
    parcours = data.get('parcours', '').strip()
    
    if not all([nom, prenom, parcours]):
        return jsonify({'error': 'Tous les champs sont requis.'}), 400
        
    # Vérification d'éligibilité (simulée ici, pourrait être une vérification DB/CSV plus complexe)
    # Dans une version réelle, il faudrait vérifier dans une liste principale
    
    # Vérifier si un étudiant avec ce nom/prénom/parcours existe déjà (simple)
    existing_voter = Voter.query.filter_by(nom=nom, prenom=prenom, parcours=parcours).first()
    if existing_voter:
        return jsonify({'error': 'Un ID a déjà été généré pour cet étudiant.'}), 400
        
    # Vérifier si l'ID a déjà été généré (si l'algo d'ID est prévisible)
    
    # Génération de l'ID numérique (UUID tronqué pour l'exemple)
    id_numerique = str(uuid4()).replace('-', '')[:10].upper()
    
    # Création du nouvel électeur dans la base de données
    new_voter = Voter(
        nom=nom,
        prenom=prenom,
        parcours=parcours,
        id_numerique=id_numerique,
        has_voted=False
    )
    
    try:
        db.session.add(new_voter)
        db.session.commit()
        
        # Enregistrement de l'événement dans la blockchain
        mine_block(data={
            'action': 'VOTER_REGISTERED',
            'id_numerique': id_numerique,
            'nom': nom, # Le nom et prénom seront anonymisés dans l'explorateur
            'prenom': prenom,
            'parcours': parcours
        })
        
        return jsonify({'success': True, 'id_numerique': id_numerique}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur lors de l'enregistrement de l'étudiant: {e}")
        return jsonify({'error': "Erreur interne lors de l'enregistrement."}), 500

@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate_api():
    if ELECTION_STATUS != 'VOTING':
        return jsonify({'error': "L'inscription est fermée, le vote n'est pas en cours."}), 400

    # Utilisation de request.form pour les champs de texte et request.files pour le fichier
    name = request.form.get('name', '').strip()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    photo_file = request.files.get('photo')

    if not all([name, slogan, programme, photo_file]):
        return jsonify({'error': 'Tous les champs (y compris la photo) sont requis.'}), 400
        
    # 1. Gestion de la photo
    if photo_file and allowed_file(photo_file.filename):
        filename = secure_filename(photo_file.filename)
        # Utiliser un nom de fichier unique pour éviter les conflits
        unique_filename = f"{uuid4().hex}_{filename}"
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        photo_file.save(photo_path)
    else:
        return jsonify({'error': "Type de fichier photo non autorisé. Utilisez PNG, JPG ou JPEG."}), 400
        
    # 2. Génération de l'ID et enregistrement
    candidate_id = str(uuid4()).replace('-', '')[:10].upper()
    
    # Création du nouveau candidat dans la base de données (is_approved=False par défaut)
    new_candidate = Candidate(
        candidate_id=candidate_id,
        name=name,
        slogan=slogan,
        programme=programme,
        photo_path=photo_path,
        is_approved=False # En attente d'approbation
    )
    
    try:
        db.session.add(new_candidate)
        db.session.commit()
        
        # Enregistrement de l'événement dans la blockchain
        mine_block(data={
            'action': 'CANDIDATE_REGISTERED',
            'candidate_id': candidate_id,
            'name': name,
            # N'incluez pas le programme complet ni le slogan dans la blockchain pour des raisons de taille/lisibilité
        })
        
        return jsonify({'success': True, 'candidate_id': candidate_id}), 200
        
    except Exception as e:
        db.session.rollback()
        # Supprimer le fichier si l'enregistrement DB échoue
        if os.path.exists(photo_path):
            os.remove(photo_path)
        logging.error(f"Erreur lors de l'enregistrement du candidat: {e}")
        return jsonify({'error': "Erreur interne lors de l'enregistrement de la candidature."}), 500

@app.route('/api/voter/login', methods=['POST'])
def voter_login_api():
    if ELECTION_STATUS != 'VOTING':
        return jsonify({'error': "Le vote est actuellement clos."}), 400

    data = request.get_json()
    id_numerique = data.get('id_numerique', '').strip().upper()
    
    voter = Voter.query.filter_by(id_numerique=id_numerique).first()
    
    if not voter:
        return jsonify({'error': "ID Numérique inconnu. Veuillez vous inscrire d'abord."}), 404

    if voter.has_voted:
        return jsonify({'error': "Vous avez déjà exercé votre droit de vote."}), 403
        
    # Connexion réussie, stockage de l'ID dans la session
    session['voter_id'] = id_numerique
    
    return jsonify({'success': True, 'redirect_url': url_for('voting_page')}), 200

@app.route('/api/voter/vote', methods=['POST'])
def voter_vote_api():
    if ELECTION_STATUS != 'VOTING':
        return jsonify({'error': "Le vote est actuellement clos."}), 400
        
    voter_id_session = session.get('voter_id')
    if not voter_id_session:
        return jsonify({'error': "Session de vote invalide. Veuillez vous reconnecter."}), 403

    data = request.get_json()
    candidate_id = data.get('candidate_id', '').strip().upper()
    voter_id = data.get('voter_id', '').strip().upper()

    if voter_id != voter_id_session:
        return jsonify({'error': "Incohérence des IDs de vote. Tentative de fraude détectée."}), 403
        
    # Vérification du votant
    voter = Voter.query.filter_by(id_numerique=voter_id).first()
    if not voter or voter.has_voted:
        return jsonify({'error': "Vous avez déjà voté ou cet ID est invalide."}), 403
        
    # Vérification du candidat
    candidate = Candidate.query.filter_by(candidate_id=candidate_id, is_approved=True).first()
    if not candidate:
        return jsonify({'error': "Candidat sélectionné invalide ou non approuvé."}), 404
        
    # 1. Enregistrement du vote sur la blockchain (via minage)
    vote_data = {
        'action': 'VOTE',
        'voter_id': voter_id, # Cet ID est stocké pour l'intégrité mais sera anonymisé dans l'explorateur
        'candidate_id': candidate_id
    }
    
    new_block = mine_block(vote_data)
    
    if new_block is None:
        return jsonify({'error': "Échec de l'enregistrement du vote (minage échoué)."}), 500

    # 2. Mise à jour du statut du votant dans la DB
    try:
        voter.has_voted = True
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur lors de la mise à jour du statut du votant: {e}")
        # L'intégrité de la blockchain est prioritaire, mais on log l'erreur DB
        return jsonify({'error': "Erreur interne post-vote. Contactez l'admin."}), 500
        
    # 3. Supprimer l'ID de session pour empêcher le retour
    session.pop('voter_id', None)
    
    return jsonify({'success': True, 'block_index': new_block.index}), 200

# --- API d'Administration ---

@app.route('/api/admin/toggle_status', methods=['POST'])
@admin_required
def toggle_status():
    global ELECTION_STATUS, RESULTS_VISIBLE
    data = request.get_json()
    action = data.get('action')

    try:
        if action == 'start_vote':
            ELECTION_STATUS = 'VOTING'
            RESULTS_VISIBLE = True
            message = "Vote démarré et résultats visibles."
        elif action == 'pause_vote':
            ELECTION_STATUS = 'PENDING'
            message = "Vote mis en pause."
        elif action == 'end_vote':
            ELECTION_STATUS = 'FINISHED'
            message = "Vote terminé."
        elif action == 'show_results':
            RESULTS_VISIBLE = True
            message = "Résultats rendus visibles."
        elif action == 'hide_results':
            RESULTS_VISIBLE = False
            message = "Résultats cachés."
        else:
            return jsonify({'error': 'Action invalide.'}), 400

        # Enregistrement de l'action dans la blockchain (à l'exception de show/hide results)
        if action in ['start_vote', 'pause_vote', 'end_vote']:
            mine_block(data={'action': action.upper()})
        
        return jsonify({'success': message}), 200

    except Exception as e:
        logging.error(f"Erreur lors du changement de statut: {e}")
        return jsonify({'error': 'Erreur interne lors de la mise à jour du statut.'}), 500

@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@admin_required
def candidate_action(candidate_id):
    data = request.get_json()
    action = data.get('action')

    candidate = Candidate.query.filter_by(candidate_id=candidate_id).first()
    if not candidate:
        return jsonify({'error': 'Candidat introuvable.'}), 404

    try:
        if action == 'validate':
            candidate.is_approved = True
            db.session.commit()
            
            mine_block(data={'action': 'CANDIDATE_APPROVED', 'candidate_id': candidate_id})
            message = f"Candidat {candidate.name} validé avec succès."
            
        elif action == 'delete':
            # Supprimer la photo
            if candidate.photo_path and os.path.exists(candidate.photo_path):
                os.remove(candidate.photo_path)
                
            db.session.delete(candidate)
            db.session.commit()
            
            mine_block(data={'action': 'CANDIDATE_DELETED', 'candidate_id': candidate_id})
            message = f"Candidat {candidate.name} supprimé avec succès."
            
        else:
            return jsonify({'error': 'Action invalide.'}), 400

        return jsonify({'success': message}), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Erreur lors de l'action sur le candidat: {e}")
        return jsonify({'error': 'Erreur interne lors de l\'opération.'}), 500

# --- COMMANDES CLI POUR LE DÉPLOIEMENT ---

@app.cli.command("initdb")
def initdb_command():
    """Crée les tables de la base de données et insère les données initiales (Admin, Genesis)."""
    init_db()
    print("Base de données initialisée avec succès.")

# Pour Render, vous utiliserez 'gunicorn serveur_vote:app' comme commande de démarrage
# et 'python serveur_vote.py initdb' comme Build Command ou une commande séparée pour l'initialisation.

if __name__ == '__main__':
    # Initialisation de la base de données (pour le développement local)
    init_db() 
    # Le 'host=0.0.0.0' est essentiel pour le déploiement sur Render ou Docker
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5000))