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

# --- AJOUTS ET MODIFICATIONS POUR LA BASE DE DONNÉES (CORRECTION DU DÉPLOIEMENT) ---
# Importations nécessaires pour SQLAlchemy et les commandes SQL brutes
from flask_sqlalchemy import SQLAlchemy 
from sqlalchemy import text 
# ----------------------------------------------------------------------------------

import pandas as pd # NOUVEL IMPORT NÉCESSAIRE (pip install pandas openpyxl)
import tempfile # NOUVEL IMPORT: Pour une gestion sécurisée et multi-OS des fichiers temporaires

# --- CONFIGURATION INITIALE SIMPLIFIÉE ---
app = Flask(__name__)
# Utilisez une clé secrète forte en production !
app.secret_key = os.environ.get('FLASK_SECRET_KEY', str(uuid4())) 

# --- CONFIGURATION BASE DE DONNÉES (AJOUTÉ POUR GÉRER L'ERREUR DE DÉPLOIEMENT) ---
# Utilisation de la variable d'environnement de Render pour la DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
# Désactiver le suivi de modification de SQLAlchemy (bonne pratique)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)
# ----------------------------------------------------------------------------------

# --- CORRECTION DE L'ERREUR JINJA : CONTEXTE-PROCESSEUR ---
@app.context_processor
def inject_datetime():
    """Rend l'objet datetime disponible dans tous les templates Jinja2."""
    return {'datetime': datetime}
# ------------------------------------------------------------------

DATA_DIR = 'database'
os.makedirs(DATA_DIR, exist_ok=True)

# Fichiers (Conservés pour la logique de sauvegarde/chargement des autres données)
VOTERS_FILE = os.path.join(DATA_DIR, 'voters.json') 
CANDIDATES_FILE = os.path.join(DATA_DIR, 'candidates.json')
VOTE_CHAIN_FILE = os.path.join(DATA_DIR, 'vote_chain.json')
ADMIN_USERS_FILE = os.path.join(DATA_DIR, 'admin_users.json')
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
ELIGIBILITY_LIST_FILE = os.path.join(DATA_DIR, 'eligibility_list.json') # NOUVEAU FICHIER

CANDIDATE_IMAGES_DIR = 'static/candidate_images'
os.makedirs(CANDIDATE_IMAGES_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- UTILS DONNÉES ---
def load_data(filepath, default_data):
    # Logique de chargement des fichiers JSON (pour les données non-DB)
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content: return default_data
                return json.loads(content)
        save_data(filepath, default_data)
        return default_data
    except Exception:
        return default_data

def save_data(filepath, data):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Erreur sauvegarde {filepath}: {e}")

def sha256(s):
    # CORRECTION DE L'ERREUR 'heigest' -> 'hexdigest'
    # Ajout du .lower() pour standardiser le hash
    return hashlib.sha256(s.lower().encode('utf-8')).hexdigest()

def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée pour Excel."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ['xlsx', 'xls']

# Initialisation et Défauts SIMPLIFIÉS
DEFAULT_ADMINS = {
    'admin': {'hash': generate_password_hash('escenpass'), 'label': 'Administrateur Unique'} 
}
# NOTE: Ces variables globales sont désormais des fallbacks/caches si le DB n'est pas utilisé
# La logique DB est désormais prioritaire pour AdminUser et Block.
ADMIN_USERS = load_data(ADMIN_USERS_FILE, DEFAULT_ADMINS) 

VOTERS = load_data(VOTERS_FILE, {}) 
CANDIDATES = load_data(CANDIDATES_FILE, {})
ELIGIBILITY_LIST = load_data(ELIGIBILITY_LIST_FILE, {}) # CHARGEMENT NOUVEAU

DEFAULT_SETTINGS = {
    'candidacy_open': False,  # NOUVEAU: Pour la gestion de l'inscription candidat
    'election_status': 'SETUP', # SETUP, VOTING, CLOSED
    'voting_status': 'CLOSED',  # OPEN/CLOSED (contrôlé par l'admin)
    'results_visibility': 'HIDDEN' # VISIBLE/HIDDEN (contrôlé par l'admin)
}
SETTINGS = load_data(SETTINGS_FILE, DEFAULT_SETTINGS)

def get_settings():
    """Charge les paramètres et les met à jour si nécessaire."""
    global SETTINGS
    # On charge toujours les dernières données pour éviter les conflits
    SETTINGS = load_data(SETTINGS_FILE, DEFAULT_SETTINGS) 
    return SETTINGS

# --- MODÈLES DE BASE DE DONNÉES (NÉCESSAIRE POUR db.create_all()) ---
class AdminUser(db.Model):
    __tablename__ = 'admin_user'
    # Utilisation d'un VARCHAR(128) pour corriger la précédente erreur de schéma
    username = db.Column(db.String(128), primary_key=True)
    password_hash = db.Column(db.String(256), nullable=False)
    label = db.Column(db.String(100), nullable=True)

class Block(db.Model):
    __tablename__ = 'block'
    # Ajout d'une colonne ID pour corriger l'erreur "column block.id does not exist"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True) 
    index = db.Column(db.Integer, unique=True, nullable=False) 
    timestamp = db.Column(db.String(64), nullable=False)
    payload_json = db.Column(db.Text, nullable=False) # Le contenu réel du vote/événement
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    nonce = db.Column(db.Integer, default=1)
    type = db.Column(db.String(50))
    
    def __repr__(self):
        return f"<Block {self.index}>"
# -------------------------------------------------------------------


# --- BLOCKCHAIN ---
class Blockchain:
    def __init__(self):
        # Utilisation du modèle DB si disponible, sinon fallback JSON
        with app.app_context():
            if Block.query.count() > 0:
                self.chain = [self._block_to_dict(b) for b in Block.query.order_by(Block.index).all()]
            else:
                self.chain = load_data(VOTE_CHAIN_FILE, [])
        
        self.current_votes = []
        if not self.chain:
            # Assure que le bloc Genesis est créé
            self.create_block(proof=1, previous_hash='0', type="GENESIS", payload={"msg": "Lancement Réseau"})

    def _block_to_dict(self, block_model):
        """Convertit un objet modèle Block en dictionnaire."""
        return {
            'index': block_model.index,
            'timestamp': block_model.timestamp,
            'type': block_model.type,
            'payload': json.loads(block_model.payload_json), # Dé-sérialiser
            'proof': block_model.nonce, # Renommé en nonce dans le modèle
            'previous_hash': block_model.previous_hash,
            'hash': block_model.hash,
        }

    def _save_block(self, block_dict):
        """Sauvegarde le bloc dans la DB et dans le fichier JSON (pour la cohérence/backup)."""
        with app.app_context():
            new_block = Block(
                index=block_dict['index'],
                timestamp=block_dict['timestamp'],
                type=block_dict['type'],
                payload_json=json.dumps(block_dict['payload'], sort_keys=True), # Sérialiser
                previous_hash=block_dict['previous_hash'],
                hash=block_dict['hash'],
                nonce=block_dict['proof']
            )
            db.session.add(new_block)
            db.session.commit()
        
        # Sauvegarde JSON (Fallback/cohérence si l'application est hybride)
        save_data(VOTE_CHAIN_FILE, self.chain) 

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def create_block(self, proof, previous_hash, type="VOTE", payload=None):
        last_block_hash = self.last_block['hash'] if self.last_block else '0' 
        
        block = {
            'index': len(self.chain) + 1,
            # CORRECTION DATE: Utiliser isoformat() pour un format standard
            'timestamp': datetime.now(timezone.utc).isoformat(), 
            'type': type, 
            'payload': payload if payload is not None else self.current_votes,
            'proof': proof,
            'previous_hash': previous_hash or last_block_hash, 
        }
        self.current_votes = []
        
        # Le hash doit être calculé sur le contenu sérialisé et trié
        block['hash'] = sha256(json.dumps(block, sort_keys=True))
        
        self.chain.append(block)
        self._save_block(block) # Appel de la nouvelle fonction de sauvegarde
        return block

    def add_event(self, type, payload):
        return self.create_block(proof=1, previous_hash=None, type=type, payload=payload)

    # Le reste des méthodes (mine, is_valid_chain, etc.) si elles existent doivent être conservées ici.
# FIN DE LA CLASSE BLOCKCHAIN
# ----------------------------------------------------------------------------------

# Initialisation de la blockchain
blockchain = Blockchain()

# --- DÉCORATEURS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ADMINISTRATION ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with app.app_context():
            # Utilisation du modèle DB
            admin_user = AdminUser.query.get(username)

        if admin_user and check_password_hash(admin_user.password_hash, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            blockchain.add_event("ADMIN_LOGIN", {"user": username, "status": "SUCCESS"})
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Nom d\'utilisateur ou mot de passe incorrect.'
            blockchain.add_event("ADMIN_LOGIN", {"user": username, "status": "FAILURE"})

    return render_template('admin_login.html', error=error)

@app.route('/admin_logout')
@admin_required
def admin_logout():
    username = session.pop('admin_username', 'Inconnu')
    session.pop('admin_logged_in', None)
    blockchain.add_event("ADMIN_LOGOUT", {"user": username})
    return redirect(url_for('admin_login'))

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    # Logique pour le dashboard (conservation des données non-DB)
    settings = get_settings()
    
    # Prépare les données pour le template
    total_eligible = len(ELIGIBILITY_LIST)
    eligible_count = len([k for k, v in ELIGIBILITY_LIST.items() if not v.get('used', False)])
    
    candidates_validated = [c for c in CANDIDATES.values() if c.get('is_validated')]
    total_students_voters = len(VOTERS)
    total_students_voted = len([v for v in VOTERS.values() if v.get('has_voted')])
    total_votes = len([b for b in blockchain.chain if b['type'] == 'VOTE']) # Utilise la chaîne en mémoire
    
    return render_template('admin_dashboard.html',
        admin_username=session.get('admin_username'),
        settings=settings,
        total_eligible=total_eligible,
        eligible_to_register=eligible_count,
        candidates_waiting=len([c for c in CANDIDATES.values() if not c.get('is_validated')]),
        candidates_validated=len(candidates_validated),
        total_students_voters=total_students_voters,
        total_students_voted=total_students_voted,
        total_votes_cast=total_votes,
        CANDIDATES=CANDIDATES, 
    )

# --- NOUVELLE ROUTE POUR L'UPLOAD DE LA LISTE D'ÉLIGIBILITÉ (WHITELIST) ---
@app.route('/api/admin/upload_whitelist', methods=['POST'])
@admin_required
def upload_whitelist():
    global ELIGIBILITY_LIST, VOTERS
    
    if 'file' not in request.files:
        return jsonify({'error': 'Aucun fichier n\'a été envoyé.'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Aucun fichier sélectionné.'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Format de fichier non autorisé. Veuillez utiliser un fichier Excel (.xlsx, .xls).'}), 400
    
    # Utilisation d'un fichier temporaire pour la lecture sécurisée
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        file.save(temp_file.name)
        temp_path = temp_file.name

    try:
        df = pd.read_excel(temp_path, sheet_name=0)
    except Exception as e:
        os.remove(temp_path)
        return jsonify({'error': f"Erreur de lecture du fichier Excel: {e}"}), 400

    new_eligibility_list = {}
    expected_columns = ['NOM', 'PRENOM', 'PARCOURS']
    
    # Vérification des colonnes
    if not all(col in df.columns for col in expected_columns):
        os.remove(temp_path)
        missing = [col for col in expected_columns if col not in df.columns]
        return jsonify({'error': f"Colonnes manquantes dans le fichier. Assurez-vous d'avoir: {', '.join(expected_columns)}. Manquant: {', '.join(missing)}"}), 400

    # Normalisation et traitement des données
    for index, row in df.iterrows():
        try:
            # Nettoyage et standardisation
            nom = str(row['NOM']).strip().upper()
            prenom = str(row['PRENOM']).strip().title()
            parcours = str(row['PARCOURS']).strip().upper()
            
            if not nom or not prenom or not parcours:
                continue # Ignore les lignes incomplètes
                
            # Création de la clé unique (hash sur les données d'éligibilité)
            eligibility_key = sha256(f"{nom}_{prenom}_{parcours}")
            
            # Stockage des données d'éligibilité (sans l'ID numérique)
            new_eligibility_list[eligibility_key] = {
                'nom': nom,
                'prenom': prenom,
                'parcours': parcours,
                'used': False # Flag pour indiquer si un ID numérique a été généré
            }
        except Exception as e:
            logger.warning(f"Ligne {index+2} ignorée: {e}")
            
    if not new_eligibility_list:
        os.remove(temp_path)
        return jsonify({'error': "Aucune entrée d'éligibilité valide n'a été trouvée dans le fichier."}), 400

    # Mise à jour et sauvegarde des listes
    ELIGIBILITY_LIST = new_eligibility_list
    save_data(ELIGIBILITY_LIST_FILE, ELIGIBILITY_LIST)
    
    # Réinitialisation des Votants (car la liste d'éligibilité a changé, réinitialisation du vote)
    VOTERS = {}
    save_data(VOTERS_FILE, VOTERS)
    
    # Enregistrement de l'événement dans la Blockchain
    blockchain.add_event("WHITELIST_UPDATE", {"count": len(ELIGIBILITY_LIST), "user": session.get('admin_username')})
    
    # Suppression du fichier temporaire
    os.remove(temp_path)
    
    return jsonify({
        'success': f"Liste d'éligibilité importée avec succès. {len(ELIGIBILITY_LIST)} étudiants éligibles ajoutés. Les votants inscrits ont été réinitialisés.",
        'total_eligible': len(ELIGIBILITY_LIST)
    })

# ROUTE pour gérer le statut de l'élection
@app.route('/api/admin/toggle_setting', methods=['POST'])
@admin_required
def toggle_setting():
    data = request.get_json()
    action = data.get('action')
    settings = get_settings()

    message = ""
    
    if action == 'toggle_candidacy':
        new_status = not settings['candidacy_open']
        settings['candidacy_open'] = new_status
        status_msg = "OUVERT" if new_status else "FERMÉ"
        blockchain.add_event("CANDIDACY_STATUS_CHANGE", {"status": status_msg, "user": session.get('admin_username')})
        message = f"Le statut de l'ouverture des candidatures est maintenant : {status_msg}."
        
    elif action == 'start_voting':
        if settings['election_status'] == 'SETUP' and settings['voting_status'] == 'CLOSED':
            settings['election_status'] = 'VOTING'
            settings['voting_status'] = 'OPEN'
            settings['results_visibility'] = 'VISIBLE'
            blockchain.add_event("ELECTION_START", {"user": session.get('admin_username')})
            message = "L'élection est maintenant en cours (STATUT VOTING). Les votes sont OUVERTS et les résultats VISIBLES."
        else:
            return jsonify({'error': "L'élection est déjà en cours ou n'est pas en phase SETUP."}), 400

    elif action == 'close_voting':
        if settings['election_status'] == 'VOTING' and settings['voting_status'] == 'OPEN':
            settings['voting_status'] = 'CLOSED'
            blockchain.add_event("VOTING_CLOSED", {"user": session.get('admin_username')})
            message = "Le vote est maintenant FERMÉ. Les utilisateurs ne peuvent plus voter."
        else:
            return jsonify({'error': "Le vote n'est pas actuellement ouvert."}), 400

    elif action == 'finalize_election':
        if settings['election_status'] == 'VOTING' and settings['voting_status'] == 'CLOSED':
            settings['election_status'] = 'CLOSED'
            settings['results_visibility'] = 'VISIBLE' # Force visible à la fin
            blockchain.add_event("ELECTION_FINALIZED", {"user": session.get('admin_username')})
            message = "L'élection est définitivement FINALISÉE. Les résultats sont désormais définitifs."
        else:
            return jsonify({'error': "L'élection doit être en statut 'VOTING' et le vote 'CLOSED' pour être finalisée."}), 400

    elif action == 'toggle_results_visibility':
        new_visibility = 'VISIBLE' if settings['results_visibility'] == 'HIDDEN' else 'HIDDEN'
        settings['results_visibility'] = new_visibility
        visibility_msg = "VISIBLES" if new_visibility == 'VISIBLE' else "CACHÉS"
        blockchain.add_event("RESULTS_VISIBILITY_CHANGE", {"status": new_visibility, "user": session.get('admin_username')})
        message = f"Les résultats sont maintenant {visibility_msg}."
    
    else:
        return jsonify({'error': "Action non reconnue."}), 400

    save_data(SETTINGS_FILE, settings) # Sauvegarde des changements de SETTINGS
    return jsonify({'success': message, 'settings': settings})

# ROUTE pour valider ou supprimer un candidat
@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@admin_required
def candidate_action(candidate_id):
    global CANDIDATES
    candidate = CANDIDATES.get(candidate_id)
    if not candidate:
        return jsonify({'error': 'Candidat non trouvé.'}), 404

    data = request.get_json()
    action = data.get('action')

    if action == 'validate':
        if not candidate.get('is_validated'):
            candidate['is_validated'] = True
            save_data(CANDIDATES_FILE, CANDIDATES)
            blockchain.add_event("CANDIDATE_VALIDATED", {"candidate_id": candidate_id, "user": session.get('admin_username')})
            return jsonify({'success': f"Candidat {candidate_id} validé avec succès."})
        return jsonify({'error': 'Candidat déjà validé.'}), 400

    elif action == 'delete':
        # Supprimer l'image si elle existe
        image_path = os.path.join(CANDIDATE_IMAGES_DIR, candidate.get('image_filename', ''))
        if os.path.exists(image_path):
            os.remove(image_path)
            
        del CANDIDATES[candidate_id]
        save_data(CANDIDATES_FILE, CANDIDATES)
        blockchain.add_event("CANDIDATE_DELETED", {"candidate_id": candidate_id, "user": session.get('admin_username')})
        return jsonify({'success': f"Candidat {candidate_id} supprimé avec succès."})

    return jsonify({'error': 'Action non reconnue.'}), 400

# --- ROUTES UTILISATEURS / VOTE ---

# Page d'accueil (Préservation de l'original)
@app.route('/')
def index():
    settings = get_settings()
    # Ajout du statut de l'élection à la page d'accueil
    return render_template('index.html', election_status=settings['election_status'])

# Page d'auto-inscription (GET)
@app.route('/self_register_student', methods=['GET'])
def self_register_student_get():
    settings = get_settings()
    if settings['election_status'] != 'SETUP':
        return render_template('error_page.html', message="L'inscription des votants est terminée. Veuillez contacter l'administration."), 403
    return render_template('self_register_student.html', election_status=settings['election_status'])

# API d'auto-inscription (POST)
@app.route('/api/student/self_register', methods=['POST'])
def self_register_student_post():
    global VOTERS, ELIGIBILITY_LIST
    settings = get_settings()

    if settings['election_status'] != 'SETUP':
        return jsonify({'error': "L'inscription est fermée. Veuillez contacter l'administration."}), 403

    data = request.get_json()
    nom = data.get('nom', '').strip().upper()
    prenom = data.get('prenom', '').strip().title()
    parcours = data.get('parcours', '').strip().upper()

    if not all([nom, prenom, parcours]):
        return jsonify({'error': "Tous les champs sont obligatoires."}), 400

    # 1. Vérification de l'éligibilité (Whitelist)
    eligibility_key = sha256(f"{nom}_{prenom}_{parcours}")
    eligibility_entry = ELIGIBILITY_LIST.get(eligibility_key)

    if not eligibility_entry:
        return jsonify({'error': "Vos informations ne correspondent à aucun étudiant éligible dans la liste."}), 403

    if eligibility_entry.get('used'):
        # On peut rechercher l'ID numérique associé pour l'afficher à l'utilisateur
        for voter in VOTERS.values():
            if voter.get('eligibility_key') == eligibility_key:
                return jsonify({'error': f"Vous êtes déjà inscrit. Votre ID Numérique est: {voter['id_numerique']}. Notez-le bien."}), 409
        # Si on ne le trouve pas, on continue l'erreur générique
        return jsonify({'error': "Vous êtes déjà inscrit. Contactez l'administration si vous avez perdu votre ID."}), 409


    # 2. Génération de l'ID numérique du votant
    unique_id_source = f"{eligibility_key}_{uuid4()}" 
    # Tronquer aux 10 premiers caractères du hash SHA256 pour respecter la limite
    id_numerique = sha256(unique_id_source)[:10] 

    # 3. Enregistrement du Votant
    VOTERS[id_numerique] = {
        'id_numerique': id_numerique,
        'eligibility_key': eligibility_key,
        'has_voted': False,
        # Utilisation du format ISO standard corrigé
        'registration_time': datetime.now(timezone.utc).isoformat(), 
        # On stocke les infos pour faciliter l'admin/debug, mais la clé d'éligibilité suffit
        'nom': nom,
        'prenom': prenom,
        'parcours': parcours
    }
    
    # 4. Marquage dans la liste d'éligibilité comme 'used'
    eligibility_entry['used'] = True 
    
    save_data(VOTERS_FILE, VOTERS)
    save_data(ELIGIBILITY_LIST_FILE, ELIGIBILITY_LIST)

    # 5. Enregistrement de l'événement dans la Blockchain
    blockchain.add_event("VOTER_REGISTERED", {
        "id_numerique": id_numerique, # Sera anonymisé dans l'explorateur
        "eligibility_key_hash": eligibility_key, # Peut servir pour audit
        "nom": nom,
        "prenom": prenom,
        "parcours": parcours
    })

    return jsonify({
        'success': "Inscription réussie.",
        'id_numerique': id_numerique
    })

# --- AUTO-INSCRIPTION CANDIDAT ---

# Page d'auto-inscription (GET)
@app.route('/self_register_candidate', methods=['GET'])
def self_register_candidate_get():
    settings = get_settings()
    if not settings['candidacy_open']:
        return render_template('error_page.html', message="L'appel à candidatures est actuellement fermé."), 403
    return render_template('self_register_candidate.html')

# API d'auto-inscription (POST)
@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate_post():
    global CANDIDATES
    settings = get_settings()

    if not settings['candidacy_open']:
        return jsonify({'error': "L'appel à candidatures est fermé."}), 403

    # Récupération des données du formulaire multipart/form-data
    nom = request.form.get('nom', '').strip().upper()
    prenom = request.form.get('prenom', '').strip().title()
    parcours = request.form.get('parcours', '').strip().upper()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    image_file = request.files.get('image')

    if not all([nom, prenom, parcours, slogan, programme, image_file]):
        return jsonify({'error': "Tous les champs, y compris l'image, sont obligatoires."}), 400

    # Vérification des limites de mots (conservation des règles strictes)
    slogan_word_count = len(slogan.split())
    programme_word_count = len(programme.split())
    
    if slogan_word_count > 100:
        return jsonify({'error': "Le Slogan ne doit pas dépasser 100 mots."}), 400
    if programme_word_count < 300:
        return jsonify({'error': "Le Programme/Objectifs doit contenir au moins 300 mots."}), 400

    # Vérification anti-doublon (simple par nom+prénom+parcours)
    check_key = sha256(f"{nom}_{prenom}_{parcours}")
    for cid, cand in CANDIDATES.items():
        existing_key = sha256(f"{cand['nom']}_{cand['prenom']}_{cand['parcours']}")
        if existing_key == check_key:
            return jsonify({'error': "Vous êtes déjà enregistré comme candidat. Veuillez attendre la validation."}), 409

    # Traitement de l'image
    if not image_file or not image_file.filename:
        return jsonify({'error': "L'image du candidat est obligatoire."}), 400
        
    filename = secure_filename(image_file.filename)
    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if extension not in ['png', 'jpg', 'jpeg']:
        return jsonify({'error': "Format d'image non supporté. Utilisez PNG ou JPG/JPEG."}), 400

    # Génération d'un ID de candidat unique (basé sur un UUID)
    candidate_id = str(uuid4())
    image_filename = f"{candidate_id}.{extension}"
    image_path = os.path.join(CANDIDATE_IMAGES_DIR, image_filename)

    try:
        image_file.save(image_path)
    except Exception as e:
        return jsonify({'error': f"Échec de l'enregistrement de l'image : {e}"}), 500

    # Enregistrement du candidat
    CANDIDATES[candidate_id] = {
        'id': candidate_id,
        'nom': nom,
        'prenom': prenom,
        'parcours': parcours,
        'slogan': slogan,
        'programme': programme,
        'image_filename': image_filename,
        'is_validated': False, # En attente de validation admin
        'registration_time': datetime.now(timezone.utc).isoformat()
    }

    save_data(CANDIDATES_FILE, CANDIDATES)

    # Enregistrement de l'événement
    blockchain.add_event("CANDIDATE_REGISTERED", {
        "candidate_id": candidate_id,
        "nom_prenom": f"{nom} {prenom}",
        "status": "AWAITING_VALIDATION"
    })

    return jsonify({
        'success': "Candidature enregistrée avec succès. En attente de validation.",
        'candidate_id': candidate_id
    })


# --- ACCÈS AU VOTE ---

@app.route('/voter_login', methods=['GET'])
def voter_login():
    settings = get_settings()
    # Le login est possible si SETUP ou VOTING
    if settings['election_status'] == 'CLOSED':
        return render_template('error_page.html', message="L'élection est terminée et le vote est fermé."), 403
        
    if settings['voting_status'] != 'OPEN':
        return render_template('error_page.html', message="Le vote est actuellement fermé par l'administration."), 403

    return render_template('voter_login.html')

@app.route('/api/voter/login', methods=['POST'])
def voter_api_login():
    settings = get_settings()
    if settings['voting_status'] != 'OPEN' or settings['election_status'] == 'CLOSED':
        return jsonify({'error': "Le vote est actuellement fermé ou l'élection est terminée."}), 403

    data = request.get_json()
    id_numerique = data.get('id_numerique', '').strip()

    voter = VOTERS.get(id_numerique)
    
    if not voter:
        return jsonify({'error': "ID Numérique invalide. Veuillez vérifier votre inscription."}), 401

    if voter.get('has_voted'):
        return jsonify({'error': "Vous avez déjà exercé votre droit de vote."}), 409

    # Stocker l'ID dans la session (authentification simple par ID)
    session['voter_id'] = id_numerique
    return jsonify({'success': 'Connexion réussie', 'redirect_url': url_for('voting_page')})

@app.route('/voting_page', methods=['GET'])
def voting_page():
    settings = get_settings()
    voter_id = session.get('voter_id')

    # Vérification du statut de l'élection et de la session
    if settings['voting_status'] != 'OPEN' or settings['election_status'] == 'CLOSED':
        return render_template('error_page.html', message="Le vote est actuellement fermé ou l'élection est terminée."), 403
    
    if not voter_id or voter_id not in VOTERS or VOTERS[voter_id].get('has_voted'):
        return redirect(url_for('voter_login'))

    # Récupérer la liste des candidats VALIDÉS
    validated_candidates = [c for c in CANDIDATES.values() if c.get('is_validated')]
    
    if not validated_candidates:
        return render_template('error_page.html', message="Aucun candidat validé n'est disponible pour le vote."), 404

    return render_template('voting_page.html', candidates=validated_candidates, voter_id=voter_id)

@app.route('/api/voter/cast_vote', methods=['POST'])
def cast_vote():
    global VOTERS
    settings = get_settings()
    data = request.get_json()
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')

    if settings['voting_status'] != 'OPEN' or settings['election_status'] == 'CLOSED':
        return jsonify({'error': "Le vote est fermé ou l'élection est terminée."}), 403

    voter = VOTERS.get(voter_id)
    candidate = CANDIDATES.get(candidate_id)

    if not voter or voter.get('has_voted'):
        return jsonify({'error': "Votant invalide ou a déjà voté."}), 409
    
    if not candidate or not candidate.get('is_validated'):
        return jsonify({'error': "Candidat invalide ou non validé."}), 404

    # 1. Enregistrement du vote dans le bloc courant
    vote_data = {
        # Utiliser le hash complet pour l'anonymisation
        'voter_key_hash': sha256(voter_id), 
        'candidate_id': candidate_id,
        'candidate_name': f"{candidate['prenom']} {candidate['nom']}",
        'vote_time': datetime.now(timezone.utc).isoformat()
    }
    
    # 2. Création du bloc de vote
    new_block = blockchain.add_event(type="VOTE", payload=vote_data)

    # 3. Marquer le votant comme ayant voté
    voter['has_voted'] = True
    voter['voted_for_candidate_id'] = candidate_id # Pour audit admin/dashboard
    save_data(VOTERS_FILE, VOTERS)
    
    # 4. Supprimer l'ID votant de la session
    session.pop('voter_id', None) 

    return jsonify({
        'success': 'Vote enregistré sur la Blockchain.',
        'block_index': new_block['index']
    })

# --- RÉSULTATS ET EXPLORATEUR ---

@app.route('/results')
def results():
    settings = get_settings()
    total_votes = len([b for b in blockchain.chain if b['type'] == 'VOTE'])
    
    if settings['election_status'] == 'CLOSED':
        # Afficher la page finale pour les résultats permanents
        return redirect(url_for('final_results'))
    
    if settings['results_visibility'] == 'HIDDEN':
        status_message = "Les résultats sont actuellement cachés par l'administration."
        return render_template('results.html',
            status_message=status_message, 
            election_status=settings['election_status'],
            total_votes=total_votes,
            results_data=None # Ne pas envoyer de données de résultats
        )

    # Calcul des résultats
    vote_counts = {}
    
    # 1. Compter les votes depuis la chaîne
    for block in blockchain.chain:
        if block['type'] == 'VOTE' and isinstance(block['payload'], dict):
            # Assurez-vous que l'index de vote correspond à l'index du bloc lui-même
            candidate_id = block['payload']['candidate_id']
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1

    # 2. Créer la structure des résultats
    results_data = []
    validated_candidates = {cid: c for cid, c in CANDIDATES.items() if c.get('is_validated')}
    
    for cid in validated_candidates:
        votes = vote_counts.get(cid, 0)
        percentage = (votes / total_votes * 100) if total_votes > 0 else 0
        
        results_data.append({
            'candidate_id': cid,
            'name': f"{validated_candidates[cid]['prenom']} {validated_candidates[cid]['nom']}",
            'votes': votes,
            'percentage': round(percentage, 2),
            'slogan': validated_candidates[cid]['slogan'],
            'image_filename': validated_candidates[cid]['image_filename'],
        })

    # Trier par nombre de votes décroissant
    results_data.sort(key=lambda x: x['votes'], reverse=True)
    
    status_msg = "EN COURS" if settings['voting_status'] == 'OPEN' else "FERMÉ (En attente de finalisation)"

    return render_template('results.html',
        results_data=results_data,
        total_votes=total_votes,
        election_status=settings['election_status'],
        status_message=status_msg
    )

@app.route('/results/final')
def final_results():
    settings = get_settings()
    if settings['election_status'] != 'CLOSED':
        # Rediriger vers les résultats en cours si l'élection n'est pas finalisée
        return redirect(url_for('results')) 
        
    total_votes = len([b for b in blockchain.chain if b['type'] == 'VOTE'])
    
    # Calcul des résultats (identique à /results)
    vote_counts = {}
    for block in blockchain.chain:
        if block['type'] == 'VOTE' and isinstance(block['payload'], dict):
            candidate_id = block['payload']['candidate_id']
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1

    results_data = []
    validated_candidates = {cid: c for cid, c in CANDIDATES.items() if c.get('is_validated')}
    
    for cid in validated_candidates:
        votes = vote_counts.get(cid, 0)
        percentage = (votes / total_votes * 100) if total_votes > 0 else 0
        
        results_data.append({
            'candidate_id': cid,
            'name': f"{validated_candidates[cid]['prenom']} {validated_candidates[cid]['nom']}",
            'votes': votes,
            'percentage': round(percentage, 2),
            'slogan': validated_candidates[cid]['slogan'],
            'image_filename': validated_candidates[cid]['image_filename'],
        })

    results_data.sort(key=lambda x: x['votes'], reverse=True)
    
    return render_template('results_final.html',
        results_data=results_data,
        total_votes=total_votes
    )

@app.route('/explorer')
def explorer():
    sanitized_chain = []
    for block in blockchain.chain:
        sanitized_block = block.copy() # Travailler sur une copie du bloc
        
        # Anonymiser les blocs de vote
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            anonymized_payload = sanitized_block['payload'].copy()
            # Seul le hash du votant et le candidat sont gardés
            anonymized_payload['voter_key_hash'] = anonymized_payload['voter_key_hash'][:8] + '...'
            # On masque le nom du candidat pour une anonymisation plus forte
            anonymized_payload['candidate_name'] = 'CANDIDAT_ID: ' + anonymized_payload['candidate_id'][:8] + '...'
            
            sanitized_block['payload'] = anonymized_payload
            
        # Anonymiser l'ID du votant lors de l'inscription pour l'événement (ID de 10 caractères)
        elif sanitized_block['type'] == 'VOTER_REGISTERED' and isinstance(sanitized_block['payload'], dict):
            sanitized_block['payload'] = sanitized_block['payload'].copy()
            # On conserve une partie de l'ID pour montrer que l'événement a eu lieu, mais on le tronque
            id_preview = sanitized_block['payload'].get('id_numerique', 'N/A')[:4] + '...'
            sanitized_block['payload']['id_numerique'] = f"ID_NUMÉ.: {id_preview}"
            # On masque le nom/prénom qui était aussi dans le payload
            sanitized_block['payload']['nom'] = 'NOM/PRÉNOM ANONYMISÉ'
            sanitized_block['payload']['prenom'] = 'NOM/PRÉNOM ANONYMISÉ' # Ajout pour être complet
            
        
        sanitized_chain.append(sanitized_block)
        
    return render_template('explorer_vote.html', blockchain_chain=sanitized_chain)


# --- COMMANDE D'INITIALISATION DE LA BASE DE DONNÉES (CORRECTION DU DÉPLOIEMENT) ---
@app.cli.command('init-db')
def init_db():
    """
    Initialise la base de données : 
    - Applique les FIX TEMPORAIRES pour supprimer/recréer les tables avec un schéma potentiellement corrompu.
    - Crée toutes les tables.
    - Crée l'utilisateur admin par défaut et le bloc Genesis si nécessaire.
    """
    print('Création des tables de la base de données...')

    with app.app_context():
        try:
            # FIX TEMPORAIRE #1: Suppression/Recréation de la table admin_user
            db.session.execute(text('DROP TABLE IF EXISTS "admin_user" CASCADE;'))
            db.session.commit()
            print("FIX TEMPORAIRE : Ancienne table 'admin_user' supprimée pour correction de schéma.")
        except Exception as e:
            db.session.rollback()
            print(f"Échec de la suppression de la table 'admin_user' (peut être ignoré) : {e}")

        try:
            # FIX TEMPORAIRE #2: Suppression/Recréation de la table block
            # Cela corrige l'erreur "column block.id does not exist"
            db.session.execute(text('DROP TABLE IF EXISTS "block" CASCADE;'))
            db.session.commit()
            print("FIX TEMPORAIRE : Ancienne table 'block' supprimée pour correction de schéma.")
        except Exception as e:
            db.session.rollback()
            print(f"Échec de la suppression de la table 'block' (peut être ignoré) : {e}")

        # Recréation de TOUTES les tables avec les schémas corrigés
        db.create_all() 
        print('Tables créées avec succès.')
        
        # Création de l'utilisateur admin par défaut
        if AdminUser.query.count() == 0:
            # Note: Le hash correspond au DEFAULT_ADMINS hash ('escenpass')
            print('Création de l\'utilisateur admin par défaut (admin_institution)...')
            default_admin = AdminUser(
                username='admin', 
                password_hash=generate_password_hash('escenpass'), 
                label='Administrateur Institution'
            )
            db.session.add(default_admin)
            db.session.commit()
            print('Utilisateur admin créé avec succès.')
        else:
            print("L'utilisateur admin existe déjà.")

        # Création du bloc Genesis si la chaîne est vide (vérification sur le modèle DB)
        if Block.query.count() == 0:
            print('Initialisation du bloc Genesis...')
            # Appel de la méthode de la classe Blockchain pour créer le premier bloc
            Blockchain().create_block(proof=1, previous_hash='0', type="GENESIS", payload={"msg": "Lancement Réseau"})
            print('Bloc Genesis créé avec succès.')
        else:
            print('La blockchain existe déjà.')
# ----------------------------------------------------------------------------------


if __name__ == '__main__':
    # Initialisation des données JSON au démarrage local (si non utilisé en production)
    load_data(ADMIN_USERS_FILE, DEFAULT_ADMINS)
    load_data(VOTERS_FILE, VOTERS)
    load_data(CANDIDATES_FILE, CANDIDATES)
    load_data(ELIGIBILITY_LIST_FILE, ELIGIBILITY_LIST)
    load_data(SETTINGS_FILE, DEFAULT_SETTINGS)
    
    # Exécuter l'application Flask
    app.run(debug=True)