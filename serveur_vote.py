import json
import os
import hashlib
from uuid import uuid4
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from datetime import datetime, timezone 
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
import pandas as pd
import tempfile
import click # NOUVEL IMPORT: Pour les commandes CLI Flask

# --- CONFIGURATION INITIALE & BASE DE DONNÉES ---
app = Flask(__name__)
# Récupère la clé secrète de l'environnement ou utilise un UUID par défaut (À CHANGER EN PROD)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', str(uuid4())) 

# Configuration de la base de données PostgreSQL pour Render
# Utilise la variable d'environnement DATABASE_URL fournie par Render
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db').replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialisation de l'ORM
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy(app)

# Fichiers de candidats (pour les photos)
UPLOAD_FOLDER = 'static/candidates_photos'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Constantes de l'élection
DEFAULT_ADMIN_USERNAME = 'admin_institution'
DEFAULT_ADMIN_PASSWORD = 'ADMIN_PASSWORD_ES'
STATUS_VOTING = 'VOTING'
STATUS_PENDING = 'PENDING'
STATUS_FINISHED = 'FINISHED'

# --- CORRECTION DE L'ERREUR JINJA : CONTEXTE-PROCESSEUR ---
@app.context_processor
def inject_datetime():
    """Rend l'objet datetime disponible dans tous les templates Jinja2."""
    return {'datetime': datetime, 'STATUS_VOTING': STATUS_VOTING}
# ------------------------------------------------------------------

# --- DÉFINITION DES MODÈLES (SQLAlchemy ORM) ---

class AdminUser(db.Model):
    """Modèle pour les utilisateurs administrateurs."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # CORRECTION DE L'ERREUR DE TRONCATURE : Augmentation à 256
    password_hash = db.Column(db.String(256), nullable=False) 
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Voter(db.Model):
    """Modèle pour les votants (étudiants éligibles)."""
    id = db.Column(db.Integer, primary_key=True)
    id_numerique = db.Column(db.String(10), unique=True, nullable=False) # ID unique de 10 caractères
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    parcours = db.Column(db.String(100), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)
    
class Candidate(db.Model):
    """Modèle pour les candidats."""
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    parcours = db.Column(db.String(100), nullable=False)
    slogan = db.Column(db.String(200), nullable=False)
    programme = db.Column(db.Text, nullable=False)
    photo_filename = db.Column(db.String(120), nullable=True) # Nom du fichier photo
    is_validated = db.Column(db.Boolean, default=False)
    
class Block(db.Model):
    """Modèle pour les blocs de la blockchain."""
    id = db.Column(db.Integer, primary_key=True)
    index = db.Column(db.Integer, unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    data = db.Column(db.Text, nullable=False) # Contient le JSON du payload (vote, inscription, etc.)
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), unique=True, nullable=False)
    type = db.Column(db.String(50), nullable=False) # 'GENESIS', 'VOTE', 'VOTER_REGISTERED', etc.

class ElectionStatus(db.Model):
    """Modèle pour stocker l'état global de l'élection."""
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), default=STATUS_PENDING) # VOTING, PENDING, FINISHED
    results_visible = db.Column(db.Boolean, default=False) # Si les résultats sont publics

# --- FONCTIONS DE BASE DE LA BLOCKCHAIN (ADAPTÉES à l'ORM) ---

def get_hash(block):
    """Calcule le SHA256 d'un bloc."""
    block_string = json.dumps(
        {
            "index": block.index,
            "timestamp": block.timestamp.isoformat(),
            "data": block.data,
            "previous_hash": block.previous_hash,
            "type": block.type
        }, 
        sort_keys=True
    )
    return hashlib.sha256(block_string.encode()).hexdigest()

def get_last_block():
    """Récupère le dernier bloc de la chaîne (Block)."""
    return db.session.execute(db.select(Block).order_by(Block.index.desc())).scalar_one_or_none()

def get_full_chain():
    """Récupère tous les blocs, triés par index."""
    return db.session.execute(db.select(Block).order_by(Block.index)).scalars().all()

def add_block(data, block_type):
    """Ajoute un nouveau bloc à la chaîne."""
    last_block = get_last_block()
    
    # Si la chaîne est vide (devrait contenir le bloc Genesis), on ne peut pas ajouter.
    if last_block is None:
        return None 
    
    new_index = last_block.index + 1
    
    # Création du nouveau bloc
    new_block = Block(
        index=new_index,
        data=json.dumps(data),
        previous_hash=last_block.hash,
        type=block_type
    )
    # Calcul du hash du nouveau bloc
    new_block.hash = get_hash(new_block)
    
    db.session.add(new_block)
    db.session.commit()
    return new_block
    
def get_election_status():
    """Récupère l'état de l'élection (status et visibilité des résultats)."""
    status = ElectionStatus.query.first()
    if not status:
        # Crée un état par défaut s'il n'existe pas
        status = ElectionStatus(status=STATUS_PENDING, results_visible=False)
        db.session.add(status)
        db.session.commit()
    return status

# --- COMMANDES CLI POUR L'INITIALISATION DE LA BD ---

@app.cli.command("initdb")
def init_db():
    """Crée toutes les tables, l'utilisateur admin et le bloc Genesis."""
    
    # 1. Création des tables
    print("Création des tables de la base de données...")
    db.create_all()
    
    # 2. Création de l'utilisateur admin par défaut
    if not AdminUser.query.filter_by(username=DEFAULT_ADMIN_USERNAME).first():
        print(f"Création de l'utilisateur admin par défaut ({DEFAULT_ADMIN_USERNAME})...")
        admin = AdminUser(username=DEFAULT_ADMIN_USERNAME)
        admin.set_password(DEFAULT_ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
    else:
        print("L'utilisateur admin existe déjà.")

    # 3. Création du bloc Genesis
    if not Block.query.filter_by(index=0).first():
        print("Création du bloc Genesis...")
        genesis_data = {
            'message': 'Initialisation de la blockchain de vote ESCEN',
            'admin_creator': DEFAULT_ADMIN_USERNAME
        }
        genesis_block = Block(
            index=0,
            data=json.dumps(genesis_data),
            previous_hash='0', # Convention pour le premier bloc
            type='GENESIS'
        )
        genesis_block.hash = get_hash(genesis_block)
        db.session.add(genesis_block)
        db.session.commit()
        print("Bloc Genesis créé.")
    else:
        print("Le bloc Genesis existe déjà.")
        
    # 4. Création du statut de l'élection
    if not ElectionStatus.query.first():
        print("Création du statut de l'élection par défaut (PENDING)...")
        status = ElectionStatus(status=STATUS_PENDING, results_visible=False)
        db.session.add(status)
        db.session.commit()
    else:
        print("Le statut de l'élection existe déjà.")
        
    print("Base de données initialisée avec succès.")

# --- DÉCORATEURS ET FONCTIONS UTILITAIRES ---

def login_required(f):
    """Décorateur pour vérifier la session administrateur."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session or not session['admin_logged_in']:
            return redirect(url_for('admin_login', error="Accès refusé. Veuillez vous connecter."))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- ROUTES D'AFFICHAGE (GET) ---

@app.route('/')
def index():
    """Page d'accueil."""
    return render_template('index.html')

@app.route('/voter_login')
def voter_login():
    """Page de connexion pour les votants."""
    return render_template('voter_login.html')

@app.route('/self_register_student')
def self_register_student_get():
    """Page d'auto-inscription des étudiants (votants)."""
    return render_template('self_register_student.html')

@app.route('/self_register_candidate')
def self_register_candidate_get():
    """Page d'auto-inscription des candidats."""
    return render_template('self_register_candidate.html')

@app.route('/admin_login', methods=['GET'])
def admin_login_get():
    """Page de connexion administrateur (GET)."""
    error = request.args.get('error')
    return render_template('admin_login.html', error=error)

@app.route('/admin_logout')
def admin_logout():
    """Déconnexion administrateur."""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('index'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    """Tableau de bord administrateur."""
    
    # 1. État de l'élection
    status_obj = get_election_status()
    
    # 2. Statistiques des votants
    total_voters = Voter.query.count()
    voters_registered = total_voters
    voters_voted = Voter.query.filter_by(has_voted=True).count()
    
    # 3. Candidats
    pending_candidates = Candidate.query.filter_by(is_validated=False).all()
    validated_candidates = Candidate.query.filter_by(is_validated=True).all()
    
    # 4. Logs/Blockchain
    last_block = get_last_block()
    latest_blocks = db.session.execute(
        db.select(Block).order_by(Block.index.desc()).limit(5)
    ).scalars().all()
    
    context = {
        'admin_username': session.get('admin_username', 'Admin'),
        'election_status': status_obj.status,
        'results_visible': status_obj.results_visible,
        'voters_registered': voters_registered,
        'voters_voted': voters_voted,
        'total_blocks': last_block.index if last_block else 0,
        'pending_candidates': pending_candidates,
        'validated_candidates': validated_candidates,
        'latest_blocks': latest_blocks,
        'STATUS_PENDING': STATUS_PENDING,
        'STATUS_VOTING': STATUS_VOTING,
        'STATUS_FINISHED': STATUS_FINISHED,
    }
    return render_template('admin_dashboard.html', **context)

@app.route('/voting_page/<voter_id>')
def voting_page(voter_id):
    """Page de vote du votant."""
    
    status_obj = get_election_status()
    
    if status_obj.status != STATUS_VOTING:
        return render_template('error_page.html', message="Le vote est actuellement clos ou en attente d'ouverture.")
        
    voter = Voter.query.filter_by(id_numerique=voter_id).first()
    
    if not voter:
        return render_template('error_page.html', message="ID Votant non valide.")
        
    if voter.has_voted:
        return render_template('error_page.html', message="Vous avez déjà exercé votre droit de vote.")

    candidates = Candidate.query.filter_by(is_validated=True).all()

    if not candidates:
         return render_template('error_page.html', message="Aucun candidat validé pour le moment.")

    return render_template('voting_page.html', voter_id=voter_id, candidates=candidates)

@app.route('/explorer')
def explorer():
    """Explorateur de la blockchain."""
    full_chain = get_full_chain()
    
    # Préparation de la chaîne pour l'affichage (Anonymisation/Simplification)
    # Le reste de la logique d'anonymisation est conservée dans la route
    sanitized_chain = []
    
    for block in full_chain:
        sanitized_block = {
            'index': block.index,
            'timestamp': block.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'type': block.type,
            'hash': block.hash,
            'previous_hash': block.previous_hash,
            'payload': json.loads(block.data) # Charger les données
        }
        
        # Anonymisation des VOTES
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            # Assure que le type de données est visible, mais masque l'identité
            anonymized_payload = sanitized_block['payload'].copy()
            # On conserve juste l'ID du candidat (qui est public), mais pas l'ID du votant
            anonymized_payload.pop('voter_id', None)
            anonymized_payload.pop('timestamp', None)
            
            # Afficher seulement l'ID du candidat qui a reçu le vote
            candidate_id = sanitized_block['payload'].get('candidate_id', 'N/A')
            candidate = Candidate.query.get(candidate_id)
            anonymized_payload['vote_for'] = f"CANDIDAT ID: {candidate_id} ({candidate.nom} {candidate.prenom})" if candidate else f"CANDIDAT ID: {candidate_id}"
            
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

@app.route('/results')
def results():
    """Page d'affichage des résultats."""
    
    status_obj = get_election_status()
    election_status = status_obj.status
    results_visible = status_obj.results_visible
    
    # 1. Récupération des votes
    vote_blocks = Block.query.filter_by(type='VOTE').all()
    total_votes = len(vote_blocks)
    
    # 2. Calcul des résultats
    vote_counts = {}
    for block in vote_blocks:
        payload = json.loads(block.data)
        candidate_id = payload.get('candidate_id')
        if candidate_id:
            vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
            
    # 3. Récupération des candidats validés
    candidates = Candidate.query.filter_by(is_validated=True).all()
    
    if not candidates:
        status_message = "Aucun candidat validé pour le moment."
        return render_template('results.html', results=[], total_votes=0, election_status=election_status, status_message=status_message)

    results_data = []
    
    if election_status == STATUS_FINISHED and results_visible:
        status_message = "RÉSULTAT FINAL OFFICIEL"
    elif election_status == STATUS_VOTING and results_visible:
        status_message = "Vote en cours - Résultats partiels visibles"
    elif results_visible is False:
        status_message = "Les résultats sont actuellement cachés par l'administration."
    elif election_status == STATUS_PENDING:
        status_message = "Le vote n'a pas encore commencé."
    else:
         status_message = "État de l'élection inconnu."


    if results_visible:
        for candidate in candidates:
            votes = vote_counts.get(candidate.id, 0)
            percentage = (votes / total_votes * 100) if total_votes > 0 else 0
            
            results_data.append({
                'id': candidate.id,
                'nom_complet': f"{candidate.prenom} {candidate.nom}",
                'photo': url_for('static', filename=f'candidates_photos/{candidate.photo_filename}') if candidate.photo_filename else url_for('static', filename='images/default_candidate.png'),
                'votes': votes,
                'percentage': f"{percentage:.2f}"
            })
            
        # Tri des résultats par nombre de votes (du plus grand au plus petit)
        results_data.sort(key=lambda x: x['votes'], reverse=True)
    
    return render_template('results.html', 
                           results=results_data, 
                           total_votes=total_votes, 
                           election_status=election_status,
                           status_message=status_message)


# --- ROUTES D'ACTION (POST / API) ---

@app.route('/admin_login', methods=['POST'])
def admin_login():
    """Connexion administrateur (POST)."""
    username = request.form.get('username')
    password = request.form.get('password')

    user = AdminUser.query.filter_by(username=username).first()

    if user and user.check_password(password):
        session['admin_logged_in'] = True
        session['admin_username'] = user.username
        return redirect(url_for('admin_dashboard'))
    else:
        return render_template('admin_login.html', error="Nom d'utilisateur ou mot de passe incorrect.")

@app.route('/api/voter/login', methods=['POST'])
def voter_api_login():
    """API de connexion pour les votants."""
    data = request.get_json()
    id_numerique = data.get('id_numerique', '').strip()

    if not id_numerique:
        return jsonify({'error': 'ID numérique manquant.'}), 400

    voter = Voter.query.filter_by(id_numerique=id_numerique).first()

    if not voter:
        return jsonify({'error': "ID non trouvé. Veuillez vous inscrire d'abord."}), 404
        
    if voter.has_voted:
        return jsonify({'error': "Vous avez déjà voté."}), 403

    status_obj = get_election_status()
    if status_obj.status != STATUS_VOTING:
        return jsonify({'error': "Le vote n'est pas ouvert pour l'instant."}), 403

    # Succès: Redirection vers la page de vote avec l'ID
    return jsonify({
        'success': True,
        'redirect_url': url_for('voting_page', voter_id=voter.id_numerique)
    })

@app.route('/api/vote', methods=['POST'])
def api_vote():
    """API d'enregistrement du vote sur la blockchain."""
    data = request.get_json()
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')

    # Vérification de l'état
    status_obj = get_election_status()
    if status_obj.status != STATUS_VOTING:
        return jsonify({'error': "Le vote n'est pas ouvert."}), 403

    # 1. Vérification du votant
    voter = Voter.query.filter_by(id_numerique=voter_id).first()
    if not voter:
        return jsonify({'error': 'ID Votant non valide.'}), 400
    if voter.has_voted:
        return jsonify({'error': 'Le votant a déjà voté.'}), 403
    
    # 2. Vérification du candidat
    candidate = Candidate.query.filter_by(id=candidate_id, is_validated=True).first()
    if not candidate:
        return jsonify({'error': 'Candidat non valide ou non validé.'}), 400

    # 3. Création du bloc de vote
    vote_data = {
        'voter_id': voter_id, # L'ID est stocké dans la chaîne pour validation interne/recomptage, mais sera anonymisé dans l'explorateur public.
        'candidate_id': candidate_id,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    
    new_block = add_block(vote_data, 'VOTE')
    
    if not new_block:
        return jsonify({'error': 'Erreur lors de la création du bloc.'}), 500
        
    # 4. Mise à jour du statut du votant
    voter.has_voted = True
    db.session.commit()
    
    return jsonify({
        'success': 'Vote enregistré', 
        'block_index': new_block.index
    }), 200

@app.route('/api/student/self_register', methods=['POST'])
def api_student_self_register():
    """API d'auto-inscription des étudiants."""
    data = request.get_json()
    nom = data.get('nom', '').upper()
    prenom = data.get('prenom', '').title()
    parcours = data.get('parcours', '').upper()

    if not all([nom, prenom, parcours]):
        return jsonify({'error': 'Tous les champs sont requis.'}), 400
        
    # Génération de l'ID numérique (UUID tronqué pour 10 caractères)
    id_numerique = str(uuid4().hex[:10]).upper()
    
    # Vérification de l'existence d'un votant avec le même nom/prénom/parcours
    # Pour éviter les doublons accidentels lors de l'inscription
    existing_voter = Voter.query.filter_by(nom=nom, prenom=prenom, parcours=parcours).first()
    if existing_voter:
        # Si la personne existe, on renvoie son ancien ID (pour éviter la fraude)
        return jsonify({'error': f"Vous êtes déjà inscrit. Votre ID numérique est : {existing_voter.id_numerique}. Veuillez le noter."}), 409

    # Création du nouveau votant
    new_voter = Voter(
        id_numerique=id_numerique,
        nom=nom,
        prenom=prenom,
        parcours=parcours
    )
    
    # Enregistrement dans la DB
    db.session.add(new_voter)
    db.session.commit()
    
    # Enregistrement dans la blockchain
    block_data = {
        'id_numerique': id_numerique,
        'nom': nom, # Sera anonymisé dans l'explorer
        'prenom': prenom,
        'parcours': parcours,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }
    add_block(block_data, 'VOTER_REGISTERED')

    return jsonify({'success': 'Inscription réussie', 'id_numerique': id_numerique}), 200

@app.route('/api/candidate/self_register', methods=['POST'])
def api_candidate_self_register():
    """API d'auto-inscription des candidats."""
    
    nom = request.form.get('nom', '').upper()
    prenom = request.form.get('prenom', '').title()
    parcours = request.form.get('parcours', '').upper()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    
    # 1. Vérification des données textuelles
    if not all([nom, prenom, parcours, slogan, programme]):
        return jsonify({'error': 'Tous les champs de texte sont requis.'}), 400
        
    # 2. Gestion de la photo
    if 'photo' not in request.files:
        return jsonify({'error': 'Photo de candidature requise.'}), 400
        
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': 'Nom de fichier de photo manquant.'}), 400
        
    if file and allowed_file(file.filename):
        # Création d'un nom de fichier sécurisé et unique basé sur le nom du candidat
        filename_base = secure_filename(f"{nom}_{prenom}_{str(uuid4().hex[:8])}")
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        photo_filename = f"{filename_base}.{file_extension}"
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], photo_filename)
        file.save(filepath)
    else:
        return jsonify({'error': 'Format de fichier non autorisé (PNG, JPG, JPEG uniquement).'}), 400
        
    # 3. Vérification de l'existence
    existing_candidate = Candidate.query.filter_by(nom=nom, prenom=prenom, parcours=parcours).first()
    if existing_candidate:
        # En cas de doublon, on refuse et on supprime la photo uploadée
        os.remove(filepath) 
        return jsonify({'error': "Ce candidat est déjà inscrit ou en attente de validation."}), 409
        
    # 4. Création du nouveau candidat
    new_candidate = Candidate(
        nom=nom,
        prenom=prenom,
        parcours=parcours,
        slogan=slogan,
        programme=programme,
        photo_filename=photo_filename,
        is_validated=False # Toujours non validé par défaut
    )
    
    db.session.add(new_candidate)
    db.session.commit()
    
    # Pas de bloc blockchain pour l'inscription simple (seulement après validation)
    
    return jsonify({'success': 'Candidature enregistrée', 'candidate_id': new_candidate.id}), 200

@app.route('/api/admin/candidate_action/<int:candidate_id>', methods=['POST'])
@login_required
def api_admin_candidate_action(candidate_id):
    """API pour valider ou supprimer un candidat."""
    data = request.get_json()
    action = data.get('action')
    
    candidate = Candidate.query.get(candidate_id)
    if not candidate:
        return jsonify({'error': 'Candidat non trouvé.'}), 404
        
    if action == 'validate':
        if candidate.is_validated:
            return jsonify({'error': 'Ce candidat est déjà validé.'}), 400
            
        candidate.is_validated = True
        db.session.commit()
        
        # Enregistrement dans la blockchain
        block_data = {
            'candidate_id': candidate.id,
            'nom_complet': f"{candidate.prenom} {candidate.nom}",
            'parcours': candidate.parcours,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        add_block(block_data, 'CANDIDATE_VALIDATED')
        
        return jsonify({'success': f"Candidat {candidate_id} validé et ajouté à la Blockchain."}), 200
        
    elif action == 'delete':
        
        # Tentative de suppression de la photo associée
        if candidate.photo_filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], candidate.photo_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                
        db.session.delete(candidate)
        db.session.commit()
        
        # Pas de bloc blockchain pour la suppression (action administrative non liée au vote)
        
        return jsonify({'success': f"Candidat {candidate_id} et sa photo supprimés."}), 200
        
    else:
        return jsonify({'error': 'Action non valide.'}), 400

@app.route('/api/admin/election_status', methods=['POST'])
@login_required
def api_admin_election_status():
    """API pour changer l'état de l'élection."""
    data = request.get_json()
    status = data.get('status')
    
    status_obj = get_election_status()
    
    if status in [STATUS_PENDING, STATUS_VOTING, STATUS_FINISHED]:
        status_obj.status = status
        db.session.commit()
        
        # Enregistrement dans la blockchain si c'est une action majeure
        if status == STATUS_VOTING:
            add_block({'status': 'OUVERTURE DU VOTE'}, 'STATUS_UPDATE')
        elif status == STATUS_FINISHED:
            add_block({'status': 'CLÔTURE DU VOTE'}, 'STATUS_UPDATE')
            
        return jsonify({'success': f"Statut de l'élection mis à jour à {status}."}), 200
    else:
        return jsonify({'error': 'Statut non valide.'}), 400

@app.route('/api/admin/results_visibility', methods=['POST'])
@login_required
def api_admin_results_visibility():
    """API pour masquer/afficher les résultats."""
    data = request.get_json()
    action = data.get('action')
    
    status_obj = get_election_status()
    
    if action == 'show':
        status_obj.results_visible = True
        message = "Les résultats sont maintenant publics."
    elif action == 'hide':
        status_obj.results_visible = False
        message = "Les résultats sont maintenant cachés."
    else:
        return jsonify({'error': 'Action non valide.'}), 400
        
    db.session.commit()
    return jsonify({'success': message}), 200

# --- POINT D'ENTRÉE PRINCIPAL (ADAPTÉ POUR RENDER) ---

# Le bloc __main__ est désormais simplifié pour la production sur Render.
# L'initialisation se fait via la commande CLI `python serveur_vote.py initdb`
# lors du Build Command sur Render.
if __name__ == '__main__':
    # Initialisation locale de la base de données si elle n'existe pas
    # Attention: cela utilisera un fichier SQLite local si DATABASE_URL n'est pas configuré.
    # Pour Render, ceci est géré par la commande Build.
    with app.app_context():
        # Tentative d'initialisation (gère les cas où les tables existent déjà)
        init_db()
        
    # Lance l'application en mode debug pour le développement local
    # En production, Gunicorn prend le relais
    app.run(debug=True)