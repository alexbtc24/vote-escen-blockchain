import json
import os
import hashlib
import time  
from uuid import uuid4
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, g, abort
from datetime import datetime, timezone  
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
import pandas as pd  
import tempfile  
import psycopg2 # NOUVEL IMPORT: Pour PostgreSQL
from urllib.parse import urlparse # NOUVEL IMPORT: Pour analyser l'URL de BDD

# --- CONFIGURATION INITIALE SIMPLIFIÉE ---\napp = Flask(__name__)
# Utilisez une clé secrète forte en production ! La variable d'environnement sera utilisée sur Render.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', str(uuid4()))  

# Logging pour le débogage en production
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- CORRECTION DE L'ERREUR JINJA : CONTEXTE-PROCESSEUR ---
@app.context_processor
def inject_datetime():
    """Rend l'objet datetime disponible dans tous les templates Jinja2."""
    return {'datetime': datetime}
# ------------------------------------------------------------------

# Les chemins de fichiers sont conservés ici, mais ne sont plus utilisés pour la persistence
# Uniquement pour les fonctions de nettoyage ou de debug si nécessaire, mais la
# logique load_data/save_data est maintenant centralisée dans la classe Blockchain
# et les fonctions de DB.

UPLOAD_FOLDER = 'static/uploads'
# Assurez-vous que le dossier d'upload existe
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configuration de la base de données PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    # Pour des connexions sécurisées via SSL/TLS
    DB_PARAMS = urlparse(DATABASE_URL)
    DB_CONFIG = {
        'database': DB_PARAMS.path[1:],
        'user': DB_PARAMS.username,
        'password': DB_PARAMS.password,
        'host': DB_PARAMS.hostname,
        'port': DB_PARAMS.port,
        'sslmode': 'require' # Généralement requis par les hébergeurs comme Render
    }
else:
    # Fallback pour le développement local si DB_URL n'est pas défini
    DB_CONFIG = None
    logger.warning("DATABASE_URL non trouvé. L'application fonctionnera sans persistance de base de données (mode setup/debug local).")


def get_db_connection():
    """Crée et retourne une connexion à la base de données."""
    if not DB_CONFIG:
        logger.error("Tentative de connexion à la DB sans configuration (DB_CONFIG est None).")
        raise Exception("Configuration de base de données manquante.")
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"Échec de la connexion à la base de données: {e}")
        raise e

# --- VOTECHAIN : Implémentation de la Blockchain ---

class Block:
    def __init__(self, index, timestamp, data, previous_hash, nonce=0, hash=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()

    def calculate_hash(self):
        """Calcule le hash SHA-256 du bloc."""
        # On inclut le nonce dans les données à hacher pour le Proof-of-Work
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.nonce}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def to_dict(self):
        """Sérialise le bloc en dictionnaire."""
        return {
            'index': self.index,
            'timestamp': self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }
        
    @classmethod
    def from_dict(cls, data):
        """Crée un objet Block à partir d'un dictionnaire."""
        # Convertir la chaîne de caractères timestamp en objet datetime si possible
        try:
            timestamp = datetime.fromisoformat(data['timestamp'])
        except (TypeError, ValueError):
            timestamp = data['timestamp'] # Garder la chaîne si la conversion échoue

        return cls(
            index=data['index'],
            timestamp=timestamp,
            data=data['data'],
            previous_hash=data['previous_hash'],
            nonce=data['nonce'],
            hash=data['hash'] # Assurez-vous que le hash est aussi chargé pour vérification
        )

class Blockchain:
    def __init__(self, difficulty=4):
        self.difficulty = difficulty
        # La chaîne est maintenant chargée depuis la DB lors de l'initialisation
        self.chain = self.load_chain_from_db()
        
        if not self.chain:
            logger.info("Blockchain vide détectée. Création du bloc Genesis.")
            self.chain = [self.create_genesis_block()]
            self.save_block_to_db(self.chain[0])

    def load_chain_from_db(self):
        """Charge tous les blocs de la DB pour reconstruire la chaîne."""
        if not DB_CONFIG:
            logger.warning("Mode sans DB : La blockchain n'est pas chargée et ne persistera pas.")
            return []

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT content FROM blockchain ORDER BY index ASC;")
            
            chain = []
            for row in cur.fetchall():
                block_dict = json.loads(row[0])
                block = Block.from_dict(block_dict)
                chain.append(block)
                
            logger.info(f"Chaîne chargée depuis la DB. Taille: {len(chain)}")
            return chain
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la chaîne depuis la DB: {e}")
            return []
        finally:
            if cur: cur.close()
            if conn: conn.close()

    def save_block_to_db(self, block):
        """Sauvegarde un nouveau bloc dans la DB."""
        if not DB_CONFIG:
            logger.warning("Mode sans DB : Le bloc n'est pas sauvegardé.")
            return

        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Utiliser la méthode to_dict pour sérialiser le bloc en JSON
            block_content = json.dumps(block.to_dict())
            
            # Insérer le nouveau bloc
            cur.execute("""
                INSERT INTO blockchain (index, hash, content, created_at)
                VALUES (%s, %s, %s, %s)
            """, (block.index, block.hash, block_content, datetime.now(timezone.utc)))
            
            conn.commit()
            logger.info(f"Bloc #{block.index} sauvegardé dans la DB.")
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du bloc dans la DB: {e}")
            conn.rollback()
        finally:
            if cur: cur.close()
            if conn: conn.close()

    def create_genesis_block(self):
        """Crée le premier bloc de la chaîne."""
        # Le bloc genesis est créé sans preuve de travail (nonce=0, previous_hash=0)
        genesis = Block(0, datetime.now(timezone.utc).isoformat(), "Bloc Genesis - Création de la chaîne de vote ESCEN", "0")
        genesis.hash = genesis.calculate_hash() # Calculer le hash initial
        return genesis

    def get_last_block(self):
        """Retourne le dernier bloc de la chaîne."""
        if not self.chain:
            return self.create_genesis_block() # Sécurité
        return self.chain[-1]

    def mine_block(self, block):
        """Effectue le Proof-of-Work pour trouver un hash valide."""
        target = '0' * self.difficulty
        while block.hash[:self.difficulty] != target:
            block.nonce += 1
            block.hash = block.calculate_hash()
        logger.info(f"Bloc miné: Nonce = {block.nonce}, Hash = {block.hash}")
        return block

    def add_block(self, data):
        """Crée, mine et ajoute un nouveau bloc à la chaîne."""
        last_block = self.get_last_block()
        new_index = last_block.index + 1
        new_timestamp = datetime.now(timezone.utc).isoformat()
        
        # Le nouveau bloc est initialisé avec un nonce à 0
        new_block = Block(new_index, new_timestamp, data, last_block.hash)
        
        # Minage (Proof-of-Work)
        mined_block = self.mine_block(new_block)
        
        # Vérification finale (facultative mais bonne pratique)
        if mined_block.hash[:self.difficulty] != '0' * self.difficulty:
            logger.error(f"Erreur de minage: Hash invalide pour le bloc #{new_index}")
            return None

        # Ajout à la chaîne et sauvegarde dans la DB
        self.chain.append(mined_block)
        self.save_block_to_db(mined_block)
        
        return mined_block

    def is_chain_valid(self):
        """Vérifie l'intégrité de toute la chaîne."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # 1. Vérifier que le hash est correct
            if current_block.hash != current_block.calculate_hash():
                logger.error(f"Validation échouée: Hash invalide pour le bloc #{current_block.index}")
                return False

            # 2. Vérifier que le previous_hash pointe vers le hash précédent
            if current_block.previous_hash != previous_block.hash:
                logger.error(f"Validation échouée: Hash précédent invalide pour le bloc #{current_block.index}")
                return False
                
            # 3. Vérifier le Proof-of-Work
            if current_block.hash[:self.difficulty] != '0' * self.difficulty:
                logger.error(f"Validation échouée: PoW invalide pour le bloc #{current_block.index}")
                return False

        return True

    def get_vote_counts(self):
        """Compte les votes pour chaque candidat à partir des blocs."""
        vote_counts = {}
        # On commence à l'index 1 pour ignorer le bloc Genesis
        for block in self.chain[1:]:
            try:
                # La donnée du vote est un dictionnaire avec 'type' et 'content'
                data = block.data
                if data.get('type') == 'VOTE':
                    candidate_id = data['content'].get('candidate_id')
                    if candidate_id:
                        vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
            except Exception as e:
                logger.error(f"Erreur de décodage/comptage pour le bloc #{block.index}: {e}")
                continue
        return vote_counts

# L'instance globale de la blockchain (sera initialisée dans le hook d'application)
blockchain = None

# --- INITIALISATION DE LA BASE DE DONNÉES (PostgreSQL) ---

def init_db():
    """Initialise les tables de la base de données si elles n'existent pas."""
    if not DB_CONFIG:
        logger.warning("Ignorer l'initialisation de la DB car DB_CONFIG est absent.")
        return

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Table des étudiants (Pour l'éligibilité et le suivi du vote)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id SERIAL PRIMARY KEY,
                id_numerique VARCHAR(255) UNIQUE NOT NULL,
                nom VARCHAR(255) NOT NULL,
                prenom VARCHAR(255) NOT NULL,
                parcours VARCHAR(255),
                has_voted BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 2. Table des candidats
        cur.execute("""
            CREATE TABLE IF NOT EXISTS candidates (
                id SERIAL PRIMARY KEY,
                full_name VARCHAR(255) UNIQUE NOT NULL,
                slogan TEXT,
                programme TEXT,
                photo_path VARCHAR(512),
                is_validated BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 3. Table de la Blockchain
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                id SERIAL PRIMARY KEY,
                index INTEGER UNIQUE NOT NULL,
                hash VARCHAR(64) UNIQUE NOT NULL,
                content JSONB NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # 4. Table pour le statut de l'élection
        cur.execute("""
            CREATE TABLE IF NOT EXISTS election_status (
                id INTEGER PRIMARY KEY DEFAULT 1,
                status VARCHAR(50) NOT NULL DEFAULT 'SETUP', -- SETUP, VOTING, FINISHED
                start_time TIMESTAMP WITH TIME ZONE,
                end_time TIMESTAMP WITH TIME ZONE,
                result_visible BOOLEAN DEFAULT FALSE,
                CHECK (id = 1) -- S'assure qu'il n'y a qu'une seule ligne
            );
        """)
        
        # 5. Table pour la liste des étudiants éligibles (initiale ou importée)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS eligible_students (
                id SERIAL PRIMARY KEY,
                nom VARCHAR(255) NOT NULL,
                prenom VARCHAR(255) NOT NULL,
                parcours VARCHAR(255),
                UNIQUE (nom, prenom, parcours)
            );
        """)

        # Insérer la ligne de statut si elle n'existe pas
        cur.execute("INSERT INTO election_status (id, status) VALUES (1, 'SETUP') ON CONFLICT (id) DO NOTHING;")
        
        # S'assurer qu'un compte administrateur par défaut existe
        default_admin_user = os.environ.get('ADMIN_USERNAME', 'admin')
        default_admin_pass = os.environ.get('ADMIN_PASSWORD', 'voteescen2025')
        hashed_password = generate_password_hash(default_admin_pass)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(512) NOT NULL
            );
        """)
        
        cur.execute("""
            INSERT INTO admin_users (username, password_hash)
            VALUES (%s, %s)
            ON CONFLICT (username) DO NOTHING;
        """, (default_admin_user, hashed_password))

        conn.commit()
        logger.info("Base de données initialisée avec succès.")
        
    except Exception as e:
        logger.error(f"Échec de l'initialisation de la base de données: {e}")
        # En cas d'échec critique (par ex. DB inaccessible), l'application peut continuer
        # en mode dégradé, mais en production, on pourrait choisir d'échouer le démarrage.
        if conn: conn.rollback()
        raise e # On propage l'exception pour la gestion au démarrage
    finally:
        if cur: cur.close()
        if conn: conn.close()

# --- FONCTIONS UTILITAIRES DE LA BASE DE DONNÉES ---

def get_election_status():
    """Récupère le statut actuel de l'élection."""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT status, start_time, end_time, result_visible FROM election_status LIMIT 1;")
        row = cur.fetchone()
        if row:
            return {
                'status': row[0],
                'start_time': row[1],
                'end_time': row[2],
                'result_visible': row[3]
            }
        return {'status': 'SETUP', 'start_time': None, 'end_time': None, 'result_visible': False}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du statut de l'élection: {e}")
        return {'status': 'ERROR', 'start_time': None, 'end_time': None, 'result_visible': False}
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
# --- DÉCORATEURS ET FONCTIONS D'AUTHENTIFICATION ---

def admin_login_required(f):
    """Décorateur pour les routes nécessitant une connexion administrateur."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            logger.warning(f"Tentative d'accès non autorisé à {request.path}")
            # Redirection vers la page de connexion avec un message d'erreur
            return redirect(url_for('admin_login', error="Accès refusé. Vous devez vous connecter."))
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES PUBLIQUES (Vues) ---

@app.route('/')
def index():
    status = get_election_status()
    return render_template('index.html', election_status=status['status'])

@app.route('/explorer')
def explorer():
    # Affichage de la chaîne (appel API par JS dans le template)
    return render_template('explorer_vote.html')

@app.route('/results')
def results():
    """Affiche la page des résultats ou le statut de l'élection."""
    status_data = get_election_status()
    election_status = status_data['status']
    result_visible = status_data['result_visible']
    
    # Si les résultats sont cachés ou l'élection est en SETUP (et non terminée), on affiche le statut
    if not result_visible and election_status != 'FINISHED':
        message = "Le vote est en cours et les résultats en temps réel sont cachés par l'administration."
        if election_status == 'SETUP':
            message = "L'élection n'a pas encore commencé. Les inscriptions sont ouvertes."
        
        # Récupérer le nombre total de votes pour l'affichage du statut
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT COUNT(*) FROM blockchain WHERE index > 0;")
            total_votes = cur.fetchone()[0]
        except Exception:
            total_votes = 0
        finally:
            if cur: cur.close()
            if conn: conn.close()
            
        return render_template('results.html', 
                               election_status=election_status, 
                               status_message=message, 
                               results=None, 
                               total_votes=total_votes)

    # Si l'élection est terminée ET les résultats sont visibles, ou si on est en VOTING et visibles.
    # On récupère les résultats.
    vote_counts = blockchain.get_vote_counts()
    
    # Récupérer les informations des candidats (nom, photo, etc.)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, full_name, photo_path FROM candidates WHERE is_validated = TRUE;")
        candidate_rows = cur.fetchall()
        
        total_votes = sum(vote_counts.values())
        
        results_list = []
        for c_id, full_name, photo_path in candidate_rows:
            votes = vote_counts.get(c_id, 0)
            percentage = (votes / total_votes * 100) if total_votes > 0 else 0
            
            results_list.append({
                'id': c_id,
                'full_name': full_name,
                'photo_path': url_for('static', filename=photo_path.replace('static/', '')) if photo_path and os.path.exists(photo_path) else url_for('static', filename='images/default_candidate.png'),
                'votes': votes,
                'percentage': round(percentage, 2)
            })
            
        # Trier les résultats par nombre de votes (descendant)
        results_list.sort(key=lambda x: x['votes'], reverse=True)
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des résultats: {e}")
        results_list = []
        total_votes = 0
    finally:
        if cur: cur.close()
        if conn: conn.close()

    # Déterminer le message d'état
    if election_status == 'FINISHED':
        status_message = "L'élection est terminée. Résultats finaux !"
        return render_template('results_final.html', 
                               results=results_list, 
                               total_votes=total_votes)
    else: # VOTING et results_visible=True
        status_message = "Le vote est en cours. Résultats en temps réel !"
        return render_template('results.html', 
                               election_status=election_status, 
                               status_message=status_message, 
                               results=results_list, 
                               total_votes=total_votes)

# --- ROUTES D'INSCRIPTION ÉTUDIANT (Vues) ---

@app.route('/self_register_student', methods=['GET'])
def self_register_student_get():
    """Affiche la page d'auto-inscription étudiant."""
    status = get_election_status()
    # Si l'élection est en VOTING ou FINISHED, l'inscription est fermée
    if status['status'] != 'SETUP':
        return render_template('error_page.html', message="L'inscription au vote est fermée. Veuillez contacter l'administration."), 403
        
    return render_template('self_register_student.html')

# --- ROUTES D'INSCRIPTION CANDIDAT (Vues) ---

@app.route('/self_register_candidate', methods=['GET'])
def self_register_candidate_get():
    """Affiche la page d'auto-inscription candidat."""
    status = get_election_status()
    # L'inscription des candidats est ouverte en SETUP
    if status['status'] != 'SETUP':
        return render_template('error_page.html', message="L'inscription des candidats est fermée."), 403
        
    return render_template('self_register_candidate.html')

# --- ROUTES D'ACCÈS AU VOTE (Vues) ---

@app.route('/voter_login', methods=['GET'])
def voter_login():
    """Affiche la page de connexion du votant."""
    status = get_election_status()
    if status['status'] != 'VOTING':
        return render_template('error_page.html', message="Le vote n'est pas actif pour le moment."), 403
        
    return render_template('voter_login.html', message=request.args.get('message'))

@app.route('/voter/vote/<id_numerique>', methods=['GET'])
def voting_page(id_numerique):
    """Affiche la page de vote après connexion réussie."""
    
    # 1. Vérification du statut de l'élection
    status = get_election_status()
    if status['status'] != 'VOTING':
        return render_template('error_page.html', message="Le vote n'est pas actif pour le moment."), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # 2. Vérification de l'existence et du statut de l'étudiant
        cur.execute("SELECT nom, prenom, has_voted FROM students WHERE id_numerique = %s;", (id_numerique,))
        student_data = cur.fetchone()
        
        if not student_data:
            return render_template('error_page.html', message="ID Numérique invalide ou non enregistré."), 404
        
        nom, prenom, has_voted = student_data
        
        if has_voted:
            return render_template('error_page.html', message="Vous avez déjà voté."), 403

        # 3. Récupération des candidats validés
        cur.execute("SELECT id, full_name, slogan, photo_path FROM candidates WHERE is_validated = TRUE ORDER BY full_name ASC;")
        candidates = [
            {
                'id': row[0],
                'full_name': row[1],
                'slogan': row[2],
                'photo_path': url_for('static', filename=row[3].replace('static/', '')) if row[3] and os.path.exists(row[3]) else url_for('static', filename='images/default_candidate.png')
            }
            for row in cur.fetchall()
        ]
        
        if not candidates:
            return render_template('error_page.html', message="Aucun candidat validé pour le moment."), 404

        return render_template('voting_page.html', 
                               voter_id=id_numerique, 
                               voter_name=f"{prenom} {nom}", 
                               candidates=candidates)

    except Exception as e:
        logger.error(f"Erreur dans la page de vote: {e}")
        return render_template('error_page.html', message="Erreur interne. Veuillez réessayer."), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
# --- ROUTES ADMIN (Vues) ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Affiche et gère le formulaire de connexion de l'administrateur."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("SELECT password_hash FROM admin_users WHERE username = %s;", (username,))
            row = cur.fetchone()
            
            if row and check_password_hash(row[0], password):
                session['admin_logged_in'] = True
                session['admin_username'] = username
                logger.info(f"Admin '{username}' connecté.")
                return redirect(url_for('admin_dashboard', message="Connexion réussie."))
            else:
                error = "Nom d'utilisateur ou mot de passe invalide."
                logger.warning(f"Tentative de connexion admin échouée pour l'utilisateur: {username}")
        except Exception as e:
            logger.error(f"Erreur de connexion admin: {e}")
            error = "Erreur interne lors de la connexion."
        finally:
            if cur: cur.close()
            if conn: conn.close()
            
        return render_template('admin_login.html', error=error, message=request.args.get('message'))

    # Pour la requête GET
    return render_template('admin_login.html', error=request.args.get('error'), message=request.args.get('message'))

@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    """Déconnecte l'administrateur."""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login', message="Vous avez été déconnecté."))

@app.route('/admin/dashboard', methods=['GET'])
@admin_login_required
def admin_dashboard():
    logger.info("Accès au tableau de bord administrateur.")
    admin_username = session.get('admin_username')
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Récupération du statut de l'élection
        cur.execute("SELECT status, start_time, end_time, result_visible FROM election_status LIMIT 1;")
        status_row = cur.fetchone()
        
        election_status = status_row[0] if status_row else "SETUP"
        election_start = status_row[1] if status_row else None
        election_end = status_row[2] if status_row else None
        result_visible = status_row[3] if status_row else False
        
        # 1. Total des votes enregistrés (taille de la blockchain - 1 bloc genesis)
        cur.execute("SELECT COUNT(*) FROM blockchain WHERE index > 0;")
        total_votes = cur.fetchone()[0]

        # 2. Total des étudiants ayant voté
        cur.execute("SELECT COUNT(*) FROM students WHERE has_voted = TRUE;")
        total_students_voters = cur.fetchone()[0]

        # 3. Total des candidats validés
        cur.execute("SELECT COUNT(*) FROM candidates WHERE is_validated = TRUE;")
        total_validated_candidates = cur.fetchone()[0]

        # 4. Total des candidats en attente
        cur.execute("SELECT COUNT(*) FROM candidates WHERE is_validated = FALSE;")
        total_pending_candidates = cur.fetchone()[0]
        
        # >>>>>>>>>>>>>>>>>> DÉBUT DE LA CORRECTION DU BUG <<<<<<<<<<<<<<<<<<<<
        # 5. Total des étudiants éligibles (inscrits dans la table des votants 'students')
        # La table 'students' contient les étudiants qui se sont enregistrés et sont donc éligibles à voter.
        cur.execute("SELECT COUNT(*) FROM students;")
        total_eligible = cur.fetchone()[0] # <-- AJOUTÉ: La valeur manquante
        # >>>>>>>>>>>>>>>>>> FIN DE LA CORRECTION DU BUG <<<<<<<<<<<<<<<<<<<<<<
        
        # 6. Liste des candidats pour la modération
        cur.execute("""
            SELECT id, full_name, slogan, programme, photo_path, is_validated, created_at 
            FROM candidates 
            ORDER BY created_at DESC;
        """)
        candidates = [
            {
                'id': row[0],
                'full_name': row[1],
                'slogan': row[2],
                'programme': row[3],
                'photo_path': row[4],
                'is_validated': row[5],
                'created_at': row[6].strftime('%Y-%m-%d %H:%M:%S') if row[6] else 'N/A'
            }
            for row in cur.fetchall()
        ]
        
        # 7. Liste des étudiants pour la modération (seulement les 100 derniers)
        cur.execute("""
            SELECT id_numerique, nom, prenom, parcours, has_voted, created_at 
            FROM students 
            ORDER BY created_at DESC
            LIMIT 100;
        """)
        recent_students = [
            {
                'id_numerique': row[0],
                'nom': row[1],
                'prenom': row[2],
                'parcours': row[3],
                'has_voted': row[4],
                'created_at': row[5].strftime('%Y-%m-%d %H:%M:%S') if row[5] else 'N/A'
            }
            for row in cur.fetchall()
        ]

        cur.close()
        conn.close()

        # Le dictionnaire de contexte à passer au template
        return render_template('admin_dashboard.html',
            admin_username=admin_username,
            election_status=election_status,
            election_start=election_start,
            election_end=election_end,
            result_visible=result_visible,
            total_votes=total_votes,
            total_students_voters=total_students_voters,
            total_validated_candidates=total_validated_candidates,
            total_pending_candidates=total_pending_candidates,
            total_eligible=total_eligible, # <-- AJOUTÉ ICI POUR CORRIGER LE BUG
            candidates=candidates,
            recent_students=recent_students,
            message=request.args.get('message'),
            error=request.args.get('error')
        )
        
    except Exception as e:
        logger.error(f"Erreur dans admin_dashboard: {e}")
        if cur: cur.close()
        if conn: conn.close()
        return render_template('error_page.html', message=f"Erreur d'accès au tableau de bord: {e}"), 500


# --- ROUTES API (Logique Métier) ---

@app.route('/api/chain', methods=['GET'])
def get_chain():
    """Retourne la chaîne de blocs complète (pour l'explorateur)."""
    try:
        # Convertit chaque objet Block en dictionnaire pour la sérialisation JSON
        serializable_chain = [block.to_dict() for block in blockchain.chain]
        return jsonify(chain=serializable_chain, length=len(blockchain.chain))
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la chaîne: {e}")
        return jsonify({'error': 'Erreur interne lors de la récupération de la blockchain.'}), 500

@app.route('/api/student/self_register', methods=['POST'])
def self_register_student():
    """Endpoint pour l'auto-inscription d'un étudiant éligible."""
    data = request.get_json()
    nom = data.get('nom', '').strip().upper()
    prenom = data.get('prenom', '').strip().capitalize()
    parcours = data.get('parcours', '').strip().upper()
    
    if not all([nom, prenom, parcours]):
        return jsonify({'error': 'Tous les champs (Nom, Prénom, Parcours) sont requis.'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Vérifier si l'étudiant est dans la liste d'éligibilité (si elle existe et est utilisée)
        # Note: Si la table eligible_students est vide, cette vérification est ignorée.
        cur.execute("SELECT COUNT(*) FROM eligible_students;")
        total_eligible_records = cur.fetchone()[0]

        if total_eligible_records > 0:
            cur.execute("""
                SELECT id FROM eligible_students 
                WHERE nom = %s AND prenom = %s AND parcours = %s;
            """, (nom, prenom, parcours))
            if cur.fetchone() is None:
                return jsonify({'error': 'Vous n\'êtes pas dans la liste des étudiants éligibles. Contactez l\'administration.'}), 403

        # 2. Vérifier si l'étudiant a déjà un ID numérique
        cur.execute("""
            SELECT id_numerique FROM students 
            WHERE nom = %s AND prenom = %s AND parcours = %s;
        """, (nom, prenom, parcours))
        existing_id = cur.fetchone()

        if existing_id:
            # S'il existe, on lui redonne son ID
            return jsonify({
                'id_numerique': existing_id[0], 
                'message': 'Vous êtes déjà inscrit. Voici votre ID Numérique existant.'
            }), 200

        # 3. Générer un nouvel ID Numérique (UUID court ou hash)
        # Utilisation d'un hash pour un ID numérique unique et anonyme
        unique_string = f"{nom}{prenom}{parcours}{time.time()}"
        id_numerique = hashlib.sha256(unique_string.encode()).hexdigest()[:12].upper()
        
        # 4. Enregistrer dans la table des étudiants (votants)
        cur.execute("""
            INSERT INTO students (id_numerique, nom, prenom, parcours)
            VALUES (%s, %s, %s, %s);
        """, (id_numerique, nom, prenom, parcours))
        
        conn.commit()
        logger.info(f"Nouvel étudiant inscrit: {prenom} {nom} avec ID {id_numerique}")
        
        return jsonify({
            'success': 'Inscription réussie.',
            'id_numerique': id_numerique,
            'redirect_url': url_for('voter_login')
        }), 201

    except psycopg2.IntegrityError:
        # Devrait être capturé par le SELECT ci-dessus, mais en cas de course condition
        conn.rollback()
        return jsonify({'error': 'Un ID pour cet étudiant a déjà été généré.'}), 409
    except Exception as e:
        logger.error(f"Erreur d'auto-inscription étudiant: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur critique: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate():
    """Endpoint pour l'auto-inscription d'un candidat."""
    
    # 1. Vérification du statut de l'élection
    status = get_election_status()
    if status['status'] != 'SETUP':
        return jsonify({'error': "L'inscription des candidats est fermée."}), 403

    full_name = request.form.get('full_name', '').strip()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    photo_file = request.files.get('photo')

    if not all([full_name, slogan, programme, photo_file]):
        return jsonify({'error': 'Tous les champs (Nom, Slogan, Programme, Photo) sont requis.'}), 400

    # 2. Validation du contenu (pour s'assurer que les contraintes minimales sont respectées)
    if len(slogan.split()) > 100 or len(programme.split()) < 300:
        return jsonify({'error': 'Le slogan doit avoir moins de 100 mots et le programme doit avoir au moins 300 mots.'}), 400

    # 3. Sauvegarde sécurisée du fichier photo
    filename = secure_filename(full_name.replace(' ', '_') + '_' + str(uuid4()) + '.png')
    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        photo_file.save(photo_path)
    except Exception as e:
        logger.error(f"Échec de l'enregistrement du fichier photo: {e}")
        return jsonify({'error': "Échec de l'enregistrement du fichier photo."}), 500

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 4. Enregistrement dans la table des candidats
        # is_validated est initialement FALSE
        cur.execute("""
            INSERT INTO candidates (full_name, slogan, programme, photo_path, is_validated)
            VALUES (%s, %s, %s, %s, FALSE) RETURNING id;
        """, (full_name, slogan, programme, photo_path))
        
        candidate_id = cur.fetchone()[0]
        conn.commit()
        logger.info(f"Nouveau candidat en attente: {full_name} (ID: {candidate_id})")

        return jsonify({
            'success': 'Candidature enregistrée avec succès. En attente de validation par l\'administrateur.',
            'candidate_id': candidate_id
        }), 201

    except psycopg2.IntegrityError:
        conn.rollback()
        # Supprimer le fichier uploadé pour éviter les orphelins
        if os.path.exists(photo_path):
            os.remove(photo_path)
        return jsonify({'error': 'Un candidat avec ce nom complet existe déjà.'}), 409
    except Exception as e:
        logger.error(f"Erreur d'auto-inscription candidat: {e}")
        if conn: conn.rollback()
        # Supprimer le fichier uploadé
        if os.path.exists(photo_path):
            os.remove(photo_path)
        return jsonify({'error': f"Erreur critique: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/voter/login', methods=['POST'])
def voter_api_login():
    """Endpoint API pour la connexion d'un votant."""
    data = request.get_json()
    id_numerique = data.get('id_numerique', '').strip().upper()
    
    if not id_numerique:
        return jsonify({'error': 'L\'ID Numérique est requis.'}), 400

    status = get_election_status()
    if status['status'] != 'VOTING':
        return jsonify({'error': "Le vote n'est pas actif pour le moment."}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT has_voted FROM students WHERE id_numerique = %s;", (id_numerique,))
        student_data = cur.fetchone()
        
        if not student_data:
            return jsonify({'error': 'ID Numérique invalide. Veuillez vous inscrire ou vérifier votre ID.'}), 404
        
        has_voted = student_data[0]
        
        if has_voted:
            return jsonify({'error': 'Vous avez déjà voté.'}), 403
        
        return jsonify({
            'success': 'Connexion réussie.',
            'redirect_url': url_for('voting_page', id_numerique=id_numerique)
        }), 200

    except Exception as e:
        logger.error(f"Erreur de connexion votant: {e}")
        return jsonify({'error': f"Erreur critique: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/voter/cast_vote', methods=['POST'])
def cast_vote():
    """Endpoint API pour enregistrer un vote sur la blockchain."""
    data = request.get_json()
    voter_id = data.get('voter_id', '').strip().upper()
    candidate_id = data.get('candidate_id')
    
    if not all([voter_id, candidate_id]):
        return jsonify({'error': 'ID de votant et de candidat sont requis.'}), 400

    status = get_election_status()
    if status['status'] != 'VOTING':
        return jsonify({'error': "Le vote n'est pas actif."}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. Vérification du votant (s'il existe et n'a pas encore voté)
        cur.execute("SELECT id, has_voted FROM students WHERE id_numerique = %s FOR UPDATE;", (voter_id,))
        student_data = cur.fetchone()
        
        if not student_data:
            conn.rollback()
            return jsonify({'error': 'ID de votant invalide.'}), 404
        
        student_db_id, has_voted = student_data
        
        if has_voted:
            conn.rollback()
            return jsonify({'error': 'Ce votant a déjà voté.'}), 403

        # 2. Vérification du candidat (s'il est validé)
        cur.execute("SELECT id FROM candidates WHERE id = %s AND is_validated = TRUE;", (candidate_id,))
        if cur.fetchone() is None:
            conn.rollback()
            return jsonify({'error': 'Candidat invalide ou non validé.'}), 404

        # 3. Construction de la donnée de transaction (vote)
        vote_data = {
            'type': 'VOTE',
            'content': {
                'voter_id_hash': hashlib.sha256(voter_id.encode()).hexdigest(), # Stocker le hash du votant, pas l'ID brut
                'candidate_id': candidate_id,
            }
        }

        # 4. Ajouter le vote à la blockchain (et miner le bloc)
        new_block = blockchain.add_block(vote_data)
        
        if not new_block:
            conn.rollback()
            return jsonify({'error': 'Échec de l\'ajout du vote à la blockchain (Minage échoué).'}), 500

        # 5. Marquer l'étudiant comme ayant voté
        cur.execute("UPDATE students SET has_voted = TRUE WHERE id = %s;", (student_db_id,))
        
        conn.commit()
        logger.info(f"Vote enregistré pour le candidat {candidate_id} par ID hashé. Bloc #{new_block.index}")
        
        return jsonify({
            'success': 'Vote enregistré sur la blockchain.',
            'block_index': new_block.index
        }), 201

    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement du vote: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur critique lors du vote: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# --- API d'Administration ---

@app.route('/api/admin/candidate_action/<int:candidate_id>', methods=['POST'])
@admin_login_required
def candidate_action(candidate_id):
    """Valide ou supprime un candidat."""
    data = request.get_json()
    action = data.get('action') # 'validate' ou 'delete'

    if action not in ['validate', 'delete']:
        return jsonify({'error': 'Action invalide.'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    
    photo_path = None
    
    try:
        if action == 'validate':
            cur.execute("UPDATE candidates SET is_validated = TRUE WHERE id = %s;", (candidate_id,))
            if cur.rowcount == 0:
                conn.rollback()
                return jsonify({'error': 'Candidat non trouvé.'}), 404
            conn.commit()
            logger.info(f"Candidat ID {candidate_id} validé par l'admin.")
            return jsonify({'success': 'Candidat validé avec succès.'}), 200
            
        elif action == 'delete':
            # 1. Récupérer le chemin de la photo
            cur.execute("SELECT photo_path FROM candidates WHERE id = %s;", (candidate_id,))
            row = cur.fetchone()
            if row:
                photo_path = row[0]
            
            # 2. Supprimer le candidat de la DB
            cur.execute("DELETE FROM candidates WHERE id = %s;", (candidate_id,))
            
            if cur.rowcount == 0:
                conn.rollback()
                return jsonify({'error': 'Candidat non trouvé.'}), 404
            
            conn.commit()
            
            # 3. Supprimer le fichier photo
            if photo_path and os.path.exists(photo_path):
                os.remove(photo_path)
                logger.info(f"Fichier photo supprimé: {photo_path}")
            
            logger.info(f"Candidat ID {candidate_id} supprimé par l'admin.")
            return jsonify({'success': 'Candidat et photo supprimés avec succès.'}), 200
            
    except Exception as e:
        logger.error(f"Erreur d'action candidat: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur critique lors de l'action: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/admin/election_action', methods=['POST'])
@admin_login_required
def election_action():
    """Démarre, arrête l'élection ou rend les résultats visibles/invisibles."""
    data = request.get_json()
    action = data.get('action') # 'start', 'stop', 'toggle_results'

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # Récupérer le statut actuel
        cur.execute("SELECT status, result_visible FROM election_status WHERE id = 1;")
        status_row = cur.fetchone()
        current_status = status_row[0] if status_row else 'SETUP'
        current_visible = status_row[1] if status_row else False
        
        success_message = "Opération effectuée."

        if action == 'start':
            if current_status != 'SETUP':
                return jsonify({'error': 'Le vote est déjà en cours ou terminé.'}), 400
            
            # Vérifier qu'il y a au moins 2 candidats validés pour commencer
            cur.execute("SELECT COUNT(*) FROM candidates WHERE is_validated = TRUE;")
            if cur.fetchone()[0] < 2:
                return jsonify({'error': "Au moins 2 candidats validés sont requis pour démarrer le vote."}), 400
            
            start_time = datetime.now(timezone.utc)
            # Mise à jour du statut
            cur.execute("""
                UPDATE election_status 
                SET status = 'VOTING', start_time = %s, end_time = NULL, result_visible = FALSE
                WHERE id = 1;
            """, (start_time,))
            success_message = f"Élection démarrée à {start_time.strftime('%Y-%m-%d %H:%M:%S')} (UTC). Le vote est ouvert."

        elif action == 'stop':
            if current_status != 'VOTING':
                return jsonify({'error': 'Le vote n\'est pas en cours.'}), 400

            end_time = datetime.now(timezone.utc)
            # Mise à jour du statut
            cur.execute("""
                UPDATE election_status 
                SET status = 'FINISHED', end_time = %s
                WHERE id = 1;
            """, (end_time,))
            success_message = f"Élection arrêtée à {end_time.strftime('%Y-%m-%d %H:%M:%S')} (UTC). Le vote est fermé."

        elif action == 'toggle_results':
            new_visibility = not current_visible
            cur.execute("""
                UPDATE election_status 
                SET result_visible = %s
                WHERE id = 1;
            """, (new_visibility,))
            success_message = f"Visibilité des résultats: {'Activée' if new_visibility else 'Désactivée'}."

        else:
            conn.rollback()
            return jsonify({'error': 'Action non reconnue.'}), 400

        conn.commit()
        logger.info(success_message)
        return jsonify({'success': success_message}), 200

    except Exception as e:
        logger.error(f"Erreur d'action élection: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur critique lors de l'action: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/admin/manage_students', methods=['POST'])
@admin_login_required
def manage_students():
    """Importe une liste d'éligibilité ou réinitialise la liste des votants/éligibles."""
    action = request.form.get('action')
    file = request.files.get('file')

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        if action == 'import' and file:
            if not file.filename.endswith('.xlsx'):
                return jsonify({'error': 'Format de fichier non supporté. Veuillez utiliser un fichier .xlsx.'}), 400
                
            # 1. Lire le fichier dans un DataFrame Pandas via un fichier temporaire
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                file.save(tmp.name)
                tmp_path = tmp.name

            try:
                # Lecture de la première feuille (ou de la feuille 'Eligibles' si elle existe)
                df = pd.read_excel(tmp_path)
                
                # S'assurer que les colonnes nécessaires existent
                if not all(col in df.columns for col in ['Nom', 'Prénom', 'Parcours']):
                    os.remove(tmp_path)
                    return jsonify({'error': 'Le fichier Excel doit contenir les colonnes: Nom, Prénom, Parcours.'}), 400

                # Normaliser les données (majuscules/première lettre en majuscule)
                df['Nom'] = df['Nom'].str.upper().str.strip()
                df['Prénom'] = df['Prénom'].str.capitalize().str.strip()
                df = df.dropna(subset=['Nom', 'Prénom', 'Parcours']) # Supprimer les lignes avec valeurs manquantes critiques
                
                # 2. Vider la table d'éligibilité existante
                cur.execute("TRUNCATE TABLE eligible_students RESTART IDENTITY;")
                
                # 3. Préparer les données pour l'insertion
                eligible_list = df[['Nom', 'Prénom', 'Parcours']].values.tolist()
                
                # 4. Insertion en masse dans eligible_students
                insert_query = "INSERT INTO eligible_students (nom, prenom, parcours) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING;"
                for row in eligible_list:
                    cur.execute(insert_query, tuple(row))
                
                conn.commit()
                os.remove(tmp_path)
                
                logger.info(f"Importation d'éligibilité réussie: {len(eligible_list)} enregistrements.")
                return jsonify({'success': f"Liste d'éligibilité importée avec succès. {len(eligible_list)} étudiants sont maintenant éligibles."}), 200

            except Exception as e:
                logger.error(f"Erreur de lecture/importation du fichier Excel: {e}")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                conn.rollback()
                return jsonify({'error': f"Erreur de traitement du fichier: {e}"}), 500

        elif action == 'reset_students':
            # Vider la liste des votants (students)
            cur.execute("TRUNCATE TABLE students RESTART IDENTITY;")
            conn.commit()
            logger.info("Liste des votants (students) réinitialisée.")
            return jsonify({'success': "Liste des votants (students) effacée avec succès."}), 200
        
        elif action == 'reset_eligible':
            # Vider la liste d'éligibilité importée (eligible_students)
            cur.execute("TRUNCATE TABLE eligible_students RESTART IDENTITY;")
            conn.commit()
            logger.info("Liste d'éligibilité (eligible_students) réinitialisée.")
            return jsonify({'success': "Liste d'éligibilité (eligible_students) effacée avec succès."}), 200

        else:
            return jsonify({'error': 'Action ou fichier invalide.'}), 400

    except Exception as e:
        logger.error(f"Erreur de gestion des étudiants/éligibles: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur critique lors de la gestion: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/admin/reset_all', methods=['POST'])
@admin_login_required
def reset_all_data():
    """Réinitialise complètement l'application (Toutes les tables, blockchain, et images)."""
    data = request.get_json()
    confirm = data.get('confirm')

    if confirm != 'CONFIRM_RESET_ALL_VOTE_ESCEN':
        return jsonify({'error': 'Confirmation de sécurité incorrecte.'}), 403

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        # 1. Supprimer toutes les tables de données
        cur.execute("TRUNCATE TABLE students RESTART IDENTITY;")
        cur.execute("TRUNCATE TABLE candidates RESTART IDENTITY;")
        cur.execute("TRUNCATE TABLE blockchain RESTART IDENTITY;")
        cur.execute("TRUNCATE TABLE eligible_students RESTART IDENTITY;")
        
        # 2. Réinitialiser le statut de l'élection
        cur.execute("""
            UPDATE election_status 
            SET status = 'SETUP', start_time = NULL, end_time = NULL, result_visible = FALSE
            WHERE id = 1;
        """)
        
        conn.commit()

        # 3. Supprimer les fichiers de photos des candidats
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                if os.path.isfile(file_path) and not filename.startswith('default'):
                    os.unlink(file_path)
            except Exception as e:
                logger.error(f"Erreur lors de la suppression du fichier {file_path}: {e}")
        
        # 4. Recharger la blockchain (créera le nouveau bloc genesis)
        global blockchain
        blockchain = Blockchain() 
        
        # Déconnexion de l'administrateur
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        
        return jsonify({'success': "Système de vote entièrement réinitialisé. Les données Votants, Candidats, Blockchain et Éligibilité ont été effacées."}), 200
    except Exception as e:
        logger.error(f"Erreur de réinitialisation: {e}")
        conn.rollback()
        return jsonify({'error': f"Erreur critique lors de la réinitialisation : {e}"}), 500
    finally:
        # Les connexions sont gérées à l'intérieur de la fonction.
        if cur: cur.close()
        if conn: conn.close()


# --- HOOK D'APPLICATION ---
# S'assure que la base de données est initialisée au lancement de l'application
# Si la connexion DB échoue, l'application fonctionnera sans persistence (mode DEBUG/SETUP local)
# mais en production, elle nécessitera la connexion DB.
with app.app_context():
    try:
        init_db()
        # Recharge la blockchain après init_db pour être sûr d'avoir le bloc genesis
        # S'il n'existait pas avant, il a été créé par init_db.
        blockchain = Blockchain()
        if not blockchain.chain:
            logger.error("Démarrage critique: La blockchain n'a pas pu être initialisée avec le bloc Genesis.")
        else:
            logger.info(f"DB initialisée et Blockchain chargée (taille: {len(blockchain.chain)} blocs).")
    except Exception as e:
        logger.error(f"Erreur CRITIQUE au démarrage: {e}")
        # En production, cela peut entraîner l'échec de l'application si la DB est requise.
        
        
if __name__ == '__main__':
    # Ceci est utilisé seulement pour le développement local.
    # En production (Render), le 'Start Command' appelle gunicorn directement.
    print("ATTENTION: Pour la production, utilisez GUNICORN (Start Command: gunicorn serveur_vote:app).")
    # Pour le débogage local avec un serveur Flask de développement:
    # app.run(host='0.0.0.0', port=5000, debug=True)
    pass # Laisser vide pour la gestion par Gunicorn/Render.