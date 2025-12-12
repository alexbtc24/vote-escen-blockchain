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

# --- CONFIGURATION INITIALE SIMPLIFIÉE ---
app = Flask(__name__)
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
# logique load_data/save_data est désactivée.
DATA_DIR = 'database'
os.makedirs(DATA_DIR, exist_ok=True) 

# Fichiers (Définitions conservées mais inutilisées pour la persistence)
VOTERS_FILE = os.path.join(DATA_DIR, 'voters.json') 
CANDIDATES_FILE = os.path.join(DATA_DIR, 'candidates.json')
VOTE_CHAIN_FILE = os.path.join(DATA_DIR, 'vote_chain.json')
ADMIN_USERS_FILE = os.path.join(DATA_DIR, 'admin_users.json')
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
ELIGIBILITY_LIST_FILE = os.path.join(DATA_DIR, 'eligibility_list.json') 

CANDIDATE_IMAGES_DIR = 'static/candidate_images'
os.makedirs(CANDIDATE_IMAGES_DIR, exist_ok=True)


# --- FONCTIONS DÉSACTIVÉES/NON UTILISÉES EN PRODUCTION PERSISTANTE ---
# La logique de chargement/sauvegarde de fichiers JSON est désactivée pour la persistence DB.
def load_data(filepath, default_data):
    # Ceci est conservé pour ne pas casser d'éventuelles références indirectes dans l'ancien code, 
    # mais n'est plus utilisé pour les données critiques.
    return default_data 

def save_data(filepath, data):
    # Désactivé pour la persistence DB
    pass

# Définitions de variables globales conservées (mais remplacées par des fonctions ci-dessous)
# Ces variables globales servent uniquement pour le style de l'ancien code.
DEFAULT_ADMINS = {
    'admin': {'hash': generate_password_hash('escenpass'), 'label': 'Administrateur Unique', 'role': 'ADMIN_INSTITUTION'} 
}

DEFAULT_SETTINGS = {
    'candidacy_open': False,  
    'election_status': 'SETUP', # SETUP, VOTING, CLOSED
    'voting_status': 'CLOSED',  # OPEN/CLOSED (contrôlé par l'admin)
    'results_visibility': 'HIDDEN' # VISIBLE/HIDDEN (contrôlé par l'admin)
}
# ADMIN_USERS, VOTERS, CANDIDATES, ELIGIBILITY_LIST, SETTINGS ne sont plus chargés ici.


# --- NOUVELLES FONCTIONS DE CONNEXION À LA BASE DE DONNÉES ---
def get_db_connection():
    """Crée et retourne une connexion à la base de données PostgreSQL."""
    try:
        # Récupère l'URL de la BDD depuis les variables d'environnement (Render)
        database_url = os.environ.get('DATABASE_URL')
        if not database_url:
            # En environnement de développement local, vous pouvez définir une URL de test ici:
            # database_url = "postgresql://user:password@host:port/dbname"
            logger.error("DATABASE_URL n'est pas définie. Connexion à la BDD impossible.")
            # Permet de continuer si la connexion n'est pas essentielle (comme pour le mode DEBUG/SETUP local)
            return None
        
        # Rend l'URL compatible avec psycopg2 si elle est au format Heroku/Render
        # Ceci est nécessaire pour les chaînes de connexion qui commencent par 'postgres://'
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)

        conn = psycopg2.connect(database_url)
        return conn
    except Exception as e:
        logger.error(f"Erreur de connexion à PostgreSQL: {e}")
        # En cas d'échec critique en production, nous devons laisser l'application planter.
        # En local, on retourne None pour tenter de gérer l'erreur plus bas.
        return None

def init_db():
    """Crée les tables de base de données si elles n'existent pas et insère les données initiales."""
    conn = get_db_connection()
    if not conn:
        logger.warning("DB non connectée. L'application démarrera en mode sans persistence.")
        return 
    
    cur = None
    try:
        cur = conn.cursor()
        
        # 1. TABLE DES VOTANTS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS voters (
                id_numerique VARCHAR(255) PRIMARY KEY,
                eligibility_key VARCHAR(255) NOT NULL,
                has_voted BOOLEAN DEFAULT FALSE,
                registration_time TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 2. TABLE DES CANDIDATS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS candidates (
                candidate_id VARCHAR(255) PRIMARY KEY,
                nom VARCHAR(255) NOT NULL,
                prenom VARCHAR(255) NOT NULL,
                parcours VARCHAR(255) NOT NULL,
                photo_path VARCHAR(500),
                slogan TEXT,
                programme TEXT,
                is_validated BOOLEAN DEFAULT FALSE,
                registered_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # 3. TABLE DE LA BLOCKCHAIN
        # Nous stockons chaque bloc comme une ligne
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                block_index INTEGER PRIMARY KEY,
                timestamp VARCHAR(255) NOT NULL,
                payload JSONB NOT NULL,
                previous_hash VARCHAR(64) NOT NULL,
                hash VARCHAR(64) NOT NULL,
                proof INTEGER NOT NULL,
                type VARCHAR(50) NOT NULL
            );
        """)
        
        # 4. TABLE DES PARAMÈTRES
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)

        # 5. TABLE DES ADMINISTRATEURS
        cur.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                username VARCHAR(255) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                label VARCHAR(255) 
            );
        """)

        # 6. TABLE DE L'ÉLIGIBILITÉ (WHITELIST)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS eligibility_list (
                eligibility_key VARCHAR(255) PRIMARY KEY
            );
        """)
        
        # Commit de toutes les créations de tables
        conn.commit()
        
        # --- Initialisation des données par défaut ---
        
        # Initialisation des administrateurs par défaut (si la table est vide)
        initial_admin_users = {
            'ADMIN_INSTITUTION': {'hash': generate_password_hash('admin_inst'), 'label': 'Administrateur Institution', 'role': 'ADMIN_INSTITUTION'},
            'CONSENSUS_STUDENT_1': {'hash': generate_password_hash('student1'), 'label': 'Étudiant Consensus 1', 'role': 'CONSENSUS'},
            'CONSENSUS_STUDENT_2': {'hash': generate_password_hash('student2'), 'label': 'Étudiant Consensus 2', 'role': 'CONSENSUS'},
        }
        
        for username, data in initial_admin_users.items():
            # Utilisation de ON CONFLICT DO NOTHING pour éviter les doublons à chaque démarrage
            cur.execute("""
                INSERT INTO admin_users (username, password_hash, role, label)
                VALUES (%s, %s, %s, %s) ON CONFLICT (username) DO NOTHING;
            """, (username, data['hash'], data['role'], data['label']))
        conn.commit()
        
        # Initialisation des paramètres par défaut
        default_settings = {
            'candidacy_open': 'False',
            'election_status': 'SETUP', 
            'voting_status': 'CLOSED', 
            'results_visibility': 'HIDDEN' 
        }
        for key, value in default_settings.items():
            cur.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING;", (key, value))
        conn.commit()

        # Initialisation du bloc GENESIS si la table blockchain est vide
        cur.execute("SELECT COUNT(*) FROM blockchain;")
        if cur.fetchone()[0] == 0:
            logger.info("Création du bloc Genesis...")
            genesis_payload = {'msg': 'Lancement Réseau'}
            previous_hash = '0'
            # Utilisation du hash du bloc 0 (proof=1) pour la première entrée
            hash_genesis_calc = hashlib.sha256(f'0{datetime.now(timezone.utc).isoformat()}{json.dumps(genesis_payload)}{previous_hash}1'.lower().encode('utf-8')).hexdigest()

            cur.execute("""
                INSERT INTO blockchain (block_index, timestamp, payload, previous_hash, hash, proof, type)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (0, datetime.now(timezone.utc).isoformat(), json.dumps(genesis_payload), '0', hash_genesis_calc, 1, 'GENESIS'))
            conn.commit()


    except Exception as e:
        logger.error(f"Échec de l'initialisation de la BDD : {e}")
        raise
    finally:
        if cur: cur.close()
        if conn: conn.close()

# --- NOUVELLES FONCTIONS D'ACCÈS/MUTATION DE LA BASE DE DONNÉES ---

def get_admin_users_from_db():
    conn = get_db_connection()
    if not conn: return DEFAULT_ADMINS 
    cur = conn.cursor()
    try:
        cur.execute("SELECT username, password_hash, role, label FROM admin_users;")
        admins = {row[0]: {'hash': row[1], 'label': row[3], 'role': row[2]} for row in cur.fetchall()}
        return admins
    except Exception as e:
        logger.error(f"Erreur get_admin_users_from_db: {e}")
        return DEFAULT_ADMINS
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_settings_from_db():
    conn = get_db_connection()
    if not conn: return DEFAULT_SETTINGS
    cur = conn.cursor()
    try:
        cur.execute("SELECT key, value FROM settings;")
        # Convertir les chaînes de caractères 'True'/'False' en booléens si nécessaire
        settings = {}
        for key, value in cur.fetchall():
            if value.lower() == 'true':
                settings[key] = True
            elif value.lower() == 'false':
                settings[key] = False
            else:
                settings[key] = value
        # Fusionner avec les défauts au cas où une nouvelle clé n'est pas dans la DB
        return {**DEFAULT_SETTINGS, **settings}
    except Exception as e:
        logger.error(f"Erreur get_settings_from_db: {e}")
        return DEFAULT_SETTINGS
    finally:
        if cur: cur.close()
        if conn: conn.close()


def update_setting_in_db(key, value):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    # S'assure que True/False sont stockés comme 'True'/'False' dans la DB (TEXT)
    value_str = str(value) 
    try:
        cur.execute("""
            INSERT INTO settings (key, value) VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
        """, (key, value_str))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur update_setting_in_db: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def get_eligibility_list_from_db():
    conn = get_db_connection()
    if not conn: return {} 
    cur = conn.cursor()
    try:
        cur.execute("SELECT eligibility_key FROM eligibility_list;")
        eligibility_list = {row[0]: True for row in cur.fetchall()}
        return eligibility_list
    except Exception as e:
        logger.error(f"Erreur get_eligibility_list_from_db: {e}")
        return {}
    finally:
        if cur: cur.close()
        if conn: conn.close()


def save_eligibility_list_to_db(eligibility_list):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        # 1. Effacer l'ancienne liste
        cur.execute("TRUNCATE eligibility_list;")
        # 2. Insérer la nouvelle liste
        for key in eligibility_list.keys():
            cur.execute("INSERT INTO eligibility_list (eligibility_key) VALUES (%s);", (key,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur save_eligibility_list_to_db: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def get_voters_from_db():
    conn = get_db_connection()
    if not conn: return {} 
    cur = conn.cursor()
    try:
        cur.execute("SELECT id_numerique, eligibility_key, has_voted, registration_time FROM voters;")
        voters = {}
        for row in cur.fetchall():
            voters[row[0]] = {
                'id_numerique': row[0],
                'eligibility_key': row[1],
                'has_voted': row[2],
                'registration_time': row[3].isoformat() if row[3] else None
            }
        return voters
    except Exception as e:
        logger.error(f"Erreur get_voters_from_db: {e}")
        return {}
    finally:
        if cur: cur.close()
        if conn: conn.close()


def register_voter_in_db(voter_data):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO voters (id_numerique, eligibility_key, has_voted, registration_time)
            VALUES (%s, %s, %s, %s);
        """, (
            voter_data['id_numerique'],
            voter_data['eligibility_key'],
            voter_data['has_voted'],
            datetime.now(timezone.utc) # Utilisez l'objet datetime pour le type TIMESTAMP
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur register_voter_in_db: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def update_voter_has_voted(id_numerique, status=True):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE voters SET has_voted = %s WHERE id_numerique = %s;
        """, (status, id_numerique))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur update_voter_has_voted: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def get_candidates_from_db():
    conn = get_db_connection()
    if not conn: return {} 
    cur = conn.cursor()
    try:
        cur.execute("SELECT candidate_id, nom, prenom, parcours, photo_path, slogan, programme, is_validated, registered_at FROM candidates;")
        candidates = {}
        for row in cur.fetchall():
            candidates[row[0]] = {
                'candidate_id': row[0],
                'nom': row[1],
                'prenom': row[2],
                'parcours': row[3],
                'photo_path': row[4],
                'slogan': row[5],
                'programme': row[6],
                'is_validated': row[7],
                'registered_at': row[8].isoformat() if row[8] else None
            }
        return candidates
    except Exception as e:
        logger.error(f"Erreur get_candidates_from_db: {e}")
        return {}
    finally:
        if cur: cur.close()
        if conn: conn.close()


def add_candidate_to_db(candidate_data):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO candidates (candidate_id, nom, prenom, parcours, photo_path, slogan, programme, is_validated, registered_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """, (
            candidate_data['candidate_id'],
            candidate_data['nom'],
            candidate_data['prenom'],
            candidate_data['parcours'],
            candidate_data['photo_path'],
            candidate_data['slogan'],
            candidate_data['programme'],
            candidate_data.get('is_validated', False), # S'assurer d'avoir un booléen
            datetime.now(timezone.utc)
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur add_candidate_to_db: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def update_candidate_status_in_db(candidate_id, is_validated):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE candidates SET is_validated = %s WHERE candidate_id = %s;
        """, (is_validated, candidate_id))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur update_candidate_status_in_db: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def delete_candidate_from_db(candidate_id):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            DELETE FROM candidates WHERE candidate_id = %s;
        """, (candidate_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur delete_candidate_from_db: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def get_chain_from_db():
    conn = get_db_connection()
    if not conn: return []
    cur = conn.cursor()
    try:
        # Ordonné par index pour garantir l'ordre
        cur.execute("SELECT block_index, timestamp, payload, previous_hash, hash, proof, type FROM blockchain ORDER BY block_index ASC;")
        chain = []
        for row in cur.fetchall():
            chain.append({
                'index': row[0],
                'timestamp': row[1],
                'payload': row[2], # Ceci est déjà un objet JSONB
                'previous_hash': row[3],
                'hash': row[4],
                'proof': row[5],
                'type': row[6]
            })
        return chain
    except Exception as e:
        logger.error(f"Erreur get_chain_from_db: {e}")
        return []
    finally:
        if cur: cur.close()
        if conn: conn.close()


def add_block_to_db(block):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO blockchain (block_index, timestamp, payload, previous_hash, hash, proof, type)
            VALUES (%s, %s, %s, %s, %s, %s, %s);
        """, (
            block['index'],
            block['timestamp'],
            json.dumps(block['payload']), # S'assurer que le payload est bien en JSON string pour l'insertion
            block['previous_hash'],
            block['hash'],
            block['proof'],
            block['type']
        ))
        conn.commit()
        return True
    except psycopg2.errors.UniqueViolation as e:
        logger.warning(f"Bloc déjà existant (index {block['index']}): {e}")
        conn.rollback()
        return False
    except Exception as e:
        logger.error(f"Erreur add_block_to_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


# --- FIN NOUVELLES FONCTIONS DE BASE DE DONNÉES ---

def sha256(s):
    # Ajout du .lower() pour standardiser le hash
    return hashlib.sha256(s.lower().encode('utf-8')).hexdigest()

def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée pour Excel."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ['xlsx', 'xls']

# --- UTILS DONNÉES GLOBALES (Simulations) ---
# Ces fonctions remplacent les variables globales et lisent DANS LA BASE DE DONNÉES à la demande.
# Ceci permet de ne pas surcharger la mémoire avec une copie de la chaîne.
def get_voters():
    return get_voters_from_db()

def get_candidates():
    return get_candidates_from_db()

def get_settings():
    return get_settings_from_db()

def get_admin_users():
    return get_admin_users_from_db()

def get_eligibility_list():
    return get_eligibility_list_from_db()
# ------------------------------------------------------------------


# --- BLOCKCHAIN ---
class Blockchain:
    def __init__(self):
        # Charge la chaîne de la base de données
        self.chain = get_chain_from_db() 
        self.current_votes = []
        if not self.chain:
            # Si la chaîne est vide, cela signifie que init_db n'a pas pu créer le Genesis block
            # On ne tente pas de recréer le bloc ici, on suppose que init_db s'en charge.
            logger.warning("La chaîne est vide, vérifiez l'initialisation de la DB.")
        
    def create_block(self, proof, previous_hash, type="VOTE", payload=None):
        # Récupère le dernier état de la chaîne avant de créer le bloc
        # C'est CRUCIAL car la chaîne est partagée
        self.chain = get_chain_from_db()
        
        last_block_hash = self.chain[-1]['hash'] if self.chain else '0'
        # Utilise le hash du dernier bloc fourni ou '0' si c'est le bloc genesis
        if last_block_hash != previous_hash and self.chain: 
            logger.error(f"Erreur: Le previous_hash fourni ({previous_hash}) ne correspond pas au dernier hash de la chaîne ({last_block_hash}).")
            return None # Échec de la création du bloc
            
        block = {
            'index': len(self.chain) if self.chain else 0, # CORRECTION: Si la chaîne est vide, index 0
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'payload': payload if payload is not None else self.current_votes,
            'previous_hash': previous_hash,
            'proof': proof,
            'type': type
        }
        
        # Le hash est calculé avec toutes les données du bloc (sauf lui-même)
        block['hash'] = self.hash_block(block) 
        
        # Ajout à la base de données
        if add_block_to_db(block):
            self.chain.append(block)
            self.current_votes = [] # Réinitialisation des transactions en attente
            return block
        else:
            logger.error(f"Échec de l'enregistrement du bloc {block['index']} dans la BDD.")
            return None

    @staticmethod
    def hash_block(block):
        # Crée une copie du bloc sans le hash (s'il existe déjà)
        block_copy = block.copy()
        block_copy.pop('hash', None)
        # Assure que le dictionnaire est ordonné pour des hashes cohérents (JSON stringifié)
        block_string = json.dumps(block_copy, sort_keys=True) 
        return sha256(block_string)

    @property
    def last_block(self):
        # Récupère le dernier bloc directement de la base de données, pour être sûr
        current_chain = get_chain_from_db()
        return current_chain[-1] if current_chain else None

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        # Complexité faible pour le PoW de démo (commence par 3 zéros)
        return guess_hash[:3] == "000"

    def valid_chain(self, chain):
        # La validation de chaîne nécessite une lecture complète, on s'assure d'avoir la plus récente
        chain = get_chain_from_db()
        
        if not chain:
            return True # Chaîne vide est valide (avant Genesis)
            
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            logger.debug(f'Vérification du bloc {block["index"]}')

            # Vérifie que le hash stocké correspond au hash recalculé
            if block['hash'] != self.hash_block(block):
                logger.error(f"Hash invalide au bloc {block['index']}")
                return False

            # Vérifie que le previous_hash est correct
            if block['previous_hash'] != last_block['hash']:
                logger.error(f"previous_hash invalide au bloc {block['index']}")
                return False

            # Vérifie que la Proof of Work est correcte
            if not self.valid_proof(last_block['proof'], block['proof']):
                logger.error(f"PoW invalide au bloc {block['index']}")
                return False

            last_block = block
            current_index += 1

        return True

    def add_vote(self, voter_id, candidate_id):
        """Ajoute le vote et mine immédiatement un bloc."""
        
        # 1. Vérifie si le vote est valide
        VOTERS = get_voters()
        CANDIDATES = get_candidates()
        
        voter = VOTERS.get(voter_id)
        candidate = CANDIDATES.get(candidate_id)

        if not voter or voter.get('has_voted'):
            return {'error': "Votant invalide ou a déjà voté."}, 409
        if not candidate or not candidate.get('is_validated'):
            return {'error': "Candidat invalide ou non validé."}, 409
            
        # 2. Mine le bloc
        last_block = self.last_block
        if not last_block:
            logger.error("Pas de bloc 'last_block'. Chaîne corrompue ou non initialisée.")
            return {'error': "Erreur interne: Chaîne non initialisée."}, 500
            
        last_proof = last_block['proof']
        proof = self.proof_of_work(last_proof)

        # Payload du vote
        vote_payload = {
            'voter_id_hash': sha256(voter_id), # On stocke le HASH de l'ID du votant pour l'anonymisation
            'candidate_id': candidate_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # 3. Crée le bloc et met à jour le statut du votant
        new_block = self.create_block(proof, last_block['hash'], type="VOTE", payload=vote_payload)
        
        if new_block:
            # Mise à jour du statut du votant dans la base de données
            update_voter_has_voted(voter_id, status=True) 
            return new_block
        else:
            return {'error': "Échec de l'ajout du bloc (erreur DB/Consensus)."}, 500

    def add_event(self, event_type, payload):
        """Ajoute un événement (non-vote) à la blockchain."""
        last_block = self.last_block
        if not last_block:
            logger.error("Pas de bloc 'last_block'. Chaîne corrompue ou non initialisée.")
            return None
            
        last_proof = last_block['proof']
        proof = self.proof_of_work(last_proof)
        
        new_block = self.create_block(proof, last_block['hash'], type=event_type, payload=payload)
        return new_block


# Instanciation de la Blockchain (chargera de la DB via __init__)
blockchain = Blockchain()


# --- DÉCORATEURS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', error="Accès Administrateur Requis."))
        return f(*args, **kwargs)
    return decorated_function

def institution_admin_required(f):
    @wraps(f)
    @admin_required
    def decorated_function(*args, **kwargs):
        ADMIN_USERS = get_admin_users()
        username = session.get('admin_username')
        if ADMIN_USERS.get(username, {}).get('role') != 'ADMIN_INSTITUTION':
            return redirect(url_for('admin_dashboard', error="Opération Institutionnelle Requis."))
        return f(*args, **kwargs)
    return decorated_function

# --- FONCTIONS UTILITAIRES ---
def calculate_results():
    """Calcule les résultats à partir de la chaîne de vote."""
    CANDIDATES = get_candidates()
    
    # Récupère la chaîne de la base de données
    chain = get_chain_from_db() 
    
    # 1. Compter les votes
    vote_counts = {cid: 0 for cid in CANDIDATES.keys()}
    total_votes = 0
    
    for block in chain:
        if block['type'] == 'VOTE':
            try:
                candidate_id = block['payload']['candidate_id']
                if candidate_id in vote_counts:
                    vote_counts[candidate_id] += 1
                    total_votes += 1
            except KeyError:
                logger.warning(f"Bloc de vote invalide à l'index {block['index']}")
                continue # Ignore les blocs de vote corrompus

    # 2. Préparer les résultats formatés
    results = []
    
    # Inclure uniquement les candidats validés
    validated_candidates = [c for c in CANDIDATES.values() if c.get('is_validated')]
    
    for candidate_data in validated_candidates:
        cid = candidate_data['candidate_id']
        votes = vote_counts.get(cid, 0)
        percentage = (votes / total_votes * 100) if total_votes > 0 else 0
        
        results.append({
            'candidate_id': cid,
            'nom': candidate_data['nom'],
            'prenom': candidate_data['prenom'],
            'parcours': candidate_data['parcours'],
            'photo_path': candidate_data['photo_path'],
            'slogan': candidate_data['slogan'],
            'votes': votes,
            'percentage': round(percentage, 2)
        })
    
    # Trier par nombre de votes
    results.sort(key=lambda x: x['votes'], reverse=True)
    
    return results, total_votes

def get_voters_stats():
    """Retourne les statistiques des votants/éligibles à partir de la base de données."""
    VOTERS = get_voters()
    ELIGIBILITY_LIST = get_eligibility_list()
    
    total_eligible = len(ELIGIBILITY_LIST)
    total_students_voters = len(VOTERS)
    total_students_voted = sum(1 for v in VOTERS.values() if v.get('has_voted'))
    
    # Compte combien d'éligibles (clés) ne sont PAS encore inscrits
    eligible_to_register_count = total_eligible - total_students_voters
    
    return {
        'total_eligible': total_eligible,
        'eligible_to_register': max(0, eligible_to_register_count),
        'total_students_voters': total_students_voters,
        'total_students_voted': total_students_voted
    }

# --- ROUTES D'ACCÈS PUBLIQUES (FRONTEND) ---

@app.route('/')
def index():
    SETTINGS = get_settings()
    election_status = SETTINGS.get('election_status', 'SETUP')
    return render_template('index.html', election_status=election_status)

# --- ROUTE INSCRIPTION ÉTUDIANT (SELF-REGISTER) ---
@app.route('/self_register_student')
def self_register_student_get():
    SETTINGS = get_settings()
    election_status = SETTINGS.get('election_status', 'SETUP')
    return render_template('self_register_student.html', election_status=election_status)


@app.route('/api/student/self_register', methods=['POST'])
def self_register_student_post():
    SETTINGS = get_settings()
    if SETTINGS.get('election_status') not in ['SETUP', 'VOTING']:
        return jsonify({'error': "L'inscription est fermée, l'élection est soit fermée soit en cours sans inscription."}), 403

    data = request.get_json()
    nom = data.get('nom', '').strip().upper()
    prenom = data.get('prenom', '').strip().upper()
    parcours = data.get('parcours', '').strip().upper()

    if not all([nom, prenom, parcours]):
        return jsonify({'error': "Tous les champs sont requis."}), 400

    # 1. Construction de la clé d'éligibilité et vérification dans la DB
    eligibility_key = sha256(f"{nom}_{prenom}_{parcours}")
    ELIGIBILITY_LIST = get_eligibility_list() # LECTURE DB
    if eligibility_key not in ELIGIBILITY_LIST:
        return jsonify({'error': "Vos informations ne correspondent à aucun étudiant éligible à l'inscription."}), 403

    # 2. Vérification anti-doublon d'inscription
    VOTERS = get_voters() # LECTURE DB
    for voter in VOTERS.values():
        if voter.get('eligibility_key') == eligibility_key:
            return jsonify({'error': "Vous êtes déjà inscrit et avez déjà un ID numérique."}), 409
            
    # Dérivation de l'ID numérique à partir de la clé d'éligibilité (anonyme pour le vote)
    unique_id_source = f"{eligibility_key}{datetime.now().strftime('%Y%m%d%H%M%S')}"
    # Utiliser les 10 premiers caractères du hash SHA256 pour respecter la limite
    id_numerique = sha256(unique_id_source)[:10] 

    # 3. Enregistrement du Votant dans la DB
    voter_data = {
        'id_numerique': id_numerique,
        'eligibility_key': eligibility_key,
        'has_voted': False,
    }
    
    # Utilisation de la nouvelle fonction DB
    if not register_voter_in_db(voter_data):
         return jsonify({'error': "Erreur lors de l'enregistrement de votre ID numérique dans la base de données. Veuillez réessayer."}), 500

    # 4. Enregistrement de l'événement dans la Blockchain
    event_payload = {
        'id_numerique': id_numerique,
        'eligibility_key_hash': sha256(eligibility_key),
        'nom': nom, # Le nom/prénom est stocké ICI (hors blockchain) mais aussi anonymisé dans l'événement blockchain
        'prenom': prenom,
    }
    
    last_block = blockchain.last_block
    if last_block:
        blockchain.add_event("VOTER_REGISTERED", event_payload)
    
    return jsonify({'success': True, 'id_numerique': id_numerique}), 200

# --- ROUTES CANDIDAT (SELF-REGISTER) ---
@app.route('/self_register_candidate')
def self_register_candidate_get():
    SETTINGS = get_settings()
    is_open = SETTINGS.get('candidacy_open', False)
    return render_template('self_register_candidate.html', candidacy_open=is_open)

@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate_post():
    SETTINGS = get_settings()
    if not SETTINGS.get('candidacy_open'):
        return jsonify({'error': "La période d'inscription des candidats est fermée."}), 403

    # 1. Récupération des données du formulaire
    nom = request.form.get('nom', '').strip().upper()
    prenom = request.form.get('prenom', '').strip().upper()
    parcours = request.form.get('parcours', '').strip().upper()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    photo = request.files.get('photo')

    if not all([nom, prenom, parcours, slogan, programme, photo]):
        return jsonify({'error': "Tous les champs sont requis, y compris la photo."}), 400

    # 2. Vérification anti-doublon (simple sur nom/prénom/parcours)
    CANDIDATES = get_candidates()
    for candidate in CANDIDATES.values():
        if candidate['nom'] == nom and candidate['prenom'] == prenom and candidate['parcours'] == parcours:
            return jsonify({'error': "Un candidat avec ce Nom, Prénom et Parcours est déjà enregistré."}), 409

    # 3. Traitement de la photo
    filename = secure_filename(photo.filename)
    extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'jpg'
    # Génération d'un ID unique pour le candidat
    candidate_id = str(uuid4())
    photo_path = os.path.join(CANDIDATE_IMAGES_DIR, f"{candidate_id}.{extension}")
    
    try:
        photo.save(photo_path)
    except Exception as e:
        logger.error(f"Échec de la sauvegarde de la photo : {e}")
        return jsonify({'error': "Échec de la sauvegarde de l'image sur le serveur."}), 500

    # 4. Enregistrement dans la DB
    candidate_data = {
        'candidate_id': candidate_id,
        'nom': nom,
        'prenom': prenom,
        'parcours': parcours,
        'photo_path': photo_path,
        'slogan': slogan,
        'programme': programme,
        'is_validated': False # Toujours False en attente d'admin
    }

    if not add_candidate_to_db(candidate_data):
        # Si l'ajout à la DB échoue, on tente de supprimer l'image
        if os.path.exists(photo_path):
            os.remove(photo_path)
        return jsonify({'error': "Erreur lors de l'enregistrement de la candidature dans la base de données."}), 500

    # 5. Enregistrement de l'événement dans la Blockchain
    event_payload = {
        'candidate_id': candidate_id,
        'nom_prenom': f"{nom} {prenom}",
        'parcours': parcours,
        'status': 'PENDING_VALIDATION'
    }
    last_block = blockchain.last_block
    if last_block:
        blockchain.add_event("CANDIDATE_REGISTERED", event_payload)

    return jsonify({'success': "Candidature enregistrée et en attente de validation.", 'candidate_id': candidate_id}), 200

# --- ROUTES VOTE ---

@app.route('/voter_login')
def voter_login():
    SETTINGS = get_settings()
    election_status = SETTINGS.get('election_status', 'SETUP')
    # Permettre la connexion uniquement si l'élection est en cours (VOTING)
    if SETTINGS.get('voting_status') != 'OPEN':
        # Rediriger vers une page d'erreur si le vote est fermé
        return render_template('error_page.html', message="Le vote est actuellement fermé par l'administration."), 403
        
    return render_template('voter_login.html', election_status=election_status)


@app.route('/api/voter/login', methods=['POST'])
def api_voter_login():
    SETTINGS = get_settings()
    if SETTINGS.get('voting_status') != 'OPEN':
        return jsonify({'error': "Le vote est actuellement fermé par l'administration."}), 403

    data = request.get_json()
    voter_id = data.get('id_numerique', '').strip()

    VOTERS = get_voters()
    voter = VOTERS.get(voter_id)

    if not voter:
        return jsonify({'error': "ID Numérique inconnu. Avez-vous effectué votre inscription ?"}), 404
    
    if voter.get('has_voted'):
        return jsonify({'error': "Vous avez déjà exercé votre droit de vote."}), 403

    # Stocke l'ID dans la session et redirige vers le bulletin
    session['voter_id'] = voter_id
    return jsonify({'success': "Accès accordé", 'redirect_url': url_for('voting_page')}), 200

@app.route('/voting_page')
def voting_page():
    voter_id = session.get('voter_id')
    SETTINGS = get_settings()
    
    # Vérifications de sécurité et de statut
    if not voter_id:
        return redirect(url_for('voter_login', error="Session de vote expirée ou invalide."))

    VOTERS = get_voters()
    voter = VOTERS.get(voter_id)

    if not voter or voter.get('has_voted'):
        # Efface l'ID s'il est invalide ou a déjà voté
        session.pop('voter_id', None)
        return redirect(url_for('voter_login', error="Vous avez déjà voté ou votre statut est invalide."))

    if SETTINGS.get('voting_status') != 'OPEN':
        session.pop('voter_id', None)
        return render_template('error_page.html', message="Le vote a été interrompu par l'administration."), 403

    # Récupérer les candidats validés uniquement
    CANDIDATES = get_candidates()
    validated_candidates = [c for c in CANDIDATES.values() if c.get('is_validated')]
    
    if not validated_candidates:
        return render_template('error_page.html', message="Aucun candidat validé n'est disponible pour le moment."), 404

    return render_template('voting_page.html', 
        voter_id=voter_id, 
        candidates=validated_candidates
    )

@app.route('/api/vote', methods=['POST'])
def api_vote():
    voter_id = session.get('voter_id')
    SETTINGS = get_settings()

    if SETTINGS.get('voting_status') != 'OPEN':
        return jsonify({'error': "Le vote est actuellement fermé par l'administration."}), 403
        
    if not voter_id:
        return jsonify({'error': "Session de vote expirée ou invalide."}), 403

    data = request.get_json()
    candidate_id = data.get('candidate_id', '').strip()
    
    if not candidate_id:
        return jsonify({'error': "Candidat non sélectionné."}), 400

    # L'ajout du vote dans la Blockchain se charge de toutes les vérifications restantes
    result = blockchain.add_vote(voter_id, candidate_id)

    if isinstance(result, tuple):
        # Si c'est un tuple, c'est une erreur de la fonction add_vote (dict, code)
        return jsonify(result[0]), result[1]
    
    # Si succès, le résultat est le nouveau bloc miné
    new_block = result
    
    # Supprimer l'ID du votant de la session après un vote réussi
    session.pop('voter_id', None)
    
    return jsonify({
        'success': "Vote enregistré", 
        'block_index': new_block['index'],
        'block_hash': new_block['hash'][:10] + '...'
    }), 200

# --- ROUTES RÉSULTATS ---
@app.route('/results')
def results():
    SETTINGS = get_settings()
    results_visibility = SETTINGS.get('results_visibility', 'HIDDEN')
    election_status = SETTINGS.get('election_status', 'SETUP')
    
    # Calcul des résultats
    results, total_votes = calculate_results()
    
    status_message = "Élection en cours."
    if election_status == 'CLOSED':
        status_message = "Élection terminée. Résultats finaux."
        # Si l'élection est fermée, on affiche les résultats finaux si visibles
        if results_visibility == 'VISIBLE':
            return render_template('results_final.html', results=results, total_votes=total_votes, voters_stats=get_voters_stats())
    
    if results_visibility == 'HIDDEN':
        status_message = "Les résultats sont actuellement cachés par l'administration."
        return render_template('results.html', 
            results=[], 
            total_votes=0, 
            status_message=status_message, 
            election_status=election_status
        )

    # Affichage des résultats en temps réel (si VISIBLE et pas CLOSED/FINAL)
    return render_template('results.html', 
        results=results, 
        total_votes=total_votes, 
        status_message=status_message, 
        election_status=election_status
    )

# --- EXPLORATEUR BLOCKCHAIN ---

@app.route('/explorer')
def explorer():
    chain = get_chain_from_db()
    sanitized_chain = []
    
    for block in chain:
        sanitized_block = block.copy()
        type = sanitized_block['type']
        
        if type == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            # Anonymisation des votes : Seul le HASH du votant et le candidat restent visibles
            anonymized_payload = {
                'voter_id_hash': sanitized_block['payload'].get('voter_id_hash', 'N/A'),
                'candidate_id': sanitized_block['payload'].get('candidate_id', 'N/A'),
                'timestamp': sanitized_block['payload'].get('timestamp', 'N/A') 
            }
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

# --- ROUTES ADMIN ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        ADMIN_USERS = get_admin_users()
        user_data = ADMIN_USERS.get(username)

        if user_data and check_password_hash(user_data['hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Identifiants Invalides"
            return render_template('admin_login.html', error=error), 401
    
    return render_template('admin_login.html', error=request.args.get('error'))


@app.route('/admin_logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('index', message="Déconnexion réussie."))


@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    ADMIN_USERS = get_admin_users()
    admin_username = session.get('admin_username')
    admin_role = ADMIN_USERS.get(admin_username, {}).get('role', 'UNKNOWN')

    SETTINGS = get_settings()
    CANDIDATES = get_candidates()
    voters_stats = get_voters_stats()
    
    # Séparation des candidats pour l'affichage
    pending_candidates = sorted([c for c in CANDIDATES.values() if not c.get('is_validated')], key=lambda x: x['registered_at'], reverse=True)
    validated_candidates = sorted([c for c in CANDIDATES.values() if c.get('is_validated')], key=lambda x: x['registered_at'], reverse=True)

    return render_template('admin_dashboard.html',
        admin_username=admin_username,
        admin_role=admin_role,
        settings=SETTINGS,
        pending_candidates=pending_candidates,
        validated_candidates=validated_candidates,
        voters_stats=voters_stats,
        message=request.args.get('message'),
        error=request.args.get('error')
    )

@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@admin_required
def candidate_action(candidate_id):
    data = request.get_json()
    action = data.get('action')
    
    CANDIDATES = get_candidates()
    candidate = CANDIDATES.get(candidate_id)
    if not candidate:
        return jsonify({'error': "Candidat introuvable."}), 404

    if action == 'validate':
        if update_candidate_status_in_db(candidate_id, True):
            # Événement Blockchain
            event_payload = {
                'candidate_id': candidate_id,
                'action_by': session.get('admin_username'),
            }
            blockchain.add_event("CANDIDATE_VALIDATED", event_payload)
            return jsonify({'success': f"Candidat {candidate_id} validé."}), 200
        return jsonify({'error': "Échec de la validation DB."}), 500
    
    elif action == 'delete':
        # Supprimer l'image avant de supprimer l'entrée DB
        photo_path = candidate.get('photo_path')
        if photo_path and os.path.exists(photo_path):
            os.remove(photo_path)
            
        if delete_candidate_from_db(candidate_id):
            # Événement Blockchain
            event_payload = {
                'candidate_id': candidate_id,
                'action_by': session.get('admin_username'),
            }
            blockchain.add_event("CANDIDATE_DELETED", event_payload)
            return jsonify({'success': f"Candidat {candidate_id} supprimé."}), 200
        return jsonify({'error': "Échec de la suppression DB."}), 500
    
    return jsonify({'error': "Action invalide."}), 400

@app.route('/api/admin/control_election', methods=['POST'])
@institution_admin_required
def control_election():
    data = request.get_json()
    action = data.get('action')
    SETTINGS = get_settings()

    # CANDIDACY
    if action == 'open_candidacy':
        if update_setting_in_db('candidacy_open', True):
            blockchain.add_event("CANDIDACY_OPENED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Inscriptions des candidats ouvertes."}), 200
    elif action == 'close_candidacy':
        if update_setting_in_db('candidacy_open', False):
            blockchain.add_event("CANDIDACY_CLOSED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Inscriptions des candidats fermées."}), 200

    # VOTING
    elif action == 'open_voting':
        if SETTINGS.get('election_status') != 'VOTING':
            return jsonify({'error': "Impossible d'ouvrir le vote si l'état de l'élection n'est pas 'VOTING'."}), 403
        if update_setting_in_db('voting_status', 'OPEN'):
            blockchain.add_event("VOTING_OPENED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Période de vote ouverte."}), 200
    elif action == 'close_voting':
        if update_setting_in_db('voting_status', 'CLOSED'):
            blockchain.add_event("VOTING_CLOSED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Période de vote fermée."}), 200

    # ELECTION STATUS
    elif action == 'start_election':
        # Vérifier s'il y a au moins 2 candidats validés
        validated_candidates = [c for c in get_candidates().values() if c.get('is_validated')]
        if len(validated_candidates) < 2:
            return jsonify({'error': "Au moins deux candidats validés sont requis pour démarrer l'élection."}), 403
            
        if update_setting_in_db('election_status', 'VOTING'):
            update_setting_in_db('candidacy_open', False) # Ferme l'inscription auto
            blockchain.add_event("ELECTION_STARTED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Élection passée en mode VOTING. Inscriptions candidats fermées."}), 200
    elif action == 'close_election':
        # Fermer le vote et mettre à jour le statut
        update_setting_in_db('voting_status', 'CLOSED')
        if update_setting_in_db('election_status', 'CLOSED'):
            blockchain.add_event("ELECTION_CLOSED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Élection terminée. Vote fermé."}), 200
    elif action == 'reset_system':
        return reset_system() # Appel de la fonction de réinitialisation

    # RESULTS VISIBILITY
    elif action == 'show_results':
        if update_setting_in_db('results_visibility', 'VISIBLE'):
            blockchain.add_event("RESULTS_VISIBLE", {'admin': session.get('admin_username')})
            return jsonify({'success': "Résultats rendus visibles."}), 200
    elif action == 'hide_results':
        if update_setting_in_db('results_visibility', 'HIDDEN'):
            blockchain.add_event("RESULTS_HIDDEN", {'admin': session.get('admin_username')})
            return jsonify({'success': "Résultats rendus cachés."}), 200

    return jsonify({'error': "Action invalide ou échec de la mise à jour DB."}), 400


@app.route('/api/admin/upload_eligibility', methods=['POST'])
@institution_admin_required
def upload_eligibility():
    # ... (Mise en œuvre complète de l'upload de l'éligibilité)
    if 'file' not in request.files:
        return redirect(url_for('admin_dashboard', error="Aucun fichier n'a été sélectionné."))
    
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('admin_dashboard', error="Aucun fichier n'a été sélectionné."))
    
    if file and allowed_file(file.filename):
        # Utilisation de tempfile pour une gestion sécurisée
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            file.save(tmp.name)
            temp_path = tmp.name

        try:
            # Lecture du fichier Excel
            df = pd.read_excel(temp_path, usecols=['NOM', 'PRENOM', 'PARCOURS'])
            
            # Nettoyage des données et formatage
            df['NOM'] = df['NOM'].astype(str).str.strip().str.upper()
            df['PRENOM'] = df['PRENOM'].astype(str).str.strip().str.upper()
            df['PARCOURS'] = df['PARCOURS'].astype(str).str.strip().str.upper()
            
            # Création des clés d'éligibilité (hash SHA256)
            eligibility_keys = df.apply(lambda row: sha256(f"{row['NOM']}_{row['PRENOM']}_{row['PARCOURS']}"), axis=1).tolist()
            
            # Création de la nouvelle liste d'éligibilité (format dict)
            new_eligibility_list = {key: True for key in eligibility_keys}
            
            # Sauvegarde dans la DB
            if save_eligibility_list_to_db(new_eligibility_list):
                # Événement Blockchain
                event_payload = {
                    'admin': session.get('admin_username'),
                    'total_keys': len(new_eligibility_list)
                }
                blockchain.add_event("ELIGIBILITY_LIST_UPDATED", event_payload)
                return redirect(url_for('admin_dashboard', message=f"Liste d'éligibilité mise à jour avec {len(new_eligibility_list)} entrées."))
            else:
                return redirect(url_for('admin_dashboard', error="Erreur critique lors de la sauvegarde dans la base de données."))

        except Exception as e:
            logger.error(f"Erreur lors du traitement du fichier Excel : {e}")
            return redirect(url_for('admin_dashboard', error=f"Erreur de lecture ou de format du fichier Excel : {e}"))

        finally:
            # Nettoyage du fichier temporaire
            if os.path.exists(temp_path):
                os.remove(temp_path)
            
    else:
        return redirect(url_for('admin_dashboard', error="Type de fichier non autorisé. Seuls .xlsx et .xls sont acceptés."))


@institution_admin_required
def reset_system():
    """Réinitialise toutes les données critiques du système (Votants, Candidats, Blockchain)."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': "Échec de la connexion à la DB pour la réinitialisation."}), 500
    
    cur = conn.cursor()
    try:
        # 1. Vider les tables de données
        cur.execute("TRUNCATE voters, candidates, blockchain, eligibility_list;")
        
        # 2. Réinitialiser les paramètres par défaut
        for key, value in DEFAULT_SETTINGS.items():
            update_setting_in_db(key, value)
            
        # 3. Supprimer toutes les photos de candidats existantes (optionnel mais recommandé pour le reset)
        for filename in os.listdir(CANDIDATE_IMAGES_DIR):
            if filename != ".gitkeep": # Conserver le fichier de placeholder
                os.remove(os.path.join(CANDIDATE_IMAGES_DIR, filename))

        # 4. Recréer le bloc GENESIS (appel de init_db qui le recréera si la table est vide)
        conn.commit()
        
        # On ferme et rouvre la connexion pour s'assurer que init_db fonctionne
        cur.close()
        conn.close()
        init_db() # Recrée le Genesis Block, les Admins par défaut, et les Settings par défaut

        # Réinitialiser l'instance globale de la blockchain
        global blockchain
        blockchain = Blockchain() # Recharge de la chaîne après la recréation du Genesis Block

        # Log l'événement
        logger.warning(f"SYSTÈME RÉINITIALISÉ PAR {session.get('admin_username')}.")
        
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

# --- HOOK D'APPLICATION ---
# S'assure que la base de données est initialisée au lancement de l'application
# Si la connexion DB échoue, l'application fonctionnera sans persistence (mode DEBUG/SETUP local)
# mais en production, elle nécessitera la connexion DB.
with app.app_context():
    try:
        init_db()
    except Exception as e:
        logger.critical(f"L'application n'a pas pu démarrer car l'initialisation de la DB a échoué: {e}")
        # En production, on pourrait choisir de ne pas continuer ici.
        
if __name__ == '__main__':
    # En production, l'initialisation de la DB est faite par le hook ci-dessus.
    # En développement, cela assure que l'instance de la blockchain est prête.
    # Ne pas appeler init_db() ici si vous l'appelez dans le hook.
    # app.run(debug=True)
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)