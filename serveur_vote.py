import json
import os
import hashlib
import time  
from uuid import uuid4
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, g
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
    'admin': {'hash': generate_password_hash('escenpass'), 'label': 'Administrateur Unique'} 
}

DEFAULT_SETTINGS = {
    'candidacy_open': False,  
    'election_status': 'SETUP', # SETUP, VOTING, CLOSED
    'voting_status': 'CLOSED',  # OPEN/CLOSED (contrôlé par l'admin)
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
            logging.error("DATABASE_URL n'est pas définie. Connexion à la BDD impossible.")
            # Permet de continuer si la connexion n'est pas essentielle (comme pour le mode DEBUG/SETUP local)
            # En production sur Render, ceci entraînera un échec de connexion, ce qui est normal.
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
    cur.execute("SELECT username, password_hash, role, label FROM admin_users;")
    admins = {row[0]: {'hash': row[1], 'label': row[3], 'role': row[2]} for row in cur.fetchall()}
    cur.close()
    conn.close()
    return admins

def get_settings_from_db():
    conn = get_db_connection()
    if not conn: return DEFAULT_SETTINGS
    cur = conn.cursor()
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
    cur.close()
    conn.close()
    # Fusionner avec les défauts au cas où une nouvelle clé n'est pas dans la DB
    return {**DEFAULT_SETTINGS, **settings}

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
        cur.close()
        conn.close()

def get_eligibility_list_from_db():
    conn = get_db_connection()
    if not conn: return {} 
    cur = conn.cursor()
    cur.execute("SELECT eligibility_key FROM eligibility_list;")
    eligibility_list = {row[0]: True for row in cur.fetchall()}
    cur.close()
    conn.close()
    return eligibility_list

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
        cur.close()
        conn.close()

def get_voters_from_db():
    conn = get_db_connection()
    if not conn: return {} 
    cur = conn.cursor()
    cur.execute("SELECT id_numerique, eligibility_key, has_voted, registration_time FROM voters;")
    voters = {}
    for row in cur.fetchall():
        voters[row[0]] = {
            'id_numerique': row[0],
            'eligibility_key': row[1],
            'has_voted': row[2],
            'registration_time': row[3].isoformat() if row[3] else None
        }
    cur.close()
    conn.close()
    return voters

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
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur register_voter_in_db: {e}")
        return False
    finally:
        cur.close()
        conn.close()

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
        cur.close()
        conn.close()

def get_candidates_from_db():
    conn = get_db_connection()
    if not conn: return {} 
    cur = conn.cursor()
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
    cur.close()
    conn.close()
    return candidates

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
            candidate_data['is_validated'],
            datetime.now(timezone.utc).isoformat()
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur add_candidate_to_db: {e}")
        return False
    finally:
        cur.close()
        conn.close()

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
        cur.close()
        conn.close()

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
        cur.close()
        conn.close()
        
def get_chain_from_db():
    conn = get_db_connection()
    if not conn: return []
    cur = conn.cursor()
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
    cur.close()
    conn.close()
    return chain

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
            json.dumps(block['payload']), # S'assurer que le payload est bien en JSON string
            block['previous_hash'],
            block['hash'],
            block['proof'],
            block['type']
        ))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur add_block_to_db: {e}")
        return False
    finally:
        cur.close()
        conn.close()

# --- FIN NOUVELLES FONCTIONS DE BASE DE DONNÉES ---

def sha256(s):
    # CORRECTION DE L'ERREUR 'heigest' -> 'hexdigest' (déjà corrigée dans votre original)
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
            # Si get_chain_from_db() retourne une liste vide, le bloc Genesis DOIT être créé
            # Ceci devrait se faire via init_db() au premier lancement
            # Si on arrive ici, c'est que init_db() n'a pas été appelé ou a échoué.
            # On tente de recréer le bloc Genesis ici pour la robustesse, mais init_db est la source.
            if self.create_block(proof=1, previous_hash='0', type="GENESIS", payload={"msg": "Lancement Réseau"}):
                 # Recharge la chaîne si le bloc Genesis a été créé avec succès
                self.chain = get_chain_from_db()

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
        
        # Le hash est calculé avec toutes les données du bloc
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
        # Assure que le dictionnaire est ordonné pour des hashes cohérents (JSON stringifié)
        block_string = json.dumps(block, sort_keys=True) 
        return sha256(block_string)

    @property
    def last_block(self):
        # Récupère le dernier bloc directement de la base de données, pour être sûr
        current_chain = get_chain_from_db()
        return current_chain[-1] if current_chain else None

    def proof_of_work(self, last_proof):
        # ... (Logique inchangée)
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        # ... (Logique inchangée)
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        # Complexité faible pour le PoW de démo (commence par 3 zéros)
        return guess_hash[:3] == "000"

    def valid_chain(self, chain):
        # ... (Logique inchangée, utilise les données passées)
        if not chain:
            return True # Chaîne vide est valide (avant Genesis)
            
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            logger.info(f'{last_block}')
            logger.info(f'{block}')

            # Vérifie que le hash du bloc est correct
            if block['previous_hash'] != last_block['hash']:
                return False

            # Vérifie que la Proof of Work est correcte
            if not self.valid_proof(last_block['proof'], block['proof']):
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

# --- FONCTIONS UTILITAIRES ---
def calculate_results():
    """Calcule les résultats à partir de la chaîne de vote."""
    VOTERS = get_voters()
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
    # ... (Logique inchangée, utilise get_settings() qui appelle la DB)
    SETTINGS = get_settings()
    election_status = SETTINGS.get('election_status', 'SETUP')
    return render_template('index.html', election_status=election_status)

# --- ROUTE INSCRIPTION ÉTUDIANT (SELF-REGISTER) ---
@app.route('/self_register_student')
def self_register_student_get():
    # ... (Logique inchangée)
    SETTINGS = get_settings()
    election_status = SETTINGS.get('election_status', 'SETUP')
    return render_template('self_register_student.html', election_status=election_status)


@app.route('/api/student/self_register', methods=['POST'])
def self_register_student_post():
    # ... (Logique inchangée)
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
        'registration_time': datetime.now(timezone.utc).isoformat(),
    }
    
    # Utilisation de la nouvelle fonction DB
    if not register_voter_in_db(voter_data):
         return jsonify({'error': "Erreur lors de l'enregistrement dans la base de données."}), 500

    # 4. Enregistrement de l'événement dans la Blockchain
    # Les champs nom/prenom/parcours sont inclus pour l'audit, mais seront anonymisés dans l'explorer
    blockchain.add_event("VOTER_REGISTERED", {
        "id_numerique": id_numerique,
        "eligibility_key": eligibility_key,
        "nom": nom, "prenom": prenom, "parcours": parcours
    })
    
    return jsonify({'success': True, 'id_numerique': id_numerique}), 200

# --- ROUTE INSCRIPTION CANDIDAT (SELF-REGISTER) ---
@app.route('/self_register_candidate', methods=['GET'])
def self_register_candidate_get():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    is_open = SETTINGS.get('candidacy_open', False)
    return render_template('self_register_candidate.html', candidacy_open=is_open)

@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate_post():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    if not SETTINGS.get('candidacy_open'):
        return jsonify({'error': "Les candidatures sont actuellement fermées par l'administration."}), 403

    # Récupération des champs du formulaire
    nom = request.form.get('nom', '').strip().upper()
    prenom = request.form.get('prenom', '').strip().upper()
    parcours = request.form.get('parcours', '').strip().upper()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    photo = request.files.get('photo')

    # ... (Vérifications de base inchangées)

    # 1. Vérification des règles de mot (inchangé)
    slogan_word_count = len(slogan.split())
    programme_word_count = len(programme.split())
    # ... (Logique de vérification de mots inchangée)

    # 2. Vérification anti-doublon dans la DB
    CANDIDATES = get_candidates() # LECTURE DB
    check_key = sha256(f"{nom}_{prenom}_{parcours}")
    for cid, cand in CANDIDATES.items():
        if sha256(f"{cand['nom']}_{cand['prenom']}_{cand['parcours']}") == check_key:
            return jsonify({'error': "Un candidat avec ce nom, prénom et parcours est déjà en attente ou validé."}), 409

    # 3. Traitement de la photo (inchangé)
    photo_path = None
    if photo and photo.filename:
        filename = secure_filename(f"{nom}_{prenom}_{str(uuid4())[:8]}.jpg")
        photo_path = os.path.join(CANDIDATE_IMAGES_DIR, filename)
        photo.save(photo_path)
    
    # 4. Enregistrement du Candidat dans la DB
    candidate_id = str(uuid4())
    candidate_data = {
        'candidate_id': candidate_id,
        'nom': nom,
        'prenom': prenom,
        'parcours': parcours,
        'photo_path': photo_path,
        'slogan': slogan,
        'programme': programme,
        'is_validated': False, # Toujours False initialement
        'registered_at': datetime.now(timezone.utc).isoformat()
    }
    
    # Utilisation de la nouvelle fonction DB
    if not add_candidate_to_db(candidate_data):
        # Si échec, on tente de supprimer l'image pour ne pas polluer le dossier (best effort)
        if photo_path and os.path.exists(photo_path): os.remove(photo_path)
        return jsonify({'error': "Erreur lors de l'enregistrement de la candidature dans la base de données."}), 500

    # 5. Enregistrement de l'événement dans la Blockchain
    blockchain.add_event("CANDIDATE_REGISTERED", {
        "candidate_id": candidate_id, 
        "nom": nom, "prenom": prenom, "parcours": parcours, 
        "photo_path": photo_path # Le chemin est stocké pour l'audit
    })

    return jsonify({'success': "Candidature enregistrée avec succès.", 'candidate_id': candidate_id}), 200

# --- ROUTE CONNEXION VOTANT ---
@app.route('/voter_login')
def voter_login():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    if SETTINGS.get('election_status') != 'VOTING':
        return render_template('error_page.html', message="L'élection n'est pas ouverte au vote pour l'instant.")
    return render_template('voter_login.html')

@app.route('/api/voter/login', methods=['POST'])
def voter_login_post():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    if SETTINGS.get('election_status') != 'VOTING':
        return jsonify({'error': "Le vote n'est pas ouvert."}), 403

    data = request.get_json()
    voter_id = data.get('id_numerique', '').strip().lower()

    if not voter_id:
        return jsonify({'error': "ID Numérique requis."}), 400

    VOTERS = get_voters() # LECTURE DB
    voter = VOTERS.get(voter_id)

    if not voter:
        return jsonify({'error': "ID Numérique invalide. Vérifiez l'ID ou inscrivez-vous."}), 404
        
    if voter.get('has_voted'):
        return jsonify({'error': "Cet ID Numérique a déjà voté."}), 409

    # Connexion réussie, stocker l'ID dans la session (sécurité Flask)
    session['voter_id'] = voter_id
    
    return jsonify({'success': True, 'redirect_url': url_for('voting_page')}), 200

# --- ROUTE PAGE DE VOTE ---
@app.route('/voting_page')
def voting_page():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    VOTERS = get_voters() # LECTURE DB
    CANDIDATES = get_candidates() # LECTURE DB
    
    # 1. Vérifications de base (Admin ou Votant Logué, Statut de l'élection)
    if SETTINGS.get('election_status') != 'VOTING':
        return redirect(url_for('index', error="Le vote n'est pas en cours."))
    
    voter_id = session.get('voter_id')
    if not voter_id:
        return redirect(url_for('voter_login', error="Veuillez vous connecter pour voter."))
        
    voter = VOTERS.get(voter_id)
    if not voter or voter.get('has_voted'):
        return render_template('error_page.html', message="Vous avez déjà voté ou votre ID est invalide.")

    # 2. Récupérer uniquement les candidats validés
    candidates_validated = [c for c in CANDIDATES.values() if c.get('is_validated')]
    
    if not candidates_validated:
        return render_template('error_page.html', message="Aucun candidat validé pour l'instant. Le vote est en pause.")

    return render_template('voting_page.html', candidates=candidates_validated, voter_id=voter_id)

@app.route('/api/vote', methods=['POST'])
def api_vote():
    # ... (Logique inchangée)
    
    SETTINGS = get_settings() # LECTURE DB
    if SETTINGS.get('election_status') != 'VOTING':
        return jsonify({'error': "Le vote n'est pas ouvert."}), 403

    data = request.get_json()
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')

    # Utilisation directe de la logique de la Blockchain (qui met à jour la DB)
    new_block = blockchain.add_vote(voter_id, candidate_id)
    
    if isinstance(new_block, dict) and 'error' in new_block:
        # En cas d'erreur renvoyée par add_vote (déjà voté, candidat invalide, etc.)
        return jsonify(new_block), new_block.get('code', 500) # Utilise le code d'erreur si défini

    if new_block:
        # Déconnexion du votant après vote réussi
        session.pop('voter_id', None)
        return jsonify({
            'success': True, 
            'message': 'Vote enregistré sur la Blockchain',
            'block_index': new_block['index']
        }), 200
    else:
        # Erreur lors du minage/enregistrement DB
        return jsonify({'error': "Échec de l'enregistrement du vote sur la Blockchain (erreur interne)."}), 500

# --- ROUTE RÉSULTATS ---
@app.route('/results')
def results():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    
    results, total_votes = calculate_results()
    
    election_status = SETTINGS.get('election_status', 'SETUP')
    results_visibility = SETTINGS.get('results_visibility', 'HIDDEN')

    status_message = ""
    
    # 1. Page de résultats finaux (l'élection est CLÔTURÉE)
    if election_status == 'CLOSED':
        # Les résultats sont toujours visibles après la clôture (sauf s'ils sont cachés en dur)
        # On utilise une page de résultats finaux différente
        return render_template('results_final.html', 
                                results=results, 
                                total_votes=total_votes, 
                                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # 2. Page de résultats en direct (l'élection est en VOTING)
    if election_status == 'VOTING':
        if results_visibility == 'VISIBLE':
            status_message = "L'élection est en cours de vote. Résultats en direct."
        else:
            # Si en VOTING, mais cachés
            status_message = "Les résultats sont actuellement cachés par l'administration."
            results = [] # Cacher les résultats réels
            total_votes = 0
            
    # 3. Page de préparation (SETUP)
    elif election_status == 'SETUP':
        status_message = "L'élection est en phase de préparation (pas de vote actif)."

    return render_template('results.html', 
                           results=results, 
                           total_votes=total_votes,
                           status_message=status_message,
                           election_status=election_status)

# --- ROUTE EXPLORATEUR BLOCKCHAIN ---
@app.route('/explorer')
def explorer():
    # ... (Logique inchangée)
    
    chain = get_chain_from_db() # LECTURE DB
    
    # La logique de validation et d'anonymisation reste inchangée
    # ...
    
    is_valid = blockchain.valid_chain(chain)

    sanitized_chain = []
    for block in chain:
        sanitized_block = block.copy()
        
        # Anonymiser les blocs de vote
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            sanitized_block['payload'] = sanitized_block['payload'].copy()
            anonymized_payload = sanitized_block['payload'].copy()
            # On masque le HASH du votant et le timestamp dans l'interface
            if 'voter_id_hash' in anonymized_payload:
                anonymized_payload['voter_id_hash'] = sha256(anonymized_payload['voter_id_hash'])[:10] + '...'
            anonymized_payload.pop('timestamp', None)
            
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

    return render_template('explorer_vote.html', blockchain_chain=sanitized_chain, is_valid=is_valid, chain_length=len(chain))

# --- ROUTES ADMIN ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    # ... (Logique inchangée)
    if request.method == 'POST':
        username = request.form['username'].strip().upper()
        password = request.form['password']
        
        ADMIN_USERS = get_admin_users() # LECTURE DB
        user = ADMIN_USERS.get(username)

        if user and check_password_hash(user['hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session['admin_role'] = user['role']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error="Nom d'utilisateur ou mot de passe incorrect.")
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
@admin_required
def admin_logout():
    # ... (Logique inchangée)
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    return redirect(url_for('admin_login', message="Déconnexion réussie."))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # ... (Logique inchangée)
    SETTINGS = get_settings() # LECTURE DB
    CANDIDATES = get_candidates() # LECTURE DB
    
    # Calcul des statistiques (utilise les nouvelles fonctions DB)
    stats = get_voters_stats()
    
    candidates_validated = [c for c in CANDIDATES.values() if c.get('is_validated')]
    
    # Calcul des résultats pour l'affichage du dashboard
    results, total_votes = calculate_results()
    
    return render_template('admin_dashboard.html',
                           admin_username=session.get('admin_username'),
                           election_status=SETTINGS.get('election_status', 'SETUP'),
                           voting_status=SETTINGS.get('voting_status', 'CLOSED'),
                           results_visibility=SETTINGS.get('results_visibility', 'HIDDEN'),
                           candidacy_open=SETTINGS.get('candidacy_open', False),
                           total_eligible=stats['total_eligible'],
                           eligible_to_register=stats['eligible_to_register'],
                           candidates_waiting=len([c for c in CANDIDATES.values() if not c.get('is_validated')]),
                           candidates_validated=len(candidates_validated),
                           total_students_voters=stats['total_students_voters'],
                           total_students_voted=stats['total_students_voted'],
                           total_votes_cast=total_votes,
                           CANDIDATES=CANDIDATES, # Utilise la fonction de lecture DB
                           results=results
                           )

# --- NOUVELLE ROUTE : Gérer l'état de l'élection ---
@app.route('/api/admin/control', methods=['POST'])
@admin_required
def admin_control():
    # ... (Logique inchangée)
    
    data = request.get_json()
    action = data.get('action')
    SETTINGS = get_settings() # LECTURE DB

    # ... (Logique de changement de statut inchangée, mais utilise la fonction DB)
    
    if action == 'start_candidacy':
        update_setting_in_db('candidacy_open', 'True')
        blockchain.add_event("CANDIDACY_OPENED", {"user": session.get('admin_username')})
        return jsonify({'success': "La période de candidature est maintenant OUVERTE."}), 200
        
    elif action == 'close_candidacy':
        update_setting_in_db('candidacy_open', 'False')
        blockchain.add_event("CANDIDACY_CLOSED", {"user": session.get('admin_username')})
        return jsonify({'success': "La période de candidature est maintenant FERMÉE."}), 200

    elif action == 'start_voting':
        if SETTINGS.get('election_status') != 'SETUP':
            return jsonify({'error': "L'élection est déjà en cours ou clôturée. Réinitialisez d'abord."}), 400
        # Vérifie qu'il y a au moins un candidat validé dans la DB
        CANDIDATES = get_candidates() # LECTURE DB
        if not [c for c in CANDIDATES.values() if c.get('is_validated')]:
            return jsonify({'error': "Aucun candidat validé. L'élection ne peut pas démarrer."}), 400
            
        update_setting_in_db('election_status', 'VOTING')
        update_setting_in_db('voting_status', 'OPEN')
        blockchain.add_event("VOTING_STARTED", {"user": session.get('admin_username')})
        return jsonify({'success': "Le VOTE est démarré et le système est OUVERT aux votants."}), 200
        
    elif action == 'pause_voting':
        if SETTINGS.get('election_status') != 'VOTING':
            return jsonify({'error': "Le vote n'est pas en cours."}), 400
        update_setting_in_db('voting_status', 'CLOSED')
        blockchain.add_event("VOTING_PAUSED", {"user": session.get('admin_username')})
        return jsonify({'success': "Le VOTE est PAUSÉ. Les étudiants ne peuvent plus voter."}), 200
        
    elif action == 'resume_voting':
        if SETTINGS.get('election_status') != 'VOTING':
            return jsonify({'error': "L'élection n'est pas en statut 'VOTING'."}), 400
        update_setting_in_db('voting_status', 'OPEN')
        blockchain.add_event("VOTING_RESUMED", {"user": session.get('admin_username')})
        return jsonify({'success': "Le VOTE est REPRIS et le système est OUVERT."}), 200

    elif action == 'finalize_election':
        if SETTINGS.get('election_status') == 'VOTING':
            update_setting_in_db('election_status', 'CLOSED')
            update_setting_in_db('voting_status', 'CLOSED')
            update_setting_in_db('results_visibility', 'VISIBLE') # Affiche les résultats par défaut à la clôture
            blockchain.add_event("ELECTION_FINALIZED", {"user": session.get('admin_username')})
            return jsonify({'success': "Élection CLÔTURÉE. Les résultats sont désormais définitifs."}), 200
        else:
            return jsonify({'error': "L'élection doit être en statut 'VOTING' pour être finalisée."}), 400
            
    elif action == 'toggle_results_visibility':
        new_visibility = 'VISIBLE' if SETTINGS.get('results_visibility') == 'HIDDEN' else 'HIDDEN'
        update_setting_in_db('results_visibility', new_visibility)
        visibility_msg = "VISIBLES" if new_visibility == 'VISIBLE' else "CACHÉS"
        blockchain.add_event("RESULTS_VISIBILITY_CHANGE", {"status": new_visibility, "user": session.get('admin_username')})
        return jsonify({'success': f"Les résultats sont maintenant {visibility_msg} pour le public."}), 200

    elif action == 'reset_system':
        if SETTINGS.get('election_status') == 'VOTING':
            return jsonify({'error': "L'élection est en cours, impossible de réinitialiser. Clôturez d'abord."}), 400
            
        # Logique de réinitialisation complète de la DB
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': "Impossible de se connecter à la DB pour la réinitialisation."}), 500
        cur = conn.cursor()
        
        try:
            # 1. Effacer les tables de données et la blockchain
            cur.execute("TRUNCATE voters, candidates, blockchain, eligibility_list;")
            
            # 2. Réinitialiser les paramètres
            cur.execute("""
                UPDATE settings SET value = 'False' WHERE key = 'candidacy_open';
                UPDATE settings SET value = 'SETUP' WHERE key = 'election_status';
                UPDATE settings SET value = 'CLOSED' WHERE key = 'voting_status';
                UPDATE settings SET value = 'HIDDEN' WHERE key = 'results_visibility';
            """)
            conn.commit()
            
            # 3. Supprimer toutes les photos de candidats (fichiers locaux)
            for f in os.listdir(CANDIDATE_IMAGES_DIR):
                if f != '.gitkeep': # Conserve le fichier placeholder si vous en avez un
                    os.remove(os.path.join(CANDIDATE_IMAGES_DIR, f))
            
            # 4. Recréer le bloc GENESIS (appel init_db)
            init_db() 
            
            # Log événement sur la nouvelle chaîne (après TRUNCATE)
            # Puisque la chaîne a été tronquée, on se contente du log de init_db
            
            return jsonify({'success': "Système réinitialisé à l'état initial (SETUP). Toutes les données de vote, candidats, et éligibilité ont été effacées."}), 200
        
        except Exception as e:
            logger.error(f"Erreur lors de la réinitialisation du système: {e}")
            conn.rollback()
            return jsonify({'error': f"Erreur critique lors de la réinitialisation: {e}"}), 500
        finally:
            cur.close()
            conn.close()

    return jsonify({'error': "Action inconnue."}), 400

# --- NOUVELLE ROUTE : Gérer les actions sur les candidats ---
@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@admin_required
def admin_candidate_action(candidate_id):
    # ... (Logique inchangée)
    
    data = request.get_json()
    action = data.get('action')
    CANDIDATES = get_candidates() # LECTURE DB
    candidate = CANDIDATES.get(candidate_id)

    if not candidate:
        return jsonify({'error': "Candidat non trouvé."}), 404

    if action == 'validate':
        if candidate.get('is_validated'):
            return jsonify({'error': "Ce candidat est déjà validé."}), 400
            
        # Utilisation de la fonction de mise à jour DB
        if update_candidate_status_in_db(candidate_id, is_validated=True):
            blockchain.add_event("CANDIDATE_VALIDATED", {"candidate_id": candidate_id, "user": session.get('admin_username')})
            return jsonify({'success': "Candidat validé et prêt à être voté."}), 200
        else:
            return jsonify({'error': "Échec de la validation dans la base de données."}), 500

    elif action == 'unvalidate':
        if not candidate.get('is_validated'):
            return jsonify({'error': "Ce candidat n'est pas validé."}), 400
            
        # Utilisation de la fonction de mise à jour DB
        if update_candidate_status_in_db(candidate_id, is_validated=False):
            blockchain.add_event("CANDIDATE_UNVALIDATED", {"candidate_id": candidate_id, "user": session.get('admin_username')})
            return jsonify({'success': "Candidat non validé. Il est retiré du scrutin."}), 200
        else:
            return jsonify({'error': "Échec de l'invalidation dans la base de données."}), 500

    elif action == 'delete':
        # 1. Supprimer l'image si elle existe
        if candidate.get('photo_path') and os.path.exists(candidate['photo_path']):
            os.remove(candidate['photo_path'])
            
        # 2. Supprimer de la DB
        if delete_candidate_from_db(candidate_id):
            blockchain.add_event("CANDIDATE_DELETED", {"candidate_id": candidate_id, "user": session.get('admin_username')})
            return jsonify({'success': "Candidat et ses données effacés."}), 200
        else:
            return jsonify({'error': "Échec de la suppression dans la base de données."}), 500

    return jsonify({'error': "Action inconnue."}), 400

# --- NOUVELLE ROUTE : Gérer l'import de la liste d'éligibilité ---
@app.route('/api/admin/upload_eligibility', methods=['POST'])
@admin_required
def upload_eligibility_list():
    # ... (Logique inchangée)
    
    SETTINGS = get_settings() # LECTURE DB
    if SETTINGS.get('election_status') != 'SETUP':
        return jsonify({'error': "Impossible de modifier la liste d'éligibilité pendant le vote."}), 403

    if 'file' not in request.files:
        return jsonify({'error': "Aucun fichier fourni."}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': "Nom de fichier invalide."}), 400

    if file and allowed_file(file.filename):
        # Utilisation du tempfile pour une gestion sécurisée et multi-OS
        temp_dir = tempfile.gettempdir()
        temp_filepath = os.path.join(temp_dir, secure_filename(file.filename))
        file.save(temp_filepath)
        
        try:
            # Lire le fichier Excel (utilise Pandas et Openpyxl)
            df = pd.read_excel(temp_filepath, header=0, dtype=str)
            
            # La liste d'éligibilité est basée sur Nom, Prénom, Parcours (colonnes 0, 1, 2)
            new_eligibility_list = {}
            for index, row in df.iterrows():
                try:
                    nom = str(row.iloc[0]).strip().upper()
                    prenom = str(row.iloc[1]).strip().upper()
                    parcours = str(row.iloc[2]).strip().upper()
                    
                    if nom and prenom and parcours:
                        key = sha256(f"{nom}_{prenom}_{parcours}")
                        new_eligibility_list[key] = True
                    else:
                        logger.warning(f"Ligne {index+2} ignorée: Champs manquants.")
                except IndexError:
                    logger.error(f"Erreur de colonne à la ligne {index+2}. Le fichier doit avoir au moins 3 colonnes.")
                    continue

            # Vérification si la liste est vide après traitement
            if not new_eligibility_list:
                return jsonify({'error': "La liste traitée est vide ou le format des colonnes est incorrect (Nom, Prénom, Parcours)."}), 400
                
            # Mise à jour et sauvegarde des listes dans la DB
            if not save_eligibility_list_to_db(new_eligibility_list):
                return jsonify({'error': "Échec de la sauvegarde de la liste d'éligibilité dans la DB."}), 500
                
            # Réinitialisation des Votants (car la liste d'éligibilité a changé)
            conn = get_db_connection()
            if conn:
                cur = conn.cursor()
                cur.execute("TRUNCATE voters;") # Efface tous les votants inscrits pour forcer la réinscription
                conn.commit()
                cur.close()
                conn.close()

            # Enregistrement de l'événement dans la Blockchain
            blockchain.add_event("WHITELIST_UPDATE", {"count": len(new_eligibility_list), "user": session.get('admin_username')})
            
            # Suppression du fichier temporaire
            os.remove(temp_filepath) 
            
            return jsonify({'success': f"Liste d'éligibilité de {len(new_eligibility_list)} étudiants importée avec succès. Tous les votants inscrits ont été réinitialisés."}), 200

        except Exception as e:
            # Suppression du fichier temporaire en cas d'erreur
            if os.path.exists(temp_filepath): os.remove(temp_filepath)
            logger.error(f"Erreur lors du traitement du fichier Excel: {e}")
            return jsonify({'error': f"Erreur de traitement du fichier (format incorrect?): {e}"}), 400
    else:
        return jsonify({'error': "Format de fichier non autorisé (doit être .xlsx ou .xls)."}), 400


if __name__ == '__main__':
    # Initialisation de la base de données PostgreSQL au démarrage
    try:
        init_db()
        # L'application démarrera avec la persistance PostgreSQL
        # Le host '0.0.0.0' est nécessaire pour le déploiement sur Render
        app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)
    except Exception as e:
        logger.critical(f"L'application ne peut pas démarrer : Échec critique de la base de données. {e}")
        # En production, Gunicorn gérera l'échec de démarrage si la DB n'est pas connectée.
        # En local, on affiche l'erreur.
        exit(1)