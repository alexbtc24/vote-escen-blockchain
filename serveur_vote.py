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
            candidate_data['is_validated'],
            datetime.now(timezone.utc)
        ))
        conn.commit()
        return True
    except psycopg2.errors.UniqueViolation:
        # Gérer le cas où l'ID existe déjà
        conn.rollback()
        logger.warning(f"Tentative d'ajout d'un candidat existant: {candidate_data['candidate_id']}")
        return False
    except Exception as e:
        logger.error(f"Erreur add_candidate_to_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def update_candidate_validation_status(candidate_id, status):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE candidates SET is_validated = %s WHERE candidate_id = %s;
        """, (status, candidate_id))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur update_candidate_validation_status: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def delete_candidate_from_db(candidate_id):
    conn = get_db_connection()
    if not conn: return False
    cur = conn.cursor()
    try:
        # 1. Supprimer le candidat
        cur.execute("DELETE FROM candidates WHERE candidate_id = %s;", (candidate_id,))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur delete_candidate_from_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_full_blockchain_from_db():
    conn = get_db_connection()
    if not conn: return []  # Retourne une chaîne vide si pas de DB
    cur = conn.cursor()
    try:
        cur.execute("SELECT block_index, timestamp, payload, previous_hash, hash, proof, type FROM blockchain ORDER BY block_index ASC;")
        
        chain = []
        for row in cur.fetchall():
            chain.append({
                'index': row[0],
                'timestamp': row[1],
                'payload': row[2],  # PostgreSQL retourne JSONB directement comme un dict/list Python
                'previous_hash': row[3],
                'hash': row[4],
                'proof': row[5],
                'type': row[6]
            })
        return chain
    except Exception as e:
        logger.error(f"Erreur get_full_blockchain_from_db: {e}")
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
    except Exception as e:
        logger.error(f"Erreur add_block_to_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def clear_all_db_data(conn):
    """
    Vide les tables des données volatiles (votants, candidats, blockchain, éligibilité)
    Nécessite une connexion active (conn)
    """
    if not conn:
        logger.warning("Connexion DB non disponible pour la réinitialisation.")
        return False
    
    cur = conn.cursor()
    try:
        cur.execute("TRUNCATE voters, candidates, blockchain, eligibility_list RESTART IDENTITY;")
        # Réinitialiser les paramètres
        cur.execute("UPDATE settings SET value = 'False' WHERE key = 'candidacy_open';")
        cur.execute("UPDATE settings SET value = 'SETUP' WHERE key = 'election_status';")
        cur.execute("UPDATE settings SET value = 'CLOSED' WHERE key = 'voting_status';")
        cur.execute("UPDATE settings SET value = 'HIDDEN' WHERE key = 'results_visibility';")
        
        # Ré-initialiser le bloc Genesis (cela sera fait par init_db si la table est vide)
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur de nettoyage des tables DB: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        # Ne ferme pas la connexion (conn) car elle est gérée par l'appelant.

# --- UTILS POUR LA BLOCKCHAIN ---

def sha256(data):
    """Calcule le hachage SHA-256 d'une donnée."""
    # S'assure que toutes les données sont encodées en UTF-8
    return hashlib.sha256(str(data).encode('utf-8')).hexdigest()

# --- CLASSE BLOCKCHAIN ---

class Blockchain(object):
    def __init__(self):
        self.chain = get_full_blockchain_from_db()  # Chargement depuis la DB
        self.nodes = set()

        # Si la chaîne est vide, l'application devrait gérer la création du Genesis
        # via init_db(). On ne le fait pas ici pour éviter des transactions concurrentes.
        if not self.chain:
            logger.info("Chaîne vide. Le bloc Genesis devrait être créé par init_db().")

    @property
    def last_block(self):
        # Récupère le dernier bloc depuis la liste en mémoire, qui est le reflet de la DB
        return self.chain[-1] if self.chain else None

    def create_block(self, proof, previous_hash, type="EVENT", payload=None):
        """
        Crée un nouveau bloc dans la Blockchain et l'ajoute à la DB.
        """
        last_block_index = self.last_block['index'] if self.last_block else -1
        
        block = {
            'index': last_block_index + 1,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'payload': payload if payload is not None else {},
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'proof': proof,
            'type': type
        }
        
        # Calcul du hash du nouveau bloc
        block_string = f"{block['index']}{block['timestamp']}{json.dumps(block['payload'], sort_keys=True)}{block['previous_hash']}{block['proof']}{block['type']}".lower().encode('utf-8')
        block['hash'] = hashlib.sha256(block_string).hexdigest()

        if add_block_to_db(block):
            self.chain.append(block) # Met à jour la chaîne en mémoire après insertion DB
            return block
        else:
            return None

    def proof_of_work(self, last_proof):
        """
        Algorithme de Proof of Work simple :
         - Trouver un nombre 'p' tel que hash(dernière preuve, p) contienne 4 zéros
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Vérifie la preuve: Est-ce que hash(last_proof, proof) contient 4 zéros devant?
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def valid_chain(self, chain):
        """Détermine si une blockchain donnée est valide."""
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            logger.info(f'{last_block}')
            logger.info(f'{block}')
            logger.info("\n-----------\n")
            
            # Vérifie que le hachage du bloc est correct
            block_string = f"{block['index']}{block['timestamp']}{json.dumps(block['payload'], sort_keys=True)}{block['previous_hash']}{block['proof']}{block['type']}".lower().encode('utf-8')
            if block['hash'] != hashlib.sha256(block_string).hexdigest():
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
        
        # 1. Vérification du statut du votant (déjà vérifié dans la route, mais sécurité supplémentaire)
        VOTERS = get_voters()
        voter = VOTERS.get(voter_id)
        if not voter or voter.get('has_voted'):
             return {'error': "Statut de vote invalide."}, 403

        # 2. Préparation et minage du bloc
        last_block = self.last_block
        if not last_block:
            return {'error': "Blockchain non initialisée (Genesis manquant)."}, 500
        
        proof = self.proof_of_work(last_block['proof'])

        vote_payload = {
            'voter_id_hash': sha256(voter_id), # Ne JAMAIS stocker l'ID clair dans le vote
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
        
        proof = self.proof_of_work(last_block['proof'])
        
        new_block = self.create_block(proof, last_block['hash'], type=event_type, payload=payload)
        return new_block

# Initialisation de l'objet Blockchain (qui charge la chaîne depuis la DB)
blockchain = Blockchain()

# --- FONCTIONS UTILITAIRES POUR L'APPLICATION ---

def get_settings():
    """Charge les paramètres de l'élection (avec cache/DB)"""
    # En production (Render), cette fonction utilise la DB
    return get_settings_from_db()

def get_admin_users():
    """Charge les utilisateurs admin (avec cache/DB)"""
    return get_admin_users_from_db()

def get_eligibility_list():
    """Charge la liste d'éligibilité (avec cache/DB)"""
    return get_eligibility_list_from_db()

def get_voters():
    """Charge tous les votants enregistrés (avec cache/DB)"""
    return get_voters_from_db()

def get_candidates():
    """Charge tous les candidats (avec cache/DB)"""
    return get_candidates_from_db()

def calculate_results():
    """Calcule les résultats à partir de la Blockchain."""
    # 1. Compter les votes
    vote_counts = {}
    total_votes = 0
    
    # On utilise la chaîne en mémoire qui est synchronisée avec la DB
    chain = blockchain.chain 

    for block in chain:
        if block['type'] == 'VOTE':
            try:
                candidate_id = block['payload']['candidate_id']
                if candidate_id in vote_counts:
                    vote_counts[candidate_id] += 1
                    total_votes += 1
                else:
                    vote_counts[candidate_id] = 1
                    total_votes += 1
            except KeyError:
                logger.warning(f"Bloc de vote invalide à l'index {block['index']}")
                continue # Ignore les blocs de vote corrompus

    # 2. Préparer les résultats formatés
    results = []
    
    CANDIDATES = get_candidates()
    # Inclure uniquement les candidats validés
    validated_candidates = [c for c in CANDIDATES.values() if c.get('is_validated')]
    
    for candidate_data in validated_candidates:
        candidate_id = candidate_data['candidate_id']
        count = vote_counts.get(candidate_id, 0)
        percentage = (count / total_votes * 100) if total_votes > 0 else 0
        
        # Le nom du candidat est dans la DB (CANDIDATES), pas dans la blockchain
        results.append({
            'candidate_id': candidate_id,
            'nom': candidate_data['nom'],
            'prenom': candidate_data['prenom'],
            'parcours': candidate_data['parcours'],
            'votes': count,
            'percentage': round(percentage, 2)
        })

    # Trier par nombre de votes (décroissant)
    results.sort(key=lambda x: x['votes'], reverse=True)

    return results, total_votes

def get_voters_stats():
    """Calcule les statistiques sur les votants."""
    ELIGIBILITY_LIST = get_eligibility_list()
    VOTERS = get_voters()
    
    total_eligible = len(ELIGIBILITY_LIST)
    total_students_voters = len(VOTERS)
    
    # Combien de votants enregistrés ont voté
    total_students_voted = sum(1 for voter in VOTERS.values() if voter['has_voted'])
    
    # Le nombre de clés éligibles restantes (non encore enregistrées)
    registered_keys = {v['eligibility_key'] for v in VOTERS.values()}
    eligible_to_register_count = total_eligible - len(registered_keys)
    
    return {
        'total_eligible': total_eligible,
        'eligible_to_register': max(0, eligible_to_register_count),
        'total_students_voters': total_students_voters,
        'total_students_voted': total_students_voted
    }

def reset_system():
    """Réinitialise l'ensemble du système (sauf les comptes admin)."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': "Connexion à la base de données impossible pour la réinitialisation."}), 500
    
    try:
        # 1. Nettoyer les tables de données volatiles
        if not clear_all_db_data(conn):
            raise Exception("Échec de la fonction clear_all_db_data.")
            
        # 2. Nettoyage local (images)
        for filename in os.listdir(CANDIDATE_IMAGES_DIR):
            if filename != '.gitkeep':
                file_path = os.path.join(CANDIDATE_IMAGES_DIR, filename)
                os.remove(file_path)
        
        # 3. Réinitialiser la blockchain en mémoire
        global blockchain
        blockchain = Blockchain()
        
        # 4. Forcer la recréation du bloc GENESIS et des settings par défaut
        # Ceci est géré par init_db, mais nous l'appelons explicitement ici pour être sûr.
        init_db() 

        # Déconnexion de l'administrateur
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        
        return jsonify({'success': "Système de vote entièrement réinitialisé. Les données Votants, Candidats, Blockchain et Éligibilité ont été effacées."}), 200
    except Exception as e:
        logger.error(f"Erreur de réinitialisation: {e}")
        conn.rollback()
        return jsonify({'error': f"Erreur critique lors de la réinitialisation : {e}"}), 500
    finally:
        # La connexion est gérée à l'intérieur de la fonction.
        if conn: conn.close()
        
# --- DÉCORATEURS ET GESTION DES SESSIONS ADMIN ---

def admin_required(f):
    """Décorateur pour exiger que l'utilisateur soit connecté en tant qu'administrateur."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', error="Accès refusé. Veuillez vous connecter."))
        g.admin_username = session.get('admin_username')
        g.admin_role = session.get('admin_role')
        return f(*args, **kwargs)
    return decorated_function

def institution_admin_required(f):
    """Décorateur pour exiger que l'utilisateur soit un administrateur institutionnel."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in') or session.get('admin_role') != 'ADMIN_INSTITUTION':
            return redirect(url_for('admin_login', error="Accès refusé. Seul l'administrateur institutionnel est autorisé."))
        g.admin_username = session.get('admin_username')
        g.admin_role = session.get('admin_role')
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES D'AUTHENTIFICATION ADMIN ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ADMIN_USERS = get_admin_users()
        admin_data = ADMIN_USERS.get(username)
        
        if admin_data and check_password_hash(admin_data['hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session['admin_role'] = admin_data['role']
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error="Nom d'utilisateur ou mot de passe incorrect.")
    
    return render_template('admin_login.html', error=request.args.get('error'))

@app.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    return redirect(url_for('admin_login', message="Vous avez été déconnecté."))

# --- ROUTES ADMIN ---

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    admin_username = g.admin_username
    admin_role = g.admin_role
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
        return jsonify({'error': "Candidat non trouvé."}), 404
        
    admin_username = session.get('admin_username')

    if action == 'validate':
        if update_candidate_validation_status(candidate_id, True):
            blockchain.add_event("CANDIDATE_VALIDATED", {'admin': admin_username, 'candidate_id': candidate_id})
            return jsonify({'success': f"Candidat {candidate_id} validé."}), 200
        else:
            return jsonify({'error': "Échec de la validation DB."}), 500

    elif action == 'reject':
        # Rejet = suppression
        photo_path = candidate.get('photo_path')
        if delete_candidate_from_db(candidate_id):
             # Tentative de suppression de l'image si elle existe
            if photo_path and os.path.exists(photo_path):
                try:
                    os.remove(photo_path)
                except Exception as e:
                    logger.warning(f"Impossible de supprimer l'image {photo_path} : {e}")
                    
            blockchain.add_event("CANDIDATE_REJECTED", {'admin': admin_username, 'candidate_id': candidate_id})
            return jsonify({'success': f"Candidat {candidate_id} rejeté et supprimé."}), 200
        else:
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
             return jsonify({'error': "Impossible d'ouvrir le vote si l'état de l'élection n'est pas 'VOTING'."}), 400
             
        if update_setting_in_db('voting_status', 'OPEN'):
            blockchain.add_event("VOTING_OPENED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Le vote est ouvert aux étudiants inscrits."}), 200
    elif action == 'close_voting':
        if update_setting_in_db('voting_status', 'CLOSED'):
            blockchain.add_event("VOTING_CLOSED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Le vote est fermé."}), 200
            
    # ELECTION STATUS
    elif action == 'start_election':
        # Passage de SETUP à VOTING
        if SETTINGS.get('election_status') != 'SETUP':
            return jsonify({'error': "L'élection est déjà en cours ou terminée."}), 400
        if update_setting_in_db('election_status', 'VOTING'):
            blockchain.add_event("ELECTION_STARTED", {'admin': session.get('admin_username')})
            return jsonify({'success': "Élection démarrée (état: VOTING). Le vote est encore fermé (CLOSE) par défaut."}), 200
    elif action == 'close_election':
        # Passage de VOTING à CLOSED
        if SETTINGS.get('election_status') != 'VOTING':
            return jsonify({'error': "L'élection n'est pas en cours (état: VOTING)."}), 400
        if update_setting_in_db('election_status', 'CLOSED') and update_setting_in_db('voting_status', 'CLOSED'):
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
    SETTINGS = get_settings()
    if SETTINGS.get('election_status') != 'SETUP':
        return jsonify({'error': "La liste d'éligibilité ne peut être modifiée que lorsque l'état de l'élection est SETUP."}), 403

    if 'eligibility_file' not in request.files:
        return jsonify({'error': "Aucun fichier fourni."}), 400

    file = request.files['eligibility_file']
    if file.filename == '':
        return jsonify({'error': "Nom de fichier invalide."}), 400
        
    filename = secure_filename(file.filename)
    # Vérification du type de fichier
    if not (filename.endswith('.csv') or filename.endswith('.xlsx')):
        return jsonify({'error': "Seuls les fichiers CSV ou Excel (xlsx) sont acceptés."}), 400

    # Utilisation d'un fichier temporaire
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tmp:
        file.save(tmp.name)
        temp_filepath = tmp.name
        
    try:
        # Lecture du fichier
        if filename.endswith('.csv'):
            df = pd.read_csv(temp_filepath)
        else:
            df = pd.read_excel(temp_filepath)
            
        # Assurez-vous que la colonne 'KEY' existe
        if 'KEY' not in df.columns:
            return jsonify({'error': "Le fichier doit contenir une colonne nommée 'KEY'."}), 400
            
        # Extraire les clés d'éligibilité (conversion en string et suppression des doublons)
        eligibility_keys = df['KEY'].astype(str).str.strip().tolist()
        
        # Filtrer les clés vides
        eligibility_keys = [key for key in eligibility_keys if key]
        
        # Le format de la DB est un dictionnaire où la clé est la clé d'éligibilité
        new_eligibility_list = {key: True for key in eligibility_keys}
        
        
        # Sauvegarde dans la DB
        if save_eligibility_list_to_db(new_eligibility_list):
            # Événement Blockchain
            event_payload = {
                'admin': session.get('admin_username'),
                'count': len(new_eligibility_list)
            }
            blockchain.add_event("ELIGIBILITY_LIST_UPDATED", event_payload)
            
            return jsonify({
                'success': "Liste d'éligibilité mise à jour.",
                'count': len(new_eligibility_list)
            }), 200
        else:
            return jsonify({'error': "Échec de la sauvegarde dans la base de données."}), 500

    except Exception as e:
        logger.error(f"Erreur de traitement de l'éligibilité : {e}")
        return jsonify({'error': f"Erreur de traitement du fichier: {e}"}), 500
    finally:
        # Nettoyage du fichier temporaire
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)

@app.route('/admin/explorer')
@admin_required
def explorer():
    # Afficher la blockchain avec un formatage lisible
    chain = blockchain.chain
    
    # Préparation pour l'affichage (anonymisation des données sensibles)
    sanitized_chain = []
    CANDIDATES = get_candidates()

    for block in chain:
        sanitized_block = block.copy()
        
        # Anonymiser les blocs de VOTE
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            # On ne garde que les informations non sensibles du vote
            anonymized_payload = {
                'voter_id_hash': sanitized_block['payload'].get('voter_id_hash', 'N/A'),
                'candidate_id': sanitized_block['payload'].get('candidate_id', 'N/A'),
                'timestamp': sanitized_block['payload'].get('timestamp', 'N/A')
            }
            # Tente de retrouver le nom du candidat pour plus de lisibilité
            candidate_id = anonymized_payload['candidate_id']
            if candidate_id in CANDIDATES:
                candidate_info = CANDIDATES[candidate_id]
                anonymized_payload['candidate_name'] = f"{candidate_info['prenom']} {candidate_info['nom']}"
            else:
                 anonymized_payload['candidate_name'] = "Candidat Inconnu"
                 
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
    eligibility_key = data.get('eligibility_key', '').strip()
    
    # 1. Vérification de la clé d'éligibilité
    ELIGIBILITY_LIST = get_eligibility_list()
    if eligibility_key not in ELIGIBILITY_LIST:
        return jsonify({'error': "Clé d'éligibilité invalide ou non reconnue."}), 400

    # 2. Vérification de l'existence de l'ID numérique
    # L'ID numérique est le hachage de la clé d'éligibilité (pour l'anonymisation du vote)
    id_numerique = sha256(eligibility_key)
    VOTERS = get_voters()
    if id_numerique in VOTERS:
        return jsonify({'error': "Cette clé d'éligibilité a déjà été utilisée pour l'enregistrement. Veuillez vous connecter avec votre ID numérique."}), 403
    
    # 3. Enregistrement dans la DB
    voter_data = {
        'id_numerique': id_numerique,
        'eligibility_key': eligibility_key, # La clé en clair est stockée ICI (dans la DB) pour l'audit, mais jamais dans la Blockchain
        'has_voted': False
    }
    
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
        return jsonify({'error': "Les candidatures sont actuellement fermées."}), 403
        
    # Validation du formulaire (utilisation de request.form car c'est un formulaire multipart/form-data)
    nom = request.form.get('nom', '').strip().upper()
    prenom = request.form.get('prenom', '').strip().upper()
    parcours = request.form.get('parcours', '').strip()
    slogan = request.form.get('slogan', '').strip()
    programme = request.form.get('programme', '').strip()
    
    # Validation des champs
    if not all([nom, prenom, parcours, slogan, programme]):
        return jsonify({'error': "Tous les champs de texte doivent être remplis."}), 400

    # 1. Gestion de l'image
    if 'photo' not in request.files:
        return jsonify({'error': "Image du candidat manquante."}), 400
        
    file = request.files['photo']
    if file.filename == '':
        return jsonify({'error': "Nom de fichier d'image invalide."}), 400

    # 2. Création de l'ID unique (parcours + initiales)
    candidate_id = f"{parcours.upper()}_{prenom[0]}{nom[0]}"
    
    CANDIDATES = get_candidates()
    if candidate_id in CANDIDATES:
        return jsonify({'error': "Un candidat avec ces initiales et ce parcours existe déjà. Veuillez contacter l'administrateur si vous pensez que c'est une erreur."}), 403
    
    # 3. Sauvegarde sécurisée de l'image
    # Utilisation du candidat_id pour le nom de fichier pour éviter les conflits
    safe_filename = secure_filename(f"{candidate_id}_{int(time.time())}{os.path.splitext(file.filename)[-1]}")
    photo_path = os.path.join(CANDIDATE_IMAGES_DIR, safe_filename)
    
    try:
        file.save(photo_path)
    except Exception as e:
        logger.error(f"Erreur de sauvegarde de l'image : {e}")
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
        'parcours': parcours,
        'message': 'Nouvelle candidature en attente de validation'
    }
    blockchain.add_event("CANDIDACY_SUBMITTED", event_payload)
    
    return jsonify({'success': True, 'candidate_id': candidate_id}), 200

# --- ROUTES VOTE ÉTUDIANT ---

@app.route('/voter_login', methods=['GET', 'POST'])
def voter_login():
    if request.method == 'POST':
        voter_id = request.form.get('voter_id', '').strip()
        
        VOTERS = get_voters()
        voter = VOTERS.get(voter_id)
        
        if not voter:
            return jsonify({'error': "ID numérique non reconnu. Veuillez vous enregistrer d'abord."}), 403
            
        if voter.get('has_voted'):
            return jsonify({'error': "Vous avez déjà exercé votre droit de vote."}), 403
            
        # Stocke l'ID dans la session et redirige vers le bulletin
        session['voter_id'] = voter_id
        return jsonify({'success': "Accès accordé", 'redirect_url': url_for('voting_page')}), 200
    
    SETTINGS = get_settings()
    election_status = SETTINGS.get('election_status', 'SETUP')
    
    return render_template('voter_login.html', 
        error=request.args.get('error'),
        message=request.args.get('message'),
        election_status=election_status
    )

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
        return redirect(url_for('voter_login', error="Le vote n'est pas ouvert pour le moment."))

    # Récupérer les candidats validés uniquement
    CANDIDATES = get_candidates()
    validated_candidates = [c for c in CANDIDATES.values() if c.get('is_validated')]

    return render_template('voting_page.html', candidates=validated_candidates, voter_id=voter_id)

@app.route('/api/vote', methods=['POST'])
def submit_vote():
    voter_id = session.get('voter_id')
    SETTINGS = get_settings()
    
    # Vérification de la session et du statut du vote
    if not voter_id or SETTINGS.get('voting_status') != 'OPEN':
        session.pop('voter_id', None)
        return jsonify({'error': "Session de vote invalide ou le vote est fermé."}), 403
        
    VOTERS = get_voters()
    voter = VOTERS.get(voter_id)
    if not voter or voter.get('has_voted'):
        session.pop('voter_id', None)
        return jsonify({'error': "Vous avez déjà voté ou votre statut est invalide."}), 403

    data = request.get_json()
    candidate_id = data.get('candidate_id')
    
    # Vérification du candidat
    CANDIDATES = get_candidates()
    candidate = CANDIDATES.get(candidate_id)
    if not candidate or not candidate.get('is_validated'):
        return jsonify({'error': "Candidat sélectionné invalide ou non validé."}), 400
        
    # Enregistrement du vote (ajoute le bloc et met à jour le statut du votant DB)
    result = blockchain.add_vote(voter_id, candidate_id)

    if isinstance(result, tuple):
        # Erreur lors de l'ajout du vote
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
            return render_template('results.html', 
                results=results, 
                total_votes=total_votes,
                status_message=status_message,
                is_visible=True
            )
        else:
            # Si l'élection est fermée mais les résultats cachés, on affiche un message d'attente
            return render_template('results.html', 
                results=[], 
                total_votes=0,
                status_message=status_message,
                is_visible=False
            )

    # Si l'élection est en cours (VOTING)
    if election_status == 'VOTING':
        # Affichage en temps réel si les résultats sont visibles
        if results_visibility == 'VISIBLE':
            return render_template('results.html', 
                results=results, 
                total_votes=total_votes,
                status_message="Résultats partiels en temps réel.",
                is_visible=True
            )
        else:
            # Si les résultats sont cachés pendant le vote
            return render_template('results.html', 
                results=[], 
                total_votes=0,
                status_message="Le vote est en cours. Les résultats sont cachés jusqu'à la clôture.",
                is_visible=False
            )
    
    # Si l'élection est en SETUP
    return render_template('results.html', 
        results=[], 
        total_votes=0,
        status_message="L'élection n'a pas encore commencé.",
        is_visible=False
    )

@app.route('/explorer_vote')
def explorer_vote():
    # Afficher la blockchain avec un formatage lisible pour le public
    chain = blockchain.chain
    
    # Préparation pour l'affichage (anonymisation des données sensibles pour le public)
    sanitized_chain = []
    
    for block in chain:
        sanitized_block = block.copy()
        
        # Anonymiser les blocs de VOTE
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            # On ne garde que les informations non sensibles du vote
            sanitized_block['payload'] = {
                'voter_id_hash': sanitized_block['payload'].get('voter_id_hash', 'N/A'),
                'candidate_id': sanitized_block['payload'].get('candidate_id', 'N/A'),
                'timestamp': sanitized_block['payload'].get('timestamp', 'N/A')
            }
            
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
    
    # Pour simuler le démarrage avec gunicorn, utilisez la commande:
    # gunicorn serveur_vote:app
    pass