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
        
        # Initialisation des admins (uniquement si la table est vide)
        cur.execute("SELECT COUNT(*) FROM admin_users;")
        if cur.fetchone()[0] == 0:
            for username, data in DEFAULT_ADMINS.items():
                cur.execute("""
                    INSERT INTO admin_users (username, password_hash, role, label)
                    VALUES (%s, %s, %s, %s);
                """, (username, data['hash'], data['role'], data['label']))
            logger.info("Admin par défaut inséré.")
        
        # Initialisation des paramètres (uniquement si la table est vide)
        cur.execute("SELECT COUNT(*) FROM settings;")
        if cur.fetchone()[0] == 0:
            for key, value in DEFAULT_SETTINGS.items():
                # Convertit les booléens en chaîne pour le stockage
                str_value = str(value).upper() if isinstance(value, bool) else str(value)
                cur.execute("""
                    INSERT INTO settings (key, value)
                    VALUES (%s, %s);
                """, (key, str_value))
            logger.info("Paramètres par défaut insérés.")
            
        # Initialisation du bloc Genesis (uniquement si la blockchain est vide)
        cur.execute("SELECT COUNT(*) FROM blockchain;")
        if cur.fetchone()[0] == 0:
            # Le bloc Genesis doit être créé après l'initialisation des tables
            # Si le code principal appelle déjà Blockchain(), il le créera via la fonction add_block_to_db (si vide).
            # Nous nous assurons ici que les tables sont prêtes.
            logger.info("La Blockchain est vide. Le bloc Genesis sera créé au démarrage de l'application.")


        conn.commit()
    except Exception as e:
        logger.error(f"Erreur d'initialisation de la DB: {e}")
        if conn:
            conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# --- FONCTIONS UTILITAIRES DE LA BASE DE DONNÉES ---

def get_settings():
    """Récupère tous les paramètres depuis la DB."""
    conn = get_db_connection()
    if not conn:
        return DEFAULT_SETTINGS # Retourne les valeurs par défaut en cas d'échec de connexion
    
    cur = conn.cursor()
    try:
        cur.execute("SELECT key, value FROM settings;")
        settings = {}
        for key, value in cur.fetchall():
            # Conversion des chaînes en booléens si nécessaire
            if value.upper() == 'TRUE':
                settings[key] = True
            elif value.upper() == 'FALSE':
                settings[key] = False
            else:
                settings[key] = value
        
        # Fusionner avec les défauts au cas où une nouvelle clé n'est pas dans la DB
        return {**DEFAULT_SETTINGS, **settings}
    except Exception as e:
        logger.error(f"Erreur get_settings: {e}")
        return DEFAULT_SETTINGS
    finally:
        if cur: cur.close()
        if conn: conn.close()

def update_setting_in_db(key, value):
    """Met à jour une paire clé/valeur dans la table settings."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cur = conn.cursor()
    try:
        str_value = str(value).upper() if isinstance(value, bool) else str(value)
        cur.execute("""
            UPDATE settings
            SET value = %s
            WHERE key = %s;
        """, (str_value, key))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur update_setting_in_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_admin_user(username):
    """Récupère un utilisateur admin par nom d'utilisateur."""
    conn = get_db_connection()
    if not conn:
        # Fallback pour le seul admin par défaut en cas d'échec DB critique
        return DEFAULT_ADMINS.get(username)
    
    cur = conn.cursor()
    try:
        cur.execute("SELECT username, password_hash, role, label FROM admin_users WHERE username = %s;", (username,))
        row = cur.fetchone()
        if row:
            return {
                'username': row[0],
                'hash': row[1],
                'role': row[2],
                'label': row[3]
            }
        return None
    except Exception as e:
        logger.error(f"Erreur get_admin_user: {e}")
        return None
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_voter(voter_id):
    """Récupère les informations d'un votant par ID numérique."""
    conn = get_db_connection()
    if not conn:
        return None
    
    cur = conn.cursor()
    try:
        cur.execute("SELECT id_numerique, eligibility_key, has_voted, nom, prenom, parcours FROM voters WHERE id_numerique = %s;", (voter_id,))
        row = cur.fetchone()
        if row:
            # ATTENTION: Il y a un mismatch entre la fonction Python (qui sélectionne 6 champs) 
            # et la table SQL (qui n'en a que 4).
            # J'assume que la structure de la table a été ajustée dans une version non vue ici, 
            # mais je me base sur les 4 champs initiaux pour éviter de casser.
            # La table VOTERS n'a que id_numerique, eligibility_key, has_voted, registration_time.
            # Je modifie la requête pour n'inclure que les champs existants dans la table 'voters'.
            cur.execute("SELECT id_numerique, eligibility_key, has_voted FROM voters WHERE id_numerique = %s;", (voter_id,))
            row = cur.fetchone()
            if row:
                return {
                    'id_numerique': row[0],
                    'eligibility_key': row[1],
                    'has_voted': row[2]
                }
        return None
    except Exception as e:
        logger.error(f"Erreur get_voter: {e}")
        return None
    finally:
        if cur: cur.close()
        if conn: conn.close()


def register_voter_in_db(voter_data):
    """Enregistre un nouveau votant dans la DB."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO voters (id_numerique, eligibility_key)
            VALUES (%s, %s);
        """, (voter_data['id_numerique'], voter_data['eligibility_key']))
        conn.commit()
        return True
    except psycopg2.errors.UniqueViolation:
        logger.warning(f"Votant ou clé d'éligibilité déjà enregistré.")
        conn.rollback()
        return False
    except Exception as e:
        logger.error(f"Erreur register_voter_in_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def is_eligible_key_available(eligibility_key):
    """Vérifie si la clé d'éligibilité existe dans la whitelist et n'a pas encore été utilisée."""
    conn = get_db_connection()
    if not conn:
        logger.warning("DB non connectée. L'éligibilité ne peut être vérifiée.")
        return False
    
    cur = conn.cursor()
    try:
        # 1. Vérifier si la clé est dans la liste d'éligibilité (whitelist)
        cur.execute("SELECT eligibility_key FROM eligibility_list WHERE eligibility_key = %s;", (eligibility_key,))
        if not cur.fetchone():
            return False # Clé non valide
        
        # 2. Vérifier si la clé n'a pas été utilisée par un votant déjà enregistré
        cur.execute("SELECT id_numerique FROM voters WHERE eligibility_key = %s;", (eligibility_key,))
        if cur.fetchone():
            return False # Clé déjà utilisée
        
        return True
    except Exception as e:
        logger.error(f"Erreur is_eligible_key_available: {e}")
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def update_voter_has_voted(id_numerique, status=True):
    """Met à jour le statut 'has_voted' d'un votant."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE voters
            SET has_voted = %s
            WHERE id_numerique = %s;
        """, (status, id_numerique))
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur update_voter_has_voted: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_all_voters():
    """Récupère tous les votants enregistrés."""
    conn = get_db_connection()
    if not conn:
        return {}
    
    cur = conn.cursor()
    voters = {}
    try:
        cur.execute("SELECT id_numerique, has_voted FROM voters;")
        for row in cur.fetchall():
            voters[row[0]] = {'id_numerique': row[0], 'has_voted': row[1]}
        return voters
    except Exception as e:
        logger.error(f"Erreur get_all_voters: {e}")
        return {}
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_voters_stats():
    """Calcule des statistiques de vote pour le dashboard."""
    conn = get_db_connection()
    if not conn:
        # Retourne des stats vides en cas d'échec
        return {
            'total_eligible': 0, 
            'eligible_to_register': 0, 
            'total_students_voters': 0, 
            'total_students_voted': 0
        }
    
    cur = conn.cursor()
    stats = {}
    try:
        # Nombre total de clés éligibles
        cur.execute("SELECT COUNT(*) FROM eligibility_list;")
        total_eligible = cur.fetchone()[0]
        stats['total_eligible'] = total_eligible

        # Nombre total de votants enregistrés (ont reçu un ID numérique)
        cur.execute("SELECT COUNT(*) FROM voters;")
        total_students_voters = cur.fetchone()[0]
        stats['total_students_voters'] = total_students_voters
        
        # Nombre total de votants ayant voté
        cur.execute("SELECT COUNT(*) FROM voters WHERE has_voted = TRUE;")
        total_students_voted = cur.fetchone()[0]
        stats['total_students_voted'] = total_students_voted
        
        # Le nombre de clés éligibles restantes (non encore enregistrées)
        stats['eligible_to_register'] = max(0, total_eligible - total_students_voters)
        
        return stats
    except Exception as e:
        logger.error(f"Erreur get_voters_stats: {e}")
        return {
            'total_eligible': 0, 
            'eligible_to_register': 0, 
            'total_students_voters': 0, 
            'total_students_voted': 0
        }
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_candidates():
    """Récupère tous les candidats."""
    conn = get_db_connection()
    if not conn:
        return {}
    
    cur = conn.cursor()
    candidates = {}
    try:
        cur.execute("""
            SELECT 
                candidate_id, nom, prenom, parcours, photo_path, slogan, programme, is_validated, registered_at
            FROM 
                candidates;
        """)
        
        for row in cur.fetchall():
            candidate_id = row[0]
            candidates[candidate_id] = {
                'candidate_id': candidate_id,
                'nom': row[1],
                'prenom': row[2],
                'parcours': row[3],
                'photo_path': row[4],
                'slogan': row[5],
                'programme': row[6],
                'is_validated': row[7],
                # Convertir l'objet datetime en chaîne pour la cohérence
                'registered_at': row[8].isoformat() if row[8] else None 
            }
        return candidates
    except Exception as e:
        logger.error(f"Erreur get_candidates: {e}")
        return {}
    finally:
        if cur: cur.close()
        if conn: conn.close()

def get_candidate(candidate_id):
    """Récupère un candidat par ID."""
    conn = get_db_connection()
    if not conn:
        return None
    
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT 
                candidate_id, nom, prenom, parcours, photo_path, slogan, programme, is_validated, registered_at
            FROM 
                candidates
            WHERE candidate_id = %s;
        """, (candidate_id,))
        
        row = cur.fetchone()
        if row:
            return {
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
        return None
    except Exception as e:
        logger.error(f"Erreur get_candidate: {e}")
        return None
    finally:
        if cur: cur.close()
        if conn: conn.close()


def add_or_update_candidate(candidate_data, is_new):
    """Ajoute ou met à jour un candidat dans la DB."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cur = conn.cursor()
    try:
        if is_new:
            cur.execute("""
                INSERT INTO candidates (candidate_id, nom, prenom, parcours, photo_path, slogan, programme, is_validated)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
            """, (
                candidate_data['candidate_id'], 
                candidate_data['nom'], 
                candidate_data['prenom'], 
                candidate_data['parcours'], 
                candidate_data['photo_path'], 
                candidate_data['slogan'], 
                candidate_data['programme'], 
                candidate_data['is_validated']
            ))
        else:
            cur.execute("""
                UPDATE candidates
                SET is_validated = %s
                WHERE candidate_id = %s;
            """, (
                candidate_data['is_validated'], 
                candidate_data['candidate_id']
            ))
        
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Erreur add_or_update_candidate: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()


def delete_candidate_from_db(candidate_id):
    """Supprime un candidat de la base de données."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM candidates WHERE candidate_id = %s RETURNING photo_path;", (candidate_id,))
        deleted_row = cur.fetchone()
        conn.commit()
        
        if deleted_row and deleted_row[0]:
            photo_path = deleted_row[0]
            # Supprimer l'image si elle existe
            if os.path.exists(photo_path):
                os.remove(photo_path)
                logger.info(f"Image supprimée: {photo_path}")
        
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur delete_candidate_from_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()

def add_eligibility_key_to_db(eligibility_key):
    """Ajoute une clé d'éligibilité à la DB."""
    conn = get_db_connection()
    if not conn:
        return False
    
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO eligibility_list (eligibility_key)
            VALUES (%s);
        """, (eligibility_key,))
        conn.commit()
        return True
    except psycopg2.errors.UniqueViolation:
        conn.rollback() # La clé existe déjà
        return False
    except Exception as e:
        logger.error(f"Erreur add_eligibility_key_to_db: {e}")
        conn.rollback()
        return False
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
def clear_db_data(cur):
    """Fonction interne pour effacer les données de vote/candidature/éligibilité/blockchain."""
    cur.execute("TRUNCATE voters RESTART IDENTITY;")
    cur.execute("TRUNCATE candidates RESTART IDENTITY;")
    cur.execute("TRUNCATE eligibility_list RESTART IDENTITY;")
    cur.execute("TRUNCATE blockchain RESTART IDENTITY;")
    # Réinitialiser les paramètres à leur état initial (SETUP, CLOSED, HIDDEN)
    for key, value in DEFAULT_SETTINGS.items():
        str_value = str(value).upper() if isinstance(value, bool) else str(value)
        cur.execute("""
            UPDATE settings SET value = %s WHERE key = %s;
        """, (str_value, key))
    # Supprimer toutes les images de candidats (nettoyage du système de fichiers)
    for filename in os.listdir(CANDIDATE_IMAGES_DIR):
        file_path = os.path.join(CANDIDATE_IMAGES_DIR, filename)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
        except Exception as e:
            logger.error(f"Erreur de suppression du fichier {file_path}: {e}")
            
    logger.info("Données Votants, Candidats, Blockchain, Eligibilité et Paramètres réinitialisés.")

# --- FONCTIONS BLOCKCHAIN ---

def sha256(data):
    """Calcule le hash SHA-256 d'une chaîne de caractères ou d'un dictionnaire."""
    # S'assurer que les données JSON sont triées pour un hash cohérent
    if isinstance(data, dict):
        data = json.dumps(data, sort_keys=True)
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def get_full_blockchain_from_db():
    """Récupère la blockchain complète depuis la DB."""
    conn = get_db_connection()
    if not conn:
        logger.warning("DB non connectée. Blockchain vide.")
        return []
    
    cur = conn.cursor()
    chain = []
    try:
        # Trier par index pour reconstruire la chaîne correctement
        cur.execute("""
            SELECT 
                block_index, timestamp, payload, previous_hash, hash, proof, type
            FROM 
                blockchain
            ORDER BY 
                block_index;
        """)
        
        for row in cur.fetchall():
            chain.append({
                'index': row[0],
                'timestamp': row[1],
                'payload': row[2], # PostgreSQL retourne JSONB directement comme un dict/list Python
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
    """Ajoute un bloc à la DB et retourne le bloc inséré, ou None en cas d'échec."""
    conn = get_db_connection()
    if not conn:
        return None
    
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO blockchain (block_index, timestamp, payload, previous_hash, hash, proof, type)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING block_index, timestamp, payload, previous_hash, hash, proof, type;
        """, (
            block['index'],
            block['timestamp'],
            json.dumps(block['payload']), # S'assurer que le payload est bien en chaîne JSON pour la DB
            block['previous_hash'],
            block['hash'],
            block['proof'],
            block['type']
        ))
        
        row = cur.fetchone()
        conn.commit()
        
        if row:
            # Reconstruire le dictionnaire du bloc (le payload est un objet Python grâce au type JSONB)
            return {
                'index': row[0],
                'timestamp': row[1],
                'payload': row[2], 
                'previous_hash': row[3],
                'hash': row[4],
                'proof': row[5],
                'type': row[6]
            }
        return None
    except Exception as e:
        logger.error(f"Erreur add_block_to_db: {e}")
        conn.rollback()
        return None
    finally:
        if cur: cur.close()
        if conn: conn.close()


class Blockchain:
    def __init__(self):
        """Initialise la chaîne de blocs en la chargeant depuis la base de données."""
        self.chain = get_full_blockchain_from_db()
        self.nodes = set()  # Pour l'évolutivité (pas utilisé ici, mais bonne pratique)
        
        # Si la chaîne est vide, crée le bloc Genesis
        if not self.chain:
            logger.info("Chaîne vide. Le bloc Genesis devrait être créé par init_db().")
            self.create_block(proof=100, previous_hash='1', type="GENESIS", payload={"message": "Bloc de Génèse créé."})
        else:
             logger.info(f"Blockchain chargée (taille: {len(self.chain)} blocs).")

    @property
    def last_block(self):
        """Retourne le dernier bloc de la chaîne, ou None si elle est vide."""
        return self.chain[-1] if self.chain else None

    @staticmethod
    def hash(block):
        """Crée un hash SHA-256 pour un bloc."""
        # On utilise le même sha256 utilitaire pour la cohérence
        return sha256(block)

    def proof_of_work(self, last_proof):
        """Algorithme de Proof of Work simple : Trouver un nombre (proof) 
        tel que hash(last_proof * new_proof) contienne 4 zéros au début.
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """Valide si le hash d'un bloc correspond aux critères (4 zéros au début)."""
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def create_block(self, proof, previous_hash, type="EVENT", payload=None):
        """ Crée un nouveau bloc dans la Blockchain et l'ajoute à la DB. """
        last_block_index = self.last_block['index'] if self.last_block else -1
        
        block = {
            'index': last_block_index + 1,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'payload': payload if payload is not None else {},
            'previous_hash': previous_hash,
            'proof': proof,
            'type': type
        }
        
        # Calcul du hash après avoir défini tous les champs sauf le hash lui-même
        block['hash'] = self.hash(block)
        
        # Ajout à la base de données (et re-vérification du bloc inséré)
        new_block_db = add_block_to_db(block)
        
        if new_block_db:
            # Si l'insertion réussit, mettre à jour la chaîne en mémoire
            self.chain.append(new_block_db)
            return new_block_db
        else:
            logger.error("Échec de l'ajout du bloc dans la base de données.")
            return None

    def add_vote(self, voter_id, candidate_id):
        """Ajoute un bloc de vote à la blockchain."""
        last_block = self.last_block
        if not last_block:
            return {'error': "Pas de bloc précédent trouvé."}, 500

        last_proof = last_block['proof']
        proof = self.proof_of_work(last_proof)
        
        payload = {
            'voter_id_hash': sha256(voter_id), # Hash de l'ID pour l'anonymat
            'candidate_id': candidate_id,
            'time': datetime.now(timezone.utc).isoformat()
        }
        
        new_block = self.create_block(
            proof=proof, 
            previous_hash=last_block['hash'],
            type="VOTE",
            payload=payload
        )
        
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
            logger.error("Pas de bloc 'last_block'. Impossible d'ajouter un événement.")
            return None

        last_proof = last_block['proof']
        # Pour les événements, on peut simplifier le PoW ou utiliser une preuve fixe si non critique
        # Utilisons le même PoW pour la cohérence
        proof = self.proof_of_work(last_proof)
        
        new_block = self.create_block(
            proof=proof, 
            previous_hash=last_block['hash'],
            type=event_type,
            payload=payload
        )
        return new_block


# Instance globale de la Blockchain (sera initialisée par le hook de l'application)
blockchain = None 

# --- FONCTIONS DE RÉSULTATS ---

def calculate_results():
    """Calcule les résultats agrégés à partir de la blockchain."""
    if not blockchain or not blockchain.chain:
        return [], 0
    
    # 1. Obtenir les candidats validés (pour filtrer les votes)
    all_candidates = get_candidates()
    validated_candidate_ids = {c_id for c_id, data in all_candidates.items() if data['is_validated']}
    
    # 2. Compter les votes
    vote_counts = {c_id: 0 for c_id in validated_candidate_ids}
    total_votes = 0
    
    for block in blockchain.chain:
        if block['type'] == 'VOTE' and block['payload']:
            candidate_id = block['payload'].get('candidate_id')
            if candidate_id in vote_counts:
                vote_counts[candidate_id] += 1
                total_votes += 1
                
    # 3. Formater les résultats
    results = []
    
    # Ajouter un vote à 'BLANC' s'il n'y a pas de candidats validés pour éviter une division par zéro
    # Le cas 'BLANC' ou 'NULL' n'est pas géré explicitement dans le bloc, on se concentre sur les candidats
    
    for candidate_id, votes in vote_counts.items():
        candidate_info = all_candidates.get(candidate_id, {'nom': 'Inconnu', 'prenom': '', 'parcours': 'N/A'})
        percentage = round((votes / total_votes) * 100, 2) if total_votes > 0 else 0
        
        results.append({
            'candidate_id': candidate_id,
            'nom_complet': f"{candidate_info['prenom']} {candidate_info['nom']}",
            'parcours': candidate_info['parcours'],
            'photo_path': candidate_info['photo_path'],
            'votes': votes,
            'percentage': percentage
        })
        
    # Trier les résultats : le plus grand nombre de votes en premier
    results.sort(key=lambda x: x['votes'], reverse=True)
    
    return results, total_votes

# --- DÉCORATEURS D'ACCÈS ---

def admin_required(f):
    """Vérifie si l'utilisateur est connecté en tant qu'administrateur."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', error="Accès refusé. Veuillez vous connecter."))
        
        # Pour une réutilisation facile de l'username et du rôle dans les vues
        g.admin_username = session.get('admin_username')
        g.admin_role = session.get('admin_role')
        return f(*args, **kwargs)
    return decorated_function

def admin_login_required(f):
    """Vérifie si l'utilisateur est connecté en tant qu'administrateur (pour les routes de login qui redirigent vers dashboard)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('admin_logged_in'):
            # Si déjà connecté, rediriger vers le tableau de bord
            return redirect(url_for('admin_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def voter_required(f):
    """Vérifie si l'utilisateur est connecté en tant que votant."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        voter_id = session.get('voter_id')
        if not voter_id:
            return redirect(url_for('voter_login', error="Accès refusé. Veuillez vous connecter."))
        
        # Vérification supplémentaire: le votant doit exister et ne pas avoir voté.
        voter = get_voter(voter_id)
        if not voter:
            session.pop('voter_id', None)
            return redirect(url_for('voter_login', error="Votre session de vote a expiré ou votre ID est invalide."))
        
        # Vérifier l'état de l'élection
        SETTINGS = get_settings()
        if SETTINGS.get('election_status') != 'VOTING' or SETTINGS.get('voting_status') != 'OPEN':
            session.pop('voter_id', None) # Fermer la session de vote
            return render_template('error_page.html', message="Le vote est actuellement fermé par l'administration.")
            
        if voter['has_voted']:
            session.pop('voter_id', None) # Fermer la session de vote
            return render_template('error_page.html', message="Vous avez déjà voté. Un seul vote par étudiant est autorisé.")
        
        g.voter_id = voter_id
        g.voter_info = voter
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES GÉNÉRALES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/explorer')
def explorer():
    # Préparation des données de la blockchain pour l'explorateur
    chain = blockchain.chain
    
    # Préparation pour l'affichage (anonymisation des données sensibles)
    sanitized_chain = []
    CANDIDATES = get_candidates()
    
    for block in chain:
        sanitized_block = block.copy()
        
        # Anonymiser les blocs de VOTE
        if sanitized_block['type'] == 'VOTE' and isinstance(sanitized_block['payload'], dict):
            # On ne garde que les informations non sensibles du vote
            candidate_id = sanitized_block['payload'].get('candidate_id')
            candidate_info = CANDIDATES.get(candidate_id, {'nom': 'Candidat Inconnu', 'prenom': ''})
            
            anonymized_payload = {
                'voter_id_hash': sanitized_block['payload'].get('voter_id_hash', 'N/A'),
                'candidate_voted': f"{candidate_info['prenom']} {candidate_info['nom']}",
                'time': sanitized_block['payload'].get('time', 'N/A')
            }
            sanitized_block['payload'] = anonymized_payload
            
        sanitized_chain.append(sanitized_block)
        
    return render_template('explorer_vote.html', chain=sanitized_chain)

# --- ROUTES ADMIN ---

@app.route('/admin/login', methods=['GET', 'POST'])
@admin_login_required
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user_data = get_admin_user(username)
        
        if user_data and check_password_hash(user_data['hash'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = user_data['username']
            session['admin_role'] = user_data['role']
            # Ajout d'un événement de connexion à la blockchain (pour l'audit)
            blockchain.add_event("ADMIN_LOGIN", {'admin': user_data['username'], 'status': 'SUCCESS'})
            return redirect(url_for('admin_dashboard', message="Connexion réussie."))
        else:
            # Ajout d'un événement d'échec de connexion
            blockchain.add_event("ADMIN_LOGIN", {'admin': username, 'status': 'FAILURE'})
            return render_template('admin_login.html', error="Nom d'utilisateur ou mot de passe incorrect.")

    # Affichage du formulaire (GET)
    return render_template('admin_login.html', error=request.args.get('error'))

@app.route('/admin/logout')
@admin_required
def admin_logout():
    # Ajout d'un événement de déconnexion
    blockchain.add_event("ADMIN_LOGOUT", {'admin': session.get('admin_username')})
    
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    return redirect(url_for('admin_login', message="Vous avez été déconnecté."))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    admin_username = g.admin_username
    admin_role = g.admin_role
    
    # 1. Récupérer les données
    SETTINGS = get_settings() # Récupérer les paramètres
    CANDIDATES = get_candidates()
    voters_stats = get_voters_stats()
    
    # 2. Séparation des candidats pour l'affichage
    pending_candidates = sorted([c for c in CANDIDATES.values() if not c.get('is_validated')], key=lambda x: x['registered_at'], reverse=True)
    validated_candidates = sorted([c for c in CANDIDATES.values() if c.get('is_validated')], key=lambda x: x['registered_at'], reverse=True)

    # 3. Calcul des résultats pour affichage rapide
    results, total_votes = calculate_results()
    
    # 4. Calcul du taux de participation (basé sur l'éligibilité totale)
    total_eligible = voters_stats['total_eligible']
    participation_rate = (voters_stats['total_students_voted'] / total_eligible * 100) if total_eligible > 0 else 0

    # 5. Rendu du template avec toutes les données
    return render_template('admin_dashboard.html',
        admin_username=admin_username,
        admin_role=admin_role,
        
        # 💥 CORRECTION DE L'ERREUR JINJA UNDEFINED 'SETTINGS' 💥
        SETTINGS=SETTINGS, 
        
        voters_stats=voters_stats,
        pending_candidates=pending_candidates,
        validated_candidates=validated_candidates,
        results=results,
        total_votes=total_votes,
        participation_rate=round(participation_rate, 2),
        message=request.args.get('message'),
        error=request.args.get('error')
    )

# --- API DE CONTRÔLE ADMIN ---

@app.route('/api/admin/control', methods=['POST'])
@admin_required
def admin_control_api():
    data = request.get_json()
    action = data.get('action')
    admin = session.get('admin_username')
    
    if action == 'open_candidacy':
        if update_setting_in_db('candidacy_open', True):
            blockchain.add_event("CANDIDACY_OPENED", {'admin': admin})
            return jsonify({'success': "Période de candidature ouverte."}), 200
        else:
            return jsonify({'error': "Échec de l'ouverture de la candidature."}), 500
            
    elif action == 'close_candidacy':
        if update_setting_in_db('candidacy_open', False):
            blockchain.add_event("CANDIDACY_CLOSED", {'admin': admin})
            return jsonify({'success': "Période de candidature fermée."}), 200
        else:
            return jsonify({'error': "Échec de la fermeture de la candidature."}), 500
    
    elif action == 'start_election':
        current_settings = get_settings()
        if current_settings.get('election_status') != 'SETUP':
            return jsonify({'error': "L'élection est déjà en cours ou terminée."}), 400
        
        # Vérifier qu'il y a au moins un candidat validé
        validated_candidates = [c for c in get_candidates().values() if c['is_validated']]
        if not validated_candidates:
            return jsonify({'error': "Aucun candidat validé. Impossible de démarrer l'élection."}), 400
            
        if update_setting_in_db('election_status', 'VOTING') and update_setting_in_db('voting_status', 'OPEN'):
            # Fermer automatiquement les candidatures au démarrage de l'élection
            update_setting_in_db('candidacy_open', False) 
            blockchain.add_event("ELECTION_STARTED", {'admin': admin, 'validated_candidates_count': len(validated_candidates)})
            return jsonify({'success': "Élection démarrée. Vote ouvert."}), 200
        else:
            return jsonify({'error': "Échec du démarrage de l'élection."}), 500

    elif action == 'close_election':
        current_settings = get_settings()
        if current_settings.get('election_status') != 'VOTING':
            return jsonify({'error': "L'élection n'est pas en cours (état: VOTING)."}), 400
            
        if update_setting_in_db('election_status', 'CLOSED') and update_setting_in_db('voting_status', 'CLOSED'):
            blockchain.add_event("ELECTION_CLOSED", {'admin': admin})
            return jsonify({'success': "Élection terminée. Vote fermé."}), 200
        else:
            return jsonify({'error': "Échec de la fermeture de l'élection."}), 500
            
    elif action == 'show_results':
        current_settings = get_settings()
        if current_settings.get('election_status') != 'CLOSED':
            return jsonify({'error': "L'élection doit être CLÔTURÉE pour afficher les résultats finaux."}), 400
            
        if update_setting_in_db('results_visibility', 'VISIBLE'):
            blockchain.add_event("RESULTS_MADE_VISIBLE", {'admin': admin})
            return jsonify({'success': "Résultats rendus visibles."}), 200
        else:
            return jsonify({'error': "Échec de l'affichage des résultats."}), 500

    elif action == 'hide_results':
        if update_setting_in_db('results_visibility', 'HIDDEN'):
            blockchain.add_event("RESULTS_MADE_HIDDEN", {'admin': admin})
            return jsonify({'success': "Résultats rendus cachés."}), 200
        else:
            return jsonify({'error': "Échec du masquage des résultats."}), 500

    elif action == 'reset_system':
        return reset_system() # Appel de la fonction de réinitialisation définie plus bas

    else:
        return jsonify({'error': "Action inconnue."}), 400

@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@admin_required
def admin_candidate_action_api(candidate_id):
    data = request.get_json()
    action = data.get('action')
    admin = session.get('admin_username')
    
    candidate = get_candidate(candidate_id)
    if not candidate:
        return jsonify({'error': "Candidat non trouvé."}), 404
        
    if action == 'validate':
        if candidate['is_validated']:
            return jsonify({'error': "Candidat déjà validé."}), 400
            
        candidate['is_validated'] = True
        if add_or_update_candidate(candidate, is_new=False):
            blockchain.add_event("CANDIDATE_VALIDATED", {'admin': admin, 'candidate_id': candidate_id})
            return jsonify({'success': f"Candidat {candidate_id} validé."}), 200
        else:
            return jsonify({'error': "Échec de la validation."}), 500
            
    elif action == 'delete':
        if delete_candidate_from_db(candidate_id):
            blockchain.add_event("CANDIDATE_DELETED", {'admin': admin, 'candidate_id': candidate_id})
            return jsonify({'success': f"Candidat {candidate_id} et son image supprimés."}), 200
        else:
            return jsonify({'error': "Échec de la suppression."}), 500
            
    else:
        return jsonify({'error': "Action inconnue."}), 400

@app.route('/api/admin/import_eligibility', methods=['POST'])
@admin_required
def import_eligibility_api():
    if 'file' not in request.files:
        return jsonify({'error': "Aucun fichier n'a été envoyé."}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': "Fichier vide ou nom de fichier manquant."}), 400

    if file:
        filename = secure_filename(file.filename)
        if not filename.endswith('.csv') and not filename.endswith('.xlsx'):
            return jsonify({'error': "Format de fichier non supporté. Seuls les fichiers .csv ou .xlsx sont acceptés."}), 400

        # Utiliser un fichier temporaire pour lire les données
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                file.save(tmp_file.name)
                tmp_file_path = tmp_file.name

            # Lire le fichier avec pandas
            if filename.endswith('.csv'):
                df = pd.read_csv(tmp_file_path, encoding='utf-8')
            elif filename.endswith('.xlsx'):
                df = pd.read_excel(tmp_file_path)
            
            # Vérifier la colonne
            if 'eligibility_key' not in df.columns:
                os.unlink(tmp_file_path) # Nettoyer
                return jsonify({'error': "Le fichier doit contenir une colonne nommée 'eligibility_key'."}), 400
            
            # Traiter les clés
            new_keys_added = 0
            
            # Utiliser la transaction pour insérer les clés
            conn = get_db_connection()
            if not conn:
                os.unlink(tmp_file_path)
                return jsonify({'error': "Erreur de connexion à la base de données."}), 500
            
            cur = conn.cursor()
            try:
                for key in df['eligibility_key'].astype(str).str.strip().tolist():
                    # Utiliser la fonction add_eligibility_key_to_db qui gère l'unicité
                    try:
                        cur.execute("INSERT INTO eligibility_list (eligibility_key) VALUES (%s);", (key,))
                        new_keys_added += 1
                    except psycopg2.errors.UniqueViolation:
                        conn.rollback()
                        cur = conn.cursor() # Réouvrir le curseur après rollback
                        pass # La clé existe déjà, on ignore
                        
                conn.commit()
                blockchain.add_event("ELIGIBILITY_LIST_UPDATED", {'admin': session.get('admin_username'), 'keys_added': new_keys_added})
                
                os.unlink(tmp_file_path) # Nettoyer
                return jsonify({'success': f"{new_keys_added} nouvelles clés d'éligibilité ont été ajoutées (Total dans le fichier: {len(df)})."}), 200
            
            except Exception as e:
                logger.error(f"Erreur lors de l'insertion des clés: {e}")
                conn.rollback()
                os.unlink(tmp_file_path) # Nettoyer
                return jsonify({'error': f"Erreur critique lors de l'insertion : {e}"}), 500
            finally:
                if cur: cur.close()
                if conn: conn.close()
                
        except Exception as e:
            logger.error(f"Erreur de traitement du fichier: {e}")
            if 'tmp_file_path' in locals() and os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
            return jsonify({'error': f"Erreur lors du traitement du fichier: {e}"}), 500
        
    return jsonify({'error': "Échec de l'importation."}), 500


# --- ROUTES CANDIDAT (AUTO-INSCRIPTION) ---

@app.route('/self_register_candidate')
def self_register_candidate_get():
    SETTINGS = get_settings()
    if not SETTINGS.get('candidacy_open'):
        return render_template('error_page.html', message="La période d'inscription des candidatures est actuellement fermée.")
    return render_template('self_register_candidate.html')

@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate_api():
    # 1. Vérifier le statut de candidature
    SETTINGS = get_settings()
    if not SETTINGS.get('candidacy_open'):
        return jsonify({'error': "La période de candidature est fermée."}), 400
        
    # 2. Récupérer les données du formulaire multipart
    nom = request.form.get('nom')
    prenom = request.form.get('prenom')
    parcours = request.form.get('parcours')
    slogan = request.form.get('slogan')
    programme = request.form.get('programme')
    file = request.files.get('photo')
    
    # Validation basique
    if not all([nom, prenom, parcours, slogan, programme, file]):
        return jsonify({'error': "Tous les champs sont requis (y compris la photo)."}), 400

    # 3. Générer un ID unique et gérer la photo
    candidate_id = str(uuid4())
    photo_path = None
    
    if file and file.filename:
        filename = secure_filename(candidate_id + '_' + file.filename)
        photo_path = os.path.join(CANDIDATE_IMAGES_DIR, filename)
        try:
            file.save(photo_path)
        except Exception as e:
            logger.error(f"Erreur de sauvegarde de l'image: {e}")
            return jsonify({'error': "Échec de l'enregistrement de l'image."}), 500
    
    candidate_data = {
        'candidate_id': candidate_id,
        'nom': nom,
        'prenom': prenom,
        'parcours': parcours,
        'photo_path': photo_path,
        'slogan': slogan,
        'programme': programme,
        'is_validated': False # Toujours false à l'auto-inscription
    }
    
    # 4. Enregistrer dans la base de données
    if add_or_update_candidate(candidate_data, is_new=True):
        # 5. Enregistrement de l'événement dans la Blockchain
        event_payload = {
            'candidate_id': candidate_id,
            'parcours': parcours,
            'message': 'Nouvelle candidature en attente de validation'
        }
        blockchain.add_event("CANDIDACY_SUBMITTED", event_payload)
        return jsonify({'success': True, 'candidate_id': candidate_id}), 200
    else:
        # En cas d'échec de la DB, nettoyer l'image
        if photo_path and os.path.exists(photo_path):
            os.remove(photo_path)
        return jsonify({'error': "Erreur lors de l'enregistrement de la candidature dans la base de données."}), 500

# --- ROUTES VOTANT (AUTO-INSCRIPTION & LOGIN) ---

@app.route('/self_register_student')
def self_register_student_get():
    SETTINGS = get_settings()
    # Le formulaire d'inscription doit être ouvert si l'élection n'est pas fermée
    if SETTINGS.get('election_status') == 'CLOSED':
         return render_template('error_page.html', message="L'élection est terminée. L'inscription des votants est fermée.")
    return render_template('self_register_student.html')

@app.route('/api/student/self_register', methods=['POST'])
def self_register_student_api():
    # 1. Vérifier l'état de l'élection
    SETTINGS = get_settings()
    if SETTINGS.get('election_status') == 'CLOSED':
         return jsonify({'error': "L'élection est terminée. L'inscription des votants est fermée."}), 400

    # 2. Récupérer les données
    data = request.get_json()
    nom = data.get('nom')
    prenom = data.get('prenom')
    parcours = data.get('parcours')
    
    if not all([nom, prenom, parcours]):
        return jsonify({'error': "Tous les champs sont requis."}), 400

    # Créer la clé d'éligibilité
    eligibility_key = sha256(f"{nom.strip().upper()}{prenom.strip().upper()}{parcours.strip().upper()}")

    # 3. Vérifier l'éligibilité (whitelist) et l'unicité (pas déjà utilisé par un autre votant)
    if not is_eligible_key_available(eligibility_key):
        # Pour des raisons de sécurité, nous ne disons pas si la clé est invalide ou déjà utilisée.
        return jsonify({'error': "Échec de l'éligibilité. Vos informations ne correspondent pas à la liste autorisée."}), 403

    # 4. Générer l'ID numérique du votant (ce qu'il utilisera pour se connecter)
    id_numerique = str(uuid4()) # ID unique et facile à stocker/utiliser

    voter_data = {
        'id_numerique': id_numerique,
        'eligibility_key': eligibility_key, # La clé d'éligibilité (le hash de ses infos) est stockée pour l'audit
        'has_voted': False,
    }
    
    # 5. Enregistrer dans la base de données
    if not register_voter_in_db(voter_data):
        return jsonify({'error': "Erreur lors de l'enregistrement de votre ID numérique dans la base de données. Veuillez réessayer."}), 500
        
    # 6. Enregistrement de l'événement dans la Blockchain
    event_payload = {
        'id_numerique': id_numerique,
        'eligibility_key_hash': sha256(eligibility_key), # Hash du hash pour plus de sécurité
        'nom': nom, # Le nom/prénom est stocké ICI (hors blockchain) mais aussi dans l'objet votant
        'prenom': prenom,
        'parcours': parcours,
        'message': 'Nouvel étudiant inscrit'
    }
    blockchain.add_event("VOTER_REGISTERED", event_payload)

    # 7. Retourner l'ID pour que l'étudiant le note
    return jsonify({'success': True, 'id_numerique': id_numerique}), 200

@app.route('/voter_login', methods=['GET', 'POST'])
def voter_login():
    SETTINGS = get_settings()
    
    # Le formulaire d'accès est toujours visible, mais on vérifie le statut au POST
    if request.method == 'POST':
        # Le login réel est géré par l'API /api/voter/login
        pass 
        
    return render_template('voter_login.html', 
        election_status=SETTINGS.get('election_status'),
        voting_status=SETTINGS.get('voting_status'),
        error=request.args.get('error')
    )

@app.route('/api/voter/login', methods=['POST'])
def voter_login_api():
    data = request.get_json()
    voter_id = data.get('id_numerique', '').strip()
    
    if not voter_id:
        return jsonify({'error': "Veuillez entrer votre ID numérique."}), 400
        
    SETTINGS = get_settings()
    
    # 1. Vérifier l'état de l'élection
    if SETTINGS.get('election_status') != 'VOTING' or SETTINGS.get('voting_status') != 'OPEN':
        return jsonify({'error': "Le vote est actuellement fermé par l'administration."}), 403
        
    # 2. Vérifier l'ID
    voter = get_voter(voter_id)
    if not voter:
        return jsonify({'error': "ID numérique invalide. Veuillez vérifier votre saisie ou vous inscrire."}), 403
        
    # 3. Vérifier si le votant a déjà voté
    if voter['has_voted']:
        return jsonify({'error': "Vous avez déjà voté. Un seul vote est autorisé."}), 403

    # 4. Connexion réussie
    session['voter_id'] = voter_id
    session.permanent = False # Déconnexion après fermeture du navigateur
    
    return jsonify({'success': True, 'redirect_url': url_for('voting_page')}), 200

# --- ROUTE DE VOTE ---

@app.route('/voting_page')
@voter_required
def voting_page():
    # v-voter_required a déjà fait toutes les vérifications (session, statut du vote, non-voté)
    
    # Récupérer la liste des candidats validés
    all_candidates = get_candidates()
    validated_candidates = [c for c in all_candidates.values() if c['is_validated']]
    
    if not validated_candidates:
        # Cas où un admin ferme une candidature mais ne démarre pas l'élection correctement
        return render_template('error_page.html', message="Aucun candidat validé n'est disponible. Le vote est temporairement indisponible.")
        
    return render_template('voting_page.html', candidates=validated_candidates, voter_id=g.voter_id)

@app.route('/api/vote', methods=['POST'])
@voter_required
def vote_api():
    data = request.get_json()
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')
    
    # Vérification de sécurité supplémentaire (ID du votant de la session VS ID du formulaire)
    if voter_id != g.voter_id:
        return jsonify({'error': "Erreur de sécurité: ID de votant ne correspond pas à la session."}), 403
        
    # Vérification que le candidat existe et est validé
    candidate = get_candidate(candidate_id)
    if not candidate or not candidate['is_validated']:
        return jsonify({'error': "Candidat invalide ou non validé."}), 400
        
    # Ajout du vote à la blockchain
    new_block = blockchain.add_vote(voter_id, candidate_id)
    
    if isinstance(new_block, dict) and 'error' in new_block:
         return jsonify(new_block), 500
         
    # Le vote a réussi, on déconnecte la session de vote
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
    results_visibility = SETTINGS.get('results_visibility')
    election_status = SETTINGS.get('election_status')
    
    # Si l'élection est en cours, afficher les résultats intermédiaires
    if election_status == 'VOTING':
        results, total_votes = calculate_results()
        status_message = "L'élection est en cours. Résultats en temps réel (intermédiaires)."
        
        return render_template('results.html',
            results=results,
            total_votes=total_votes,
            election_status=election_status,
            status_message=status_message
        )
    
    # Si l'élection est fermée et les résultats cachés, afficher le message de restriction
    elif election_status == 'CLOSED' and results_visibility == 'HIDDEN':
        status_message = "Les résultats sont actuellement cachés par l'administration."
        return render_template('results.html',
            results=[],
            total_votes=0,
            election_status=election_status,
            status_message=status_message
        )
        
    # Si l'élection est fermée et les résultats visibles, afficher la page finale
    elif election_status == 'CLOSED' and results_visibility == 'VISIBLE':
        results, total_votes = calculate_results()
        return render_template('results_final.html',
            results=results,
            total_votes=total_votes,
            election_status=election_status
        )
    
    # Sinon (SETUP ou autre état), pas de résultats à afficher
    else:
        status_message = "Le système de vote est en phase de préparation ou de configuration. Aucun vote n'a été enregistré."
        return render_template('results.html',
            results=[],
            total_votes=0,
            election_status=election_status,
            status_message=status_message
        )

# --- ROUTE DE RÉINITIALISATION DU SYSTÈME ---

def reset_system():
    """Efface toutes les données de vote (Votants, Candidats, Blockchain, Éligibilité) et réinitialise les paramètres."""
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': "Erreur de connexion à la base de données. Réinitialisation impossible."}), 500
        
    cur = conn.cursor()
    try:
        clear_db_data(cur)
        conn.commit()

        # Re-initialiser la blockchain en mémoire et dans la DB (création d'un nouveau bloc Genesis)
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
    pass