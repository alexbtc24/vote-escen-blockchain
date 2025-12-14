# serveur_vote.py
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

# --- CONFIGURATION INITIALE (CORRECTION de l'ERREUR GUNICORN) ---
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
CANDIDATE_UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'candidates_photos')
if not os.path.exists(CANDIDATE_UPLOAD_FOLDER):
    os.makedirs(CANDIDATE_UPLOAD_FOLDER)

# Configuration Admin (à changer en production)
ADMIN_USERS = {
    os.environ.get('ADMIN_USERNAME', 'ADMIN_INSTITUTION'): generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'test_secure'))
}

# --- GESTION DE LA BASE DE DONNÉES POSTGRESQL ---

def get_db_connection():
    """
    Établit et retourne une connexion à la base de données PostgreSQL.
    Utilise la variable d'environnement DATABASE_URL (pour Render).
    Retourne la connexion ou lève une exception.
    """
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        logger.error("Variable d'environnement DATABASE_URL non définie.")
        # Utiliser une exception spécifique ou un mécanisme de fallback
        raise ConnectionError("DATABASE_URL is not set.")

    try:
        url = urlparse(db_url)
        conn = psycopg2.connect(
            database=url.path[1:],
            user=url.username,
            password=url.password,
            host=url.hostname,
            port=url.port,
            # Configuration SSL nécessaire pour certains hébergeurs comme Render
            sslmode='require'
        )
        return conn
    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données: {e}")
        raise

def init_db():
    """
    Initialise les tables de la base de données si elles n'existent pas
    ET s'assure que le bloc Genesis existe.
    """
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        logger.info("Démarrage de la création des tables de la base de données...")
        
        # Table Candidats
        cur.execute("""
            CREATE TABLE IF NOT EXISTS candidats (
                id SERIAL PRIMARY KEY,
                id_numerique VARCHAR(255) UNIQUE NOT NULL,
                nom VARCHAR(255) NOT NULL,
                prenom VARCHAR(255) NOT NULL,
                slogan TEXT,
                programme TEXT,
                photo_path VARCHAR(255),
                statut VARCHAR(50) DEFAULT 'pending', -- pending, accepted, rejected
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Table Votants (Éligibilité)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS votants (
                id SERIAL PRIMARY KEY,
                id_numerique VARCHAR(255) UNIQUE NOT NULL,
                nom VARCHAR(255) NOT NULL,
                prenom VARCHAR(255) NOT NULL,
                parcours VARCHAR(255),
                has_voted BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Table Blockchain
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blockchain (
                index INTEGER PRIMARY KEY,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                data TEXT NOT NULL,
                previous_hash VARCHAR(64) NOT NULL,
                hash VARCHAR(64) UNIQUE NOT NULL,
                nonce INTEGER NOT NULL
            );
        """)

        # Table Configuration (pour le statut du vote, les résultats, etc.)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS configuration (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT NOT NULL
            );
        """)
        
        # Initialisation du statut du vote si non présent
        cur.execute("SELECT value FROM configuration WHERE key = 'election_status'")
        if cur.fetchone() is None:
            cur.execute("INSERT INTO configuration (key, value) VALUES ('election_status', 'SETUP')")
        
        # Initialisation de la visibilité des résultats si non présente
        cur.execute("SELECT value FROM configuration WHERE key = 'results_visible'")
        if cur.fetchone() is None:
            cur.execute("INSERT INTO configuration (key, value) VALUES ('results_visible', 'False')")

        conn.commit()
        logger.info("Tables créées avec succès.")
        
        # --- CORRECTION DE L'ERREUR : VÉRIFICATION DU BLOC GENESIS EN PUR SQL ---
        
        # Vérifie si le bloc genesis existe déjà (index 0)
        cur.execute("SELECT COUNT(*) FROM blockchain WHERE index = 0;")
        count = cur.fetchone()[0]

        if count == 0:
            logger.info("Bloc Genesis non trouvé. Création du bloc Genesis...")
            # On crée un bloc genesis "virtuel" pour le minage
            genesis_block = Block(
                index=0,
                timestamp=datetime.now(timezone.utc),
                data=json.dumps({"message": "Bloc Genesis du système de vote ESCEN", "type": "GENESIS"}),
                previous_hash="0" * 64
            )
            
            # Initialisation de la blockchain pour le minage et l'enregistrement
            temp_blockchain = Blockchain(initial_load=False) 
            temp_blockchain.mine_block(genesis_block, skip_db_check=True) # Calcule le hash
            
            # Enregistrement du bloc
            cur.execute("""
                INSERT INTO blockchain (index, timestamp, data, previous_hash, hash, nonce)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (genesis_block.index, genesis_block.timestamp, genesis_block.data, genesis_block.previous_hash, genesis_block.hash, genesis_block.nonce))
            
            conn.commit()
            logger.info("Bloc Genesis créé et enregistré dans la base de données.")
        else:
            logger.info("Bloc Genesis déjà présent dans la base de données.")


    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation de la base de données: {e}")
        if conn:
            conn.rollback()
        # En production, cela pourrait être fatal, mieux vaut propager l'erreur.
        raise
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# --- BLOCEKCHAIN LOGIC (INTÉGRALEMENT CONSERVÉ ET ADAPTÉ) ---

class Block:
    """Représente un bloc dans la blockchain."""
    def __init__(self, index, timestamp, data, previous_hash, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Calcule le hachage SHA-256 du bloc."""
        # Convertir l'objet en JSON string et encoder
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @classmethod
    def from_db_row(cls, row):
        """Crée un objet Block à partir d'une ligne de la DB."""
        # row: (index, timestamp, data, previous_hash, hash, nonce)
        # Assurez-vous que le timestamp est converti correctement
        return cls(
            index=row[0],
            timestamp=row[1], # psycopg2 retourne un datetime object
            data=row[2],
            previous_hash=row[3],
            nonce=row[5]
        )

class Blockchain:
    """Gère la chaîne de blocs et les opérations de minage."""
    def __init__(self, initial_load=True):
        self.difficulty = 4 # Difficulté de minage (nombre de zéros initiaux)
        self.chain = []
        
        if initial_load:
            self.chain = self.load_chain()
        
        # NOTE: La création du bloc genesis est maintenant gérée par init_db() pour éviter les conflits au démarrage.
        # Si load_chain est appelé et que la chaîne est vide, cela signifie que init_db a échoué ou n'a pas été appelé.
        # Si la chaîne est vide, on laisse l'erreur de l'environnement (pas de DB) être gérée par le try/except global.

    def load_chain(self):
        """Charge la blockchain depuis la base de données."""
        conn = None
        cur = None
        chain = []
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT index, timestamp, data, previous_hash, hash, nonce FROM blockchain ORDER BY index ASC")
            
            rows = cur.fetchall()
            for row in rows:
                # Créer des objets Block à partir des lignes de la DB
                block = Block.from_db_row(row)
                chain.append(block)

            return chain

        except ConnectionError as ce:
            logger.warning(f"Impossible de charger la chaîne (mode non persistant ?): {ce}. Retourne chaîne vide.")
            return []
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la blockchain depuis la DB: {e}")
            return []
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    def save_block(self, block):
        """Sauvegarde un nouveau bloc dans la base de données."""
        conn = None
        cur = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            
            # Sauvegarder uniquement les données de base pour la persistance
            cur.execute("""
                INSERT INTO blockchain (index, timestamp, data, previous_hash, hash, nonce)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (block.index, block.timestamp, block.data, block.previous_hash, block.hash, block.nonce))
            
            conn.commit()
            return True

        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde du bloc {block.index} dans la DB: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
        
    def get_last_block(self):
        """Retourne le dernier bloc de la chaîne."""
        # On s'assure que la chaîne est à jour si possible
        self.chain = self.load_chain() 
        return self.chain[-1] if self.chain else None

    def mine_block(self, block, skip_db_check=False):
        """Effectue le Proof of Work (PoW) et ajoute le bloc à la chaîne s'il est valide."""
        target = '0' * self.difficulty
        while block.hash[:self.difficulty] != target:
            block.nonce += 1
            block.hash = block.calculate_hash()

        # Si nous n'ignorons pas la vérification DB, cela signifie qu'il s'agit d'un nouveau vote
        if not skip_db_check:
            if self.save_block(block):
                # On met à jour la chaîne locale après succès
                self.chain.append(block) 
                logger.info(f"Bloc #{block.index} miné et sauvegardé. Hash: {block.hash[:10]}...")
                return True
            else:
                logger.error(f"Échec de la sauvegarde du bloc {block.index} en DB après minage.")
                return False
        
        # Pour le bloc genesis (skip_db_check=True), on ne l'ajoute pas à la chaîne locale ici.
        return True

    def add_new_vote(self, voter_id, candidate_id):
        """Ajoute un nouveau vote à la blockchain."""
        last_block = self.get_last_block()
        if not last_block:
            # Échec critique de l'initialisation du bloc Genesis.
            return None

        # Format des données pour le vote
        vote_data = {
            "voter_id": hashlib.sha256(voter_id.encode()).hexdigest(), # Hashage de l'ID du votant pour l'anonymat
            "candidate_id": candidate_id,
            "timestamp_vote": datetime.now(timezone.utc).isoformat(),
            "type": "VOTE"
        }

        new_block = Block(
            index=last_block.index + 1,
            timestamp=datetime.now(timezone.utc),
            data=json.dumps(vote_data),
            previous_hash=last_block.hash
        )

        # Minage et enregistrement
        if self.mine_block(new_block):
            return new_block
        return None

    def get_vote_counts(self):
        """Calcule les résultats du vote en parcourant la chaîne."""
        # Recharge la chaîne pour s'assurer qu'elle est à jour
        self.chain = self.load_chain() 
        
        vote_counts = {}
        for block in self.chain:
            try:
                data = json.loads(block.data)
                if data.get("type") == "VOTE":
                    candidate_id = data.get("candidate_id")
                    if candidate_id:
                        vote_counts[candidate_id] = vote_counts.get(candidate_id, 0) + 1
            except json.JSONDecodeError:
                logger.warning(f"Bloc {block.index} contient des données JSON invalides.")
        return vote_counts

# L'instance de la blockchain est créée de manière sécurisée après l'initialisation de la DB.
# On crée ici un placeholder qui sera remplacé après init_db()
blockchain = None 
try:
    # On crée une instance pour la première fois.
    blockchain = Blockchain()
except ConnectionError as e:
    logger.error(f"Démarrage SANS persistance DB : {e}")
    # En cas d'échec de la DB au démarrage, on passe en mode non persistant (pour le dev local sans DB)
    class DummyBlockchain:
        def __init__(self): self.chain = []
        def get_last_block(self): return None
        def add_new_vote(self, *args): return None
        def get_vote_counts(self): return {}
        def load_chain(self): return []
        def save_block(self, *args): return False
    blockchain = DummyBlockchain()
except Exception as e:
    logger.error(f"Erreur inattendue lors de l'initialisation de la Blockchain: {e}")
    # Fallback critique
    class DummyBlockchain:
        def __init__(self): self.chain = []
        def get_last_block(self): return None
        def add_new_vote(self, *args): return None
        def get_vote_counts(self): return {}
        def load_chain(self): return []
        def save_block(self, *args): return False
    blockchain = DummyBlockchain()


# --- DÉCORATEURS ET FONCTIONS UTILITAIRES ---

def admin_required(f):
    """Décorateur pour exiger la connexion de l'administrateur."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login', error="Accès administrateur requis."))
        return f(*args, **kwargs)
    return decorated_function

def get_election_status():
    """Récupère le statut de l'élection et la visibilité des résultats depuis la DB."""
    conn = None
    cur = None
    status = 'SETUP'
    results_visible = False
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT key, value FROM configuration WHERE key IN ('election_status', 'results_visible')")
        config = dict(cur.fetchall())
        
        status = config.get('election_status', 'SETUP')
        results_visible = config.get('results_visible', 'False').lower() == 'true'

    except Exception as e:
        logger.warning(f"Impossible de lire le statut de la DB (mode par défaut): {e}")
        # En cas d'échec, utiliser des valeurs par défaut sécuritaires
        status = 'SETUP'
        results_visible = False
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
    return status, results_visible

def get_candidates_for_voting():
    """Récupère la liste des candidats 'accepted' pour le vote."""
    conn = None
    cur = None
    candidates = []
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id_numerique, nom, prenom, slogan, photo_path FROM candidats WHERE statut = 'accepted'")
        rows = cur.fetchall()
        
        for row in rows:
            candidates.append({
                'id_numerique': row[0],
                'nom': row[1],
                'prenom': row[2],
                'slogan': row[3],
                'photo_path': row[4]
            })
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des candidats acceptés: {e}")
    finally:
        if cur: cur.close()
        if conn: conn.close()
        
    return candidates

# --- ROUTES DE L'APPLICATION ---

@app.route('/')
def index():
    """Page d'accueil."""
    return render_template('index.html')

@app.route('/explorer')
def explorer():
    """Affiche la blockchain complète."""
    # Recharge la blockchain pour s'assurer qu'elle est à jour avec la DB
    if not isinstance(blockchain, Blockchain):
        # Si nous sommes en DummyBlockchain, on ne peut pas charger de données.
        return render_template('error_page.html', message="L'explorateur n'est pas disponible : Connexion à la base de données échouée.", title="Erreur DB")

    blockchain.chain = blockchain.load_chain() 
    
    # Prépare les blocs pour l'affichage (conversion en dictionnaire et encodage Base64)
    blocks_for_display = []
    for block in blockchain.chain:
        block_dict = {
            "index": block.index,
            "timestamp": block.timestamp.isoformat(),
            "data": json.loads(block.data), # Les données sont stockées en JSON string
            "previous_hash": block.previous_hash,
            "hash": block.hash,
            "nonce": block.nonce
        }
        blocks_for_display.append(block_dict)

    return render_template('explorer_vote.html', chain=blocks_for_display, chain_length=len(blocks_for_display))

# --- ROUTES D'INSCRIPTION ÉTUDIANT (VOTANT) ---

@app.route('/self_register_student', methods=['GET'])
def self_register_student_get():
    """Affiche la page d'auto-inscription pour les votants."""
    return render_template('self_register_student.html')

@app.route('/api/student/self_register', methods=['POST'])
def self_register_student_post():
    """API pour l'auto-inscription des votants (vérification éligibilité et génération ID)."""
    data = request.get_json()
    nom = data.get('nom')
    prenom = data.get('prenom')
    parcours = data.get('parcours')

    if not all([nom, prenom, parcours]):
        return jsonify({'error': 'Tous les champs sont requis.'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. Vérification de l'unicité (Nom + Prénom + Parcours)
        cur.execute("SELECT id_numerique FROM votants WHERE nom = %s AND prenom = %s AND parcours = %s", (nom, prenom, parcours))
        existing_voter = cur.fetchone()

        if existing_voter:
            return jsonify({
                'error': 'Vous êtes déjà inscrit pour voter.', 
                'id_numerique': existing_voter[0]
            }), 409

        # 2. Génération de l'ID numérique
        id_numerique = str(uuid4())

        # 3. Enregistrement dans la DB
        cur.execute("""
            INSERT INTO votants (id_numerique, nom, prenom, parcours, has_voted)
            VALUES (%s, %s, %s, %s, FALSE)
        """, (id_numerique, nom, prenom, parcours))
        
        conn.commit()

        return jsonify({'success': 'Inscription réussie.', 'id_numerique': id_numerique}), 201

    except ConnectionError:
        return jsonify({'error': 'Service de base de données indisponible. Veuillez réessayer plus tard.'}), 503
    except Exception as e:
        logger.error(f"Erreur lors de l'auto-inscription: {e}")
        if conn: conn.rollback()
        return jsonify({'error': 'Une erreur interne est survenue lors de l\'inscription.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# --- ROUTES D'INSCRIPTION CANDIDAT ---

@app.route('/self_register_candidate', methods=['GET'])
def self_register_candidate_get():
    """Affiche la page d'auto-inscription pour les candidats."""
    return render_template('self_register_candidate.html')

@app.route('/api/candidate/self_register', methods=['POST'])
def self_register_candidate_post():
    """API pour l'auto-inscription des candidats."""
    # Vérification du statut de l'élection
    election_status, _ = get_election_status()
    if election_status != 'SETUP':
        return jsonify({'error': 'L\'inscription des candidats est fermée. Le vote est en cours ou terminé.'}), 403

    # Récupération des données du formulaire (y compris le fichier photo)
    nom = request.form.get('nom')
    prenom = request.form.get('prenom')
    slogan = request.form.get('slogan')
    programme = request.form.get('programme')
    photo = request.files.get('photo')

    if not all([nom, prenom, slogan, programme, photo]):
        return jsonify({'error': 'Tous les champs (y compris la photo) sont requis.'}), 400

    conn = None
    cur = None
    try:
        # 1. Traitement de la photo
        if photo and photo.filename:
            # Sécurisation du nom de fichier
            filename = secure_filename(f"{nom}_{prenom}_{str(uuid4())[:8]}_{photo.filename}")
            filepath = os.path.join(CANDIDATE_UPLOAD_FOLDER, filename)
            photo.save(filepath)
            photo_path = os.path.join('candidates_photos', filename)
        else:
            return jsonify({'error': 'Photo manquante ou invalide.'}), 400

        conn = get_db_connection()
        cur = conn.cursor()

        # 2. Vérification de l'unicité
        cur.execute("SELECT id FROM candidats WHERE nom = %s AND prenom = %s", (nom, prenom))
        if cur.fetchone():
            return jsonify({'error': 'Ce candidat est déjà en attente ou inscrit.'}), 409
        
        # 3. Génération de l'ID numérique
        candidate_id = str(uuid4())

        # 4. Enregistrement dans la DB (statut par défaut: pending)
        cur.execute("""
            INSERT INTO candidats (id_numerique, nom, prenom, slogan, programme, photo_path, statut)
            VALUES (%s, %s, %s, %s, %s, %s, 'pending')
        """, (candidate_id, nom, prenom, slogan, programme, photo_path))
        
        conn.commit()

        return jsonify({'success': 'Candidature soumise avec succès. En attente de validation.', 'candidate_id': candidate_id}), 201

    except ConnectionError:
        return jsonify({'error': 'Service de base de données indisponible. Veuillez réessayer plus tard.'}), 503
    except Exception as e:
        logger.error(f"Erreur lors de l'auto-inscription du candidat: {e}")
        if conn: conn.rollback()
        # En cas d'échec, si le fichier a été enregistré, on pourrait le supprimer ici.
        return jsonify({'error': 'Une erreur interne est survenue lors de la soumission.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# --- ROUTES DE CONNEXION ET VOTE ---

@app.route('/voter_login', methods=['GET'])
def voter_login():
    """Page de connexion pour les votants."""
    return render_template('voter_login.html')

@app.route('/api/voter/login', methods=['POST'])
def api_voter_login():
    """API pour valider l'ID du votant et vérifier l'éligibilité."""
    data = request.get_json()
    id_numerique = data.get('id_numerique')

    if not id_numerique:
        return jsonify({'error': 'ID Numérique requis.'}), 400

    election_status, _ = get_election_status()
    if election_status != 'VOTING':
        return jsonify({'error': 'Le vote n\'est pas en cours.'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 1. Vérification de l'ID et si le votant a déjà voté
        cur.execute("SELECT id_numerique, has_voted FROM votants WHERE id_numerique = %s", (id_numerique,))
        voter_data = cur.fetchone()

        if not voter_data:
            return jsonify({'error': 'ID Numérique invalide.'}), 404
        
        if voter_data[1]: # has_voted est True
            return jsonify({'error': 'Vous avez déjà voté.'}), 403

        # 2. Succès : stocker l'ID dans la session et rediriger vers la page de vote
        session['voter_id'] = id_numerique
        
        return jsonify({'success': 'Connexion réussie.', 'redirect_url': url_for('voting_page')}), 200

    except ConnectionError:
        return jsonify({'error': 'Service de base de données indisponible. Veuillez réessayer plus tard.'}), 503
    except Exception as e:
        logger.error(f"Erreur lors de la connexion du votant: {e}")
        return jsonify({'error': 'Une erreur interne est survenue.'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/voting_page')
def voting_page():
    """Affiche la page du bulletin de vote si le votant est connecté."""
    # S'assurer que le votant est bien connecté
    voter_id = session.get('voter_id')
    if not voter_id:
        return redirect(url_for('voter_login', error="Veuillez vous connecter pour accéder au vote."))

    election_status, _ = get_election_status()
    if election_status != 'VOTING':
        return render_template('error_page.html', message="Le vote n'est pas en cours. Veuillez revenir plus tard.", title="Vote Fermé")
        
    candidates = get_candidates_for_voting()
    
    if not candidates:
        return render_template('error_page.html', message="Aucun candidat validé n'est disponible pour l'instant.", title="Pas de Candidat")

    return render_template('voting_page.html', candidates=candidates, voter_id=voter_id)

@app.route('/api/vote', methods=['POST'])
def api_vote():
    """API pour enregistrer un vote sur la blockchain."""
    data = request.get_json()
    voter_id = data.get('voter_id')
    candidate_id = data.get('candidate_id')

    # 1. Vérifications de base et de la session
    if not (voter_id and candidate_id):
        return jsonify({'error': 'ID du votant ou du candidat manquant.'}), 400

    if session.get('voter_id') != voter_id:
        # Ceci peut arriver si la session expire ou si quelqu'un tente un accès direct
        return jsonify({'error': 'Session de vote invalide ou expirée.'}), 403

    election_status, _ = get_election_status()
    if election_status != 'VOTING':
        return jsonify({'error': 'Le vote n\'est pas en cours.'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # 2. Vérification DB : le votant a-t-il déjà voté ?
        cur.execute("SELECT has_voted FROM votants WHERE id_numerique = %s", (voter_id,))
        voter_data = cur.fetchone()

        if not voter_data:
            return jsonify({'error': 'ID votant introuvable.'}), 404
            
        if voter_data[0]:
            return jsonify({'error': 'Vous avez déjà voté. Un seul vote est autorisé.'}), 403

        # 3. Enregistrement du vote sur la Blockchain
        new_block = blockchain.add_new_vote(voter_id, candidate_id)

        if not new_block:
            # Échec du minage ou de la sauvegarde DB du bloc
            raise Exception("Échec de l'enregistrement du vote sur la Blockchain/DB.")

        # 4. Mise à jour du statut du votant dans la DB
        cur.execute("UPDATE votants SET has_voted = TRUE WHERE id_numerique = %s", (voter_id,))
        
        conn.commit()

        # 5. Nettoyage de la session du votant
        session.pop('voter_id', None) 
        
        return jsonify({
            'success': 'Vote enregistré.', 
            'block_index': new_block.index, 
            'block_hash': new_block.hash
        }), 200

    except ConnectionError:
        return jsonify({'error': 'Service de base de données indisponible. Veuillez réessayer plus tard.'}), 503
    except Exception as e:
        logger.error(f"Erreur critique lors de l'enregistrement du vote: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f'Erreur interne lors du vote: {e}'}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

# --- ROUTES RÉSULTATS ---

@app.route('/results')
def results():
    """Affiche les résultats du vote en temps réel."""
    
    # 1. Récupérer le statut
    election_status, results_visible = get_election_status()
    
    # 2. Vérifier la visibilité
    if not results_visible:
        status_message = "Les résultats sont actuellement cachés par l'administration."
        # Tente de charger la chaîne pour avoir le nombre total de votes même si les résultats sont cachés
        total_votes = len(blockchain.load_chain()) - 1 if isinstance(blockchain, Blockchain) else 0 
        return render_template('results.html', 
                               election_status=election_status, 
                               status_message=status_message, 
                               total_votes=total_votes, 
                               results=[])

    # 3. Si visible, calculer les résultats
    try:
        # L'instance de blockchain est supposée être la vraie Blockchain ici
        if not isinstance(blockchain, Blockchain):
            raise Exception("Blockchain non disponible (DB down).")

        vote_counts = blockchain.get_vote_counts()
        candidates = get_candidates_for_voting()
        
        total_votes = sum(vote_counts.values())
        
        detailed_results = []
        for candidate in candidates:
            candidate_id = candidate['id_numerique']
            votes = vote_counts.get(candidate_id, 0)
            percentage = (votes / total_votes * 100) if total_votes > 0 else 0
            
            detailed_results.append({
                'id_numerique': candidate_id,
                'nom_complet': f"{candidate['prenom']} {candidate['nom']}",
                'photo_path': candidate['photo_path'],
                'votes': votes,
                'percentage': f"{percentage:.2f}"
            })

        # Trier par nombre de votes (décroissant)
        detailed_results.sort(key=lambda x: x['votes'], reverse=True)
        
        if election_status == 'VOTING':
            status_message = "Le vote est en cours. Résultats en temps réel."
        elif election_status == 'CLOSED':
            status_message = "Le vote est terminé. Résultats finaux."
        else: # SETUP ou autre
            status_message = "Aucun vote n'a encore été enregistré sur la Blockchain."
            
        return render_template('results.html', 
                               election_status=election_status, 
                               status_message=status_message, 
                               total_votes=total_votes,
                               results=detailed_results)

    except Exception as e:
        logger.error(f"Erreur lors du calcul des résultats: {e}")
        status_message = "Erreur critique lors du calcul des résultats."
        return render_template('results.html', 
                               election_status="ERROR", 
                               status_message=status_message, 
                               total_votes=0,
                               results=[])


# --- ROUTES ADMINISTRATEUR ---

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Page de connexion administrateur."""
    error = request.args.get('error')
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        stored_hash = ADMIN_USERS.get(username)

        if stored_hash and check_password_hash(stored_hash, password):
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Nom d'utilisateur ou mot de passe invalide."
            
    return render_template('admin_login.html', error=error)

@app.route('/admin_logout')
@admin_required
def admin_logout():
    """Déconnexion de l'administrateur."""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login', error="Déconnexion réussie."))

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    """Tableau de bord administrateur."""
    conn = None
    cur = None
    candidates = []
    voters = []
    
    # 1. Récupérer les candidats (tous statuts)
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id_numerique, nom, prenom, slogan, photo_path, statut, created_at FROM candidats ORDER BY created_at DESC")
        candidates_rows = cur.fetchall()
        for row in candidates_rows:
            # id_numerique, nom, prenom, slogan, photo_path, statut, created_at
            candidates.append({
                'id_numerique': row[0], 'nom': row[1], 'prenom': row[2], 'slogan': row[3],
                'photo_path': row[4], 'statut': row[5], 'created_at': row[6]
            })

        # 2. Récupérer les votants
        cur.execute("SELECT id_numerique, nom, prenom, parcours, has_voted, created_at FROM votants ORDER BY created_at DESC")
        voters_rows = cur.fetchall()
        for row in voters_rows:
            # id_numerique, nom, prenom, parcours, has_voted, created_at
            voters.append({
                'id_numerique': row[0], 'nom': row[1], 'prenom': row[2], 'parcours': row[3],
                'has_voted': row[4], 'created_at': row[5]
            })
            
    except Exception as e:
        logger.error(f"Erreur lors du chargement du dashboard: {e}")
        # Gérer l'erreur mais laisser le dashboard s'afficher avec les données vides
    finally:
        if cur: cur.close()
        if conn: conn.close()

    # 3. Récupérer le statut
    election_status, results_visible = get_election_status()
    
    # 4. Compter les votes (pour info rapide)
    vote_counts = blockchain.get_vote_counts()
    total_votes = sum(vote_counts.values())

    return render_template('admin_dashboard.html', 
                           admin_username=session.get('admin_username'),
                           candidates=candidates,
                           voters=voters,
                           election_status=election_status,
                           results_visible=results_visible,
                           total_votes_recorded=total_votes,
                           message=request.args.get('message'),
                           error=request.args.get('error'))

@app.route('/api/admin/candidate_action/<candidate_id>', methods=['POST'])
@admin_required
def api_admin_candidate_action(candidate_id):
    """API pour valider ou rejeter un candidat."""
    data = request.get_json()
    action = data.get('action') # 'accept', 'reject', 'delete'

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if action in ['accept', 'reject']:
            new_status = 'accepted' if action == 'accept' else 'rejected'
            cur.execute("UPDATE candidats SET statut = %s WHERE id_numerique = %s", (new_status, candidate_id))
            conn.commit()
            return jsonify({'success': f"Statut du candidat {candidate_id} mis à jour : {new_status}."}), 200
            
        elif action == 'delete':
            # 1. Récupérer le chemin de la photo
            cur.execute("SELECT photo_path FROM candidats WHERE id_numerique = %s", (candidate_id,))
            photo_path_db = cur.fetchone()
            
            # 2. Supprimer l'entrée DB
            cur.execute("DELETE FROM candidats WHERE id_numerique = %s", (candidate_id,))
            conn.commit()
            
            # 3. Supprimer le fichier photo
            if photo_path_db and photo_path_db[0]:
                full_path = os.path.join(os.getcwd(), 'static', photo_path_db[0])
                if os.path.exists(full_path):
                    os.remove(full_path)
                    logger.info(f"Photo supprimée: {full_path}")
            
            return jsonify({'success': f"Candidat {candidate_id} et sa photo ont été supprimés."}), 200

        else:
            return jsonify({'error': 'Action invalide.'}), 400

    except Exception as e:
        logger.error(f"Erreur lors de l'action sur le candidat {candidate_id}: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur de traitement: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/admin/election_status', methods=['POST'])
@admin_required
def api_admin_election_status():
    """API pour changer le statut de l'élection."""
    data = request.get_json()
    new_status = data.get('status') # 'SETUP', 'VOTING', 'CLOSED'
    
    if new_status not in ['SETUP', 'VOTING', 'CLOSED']:
        return jsonify({'error': 'Statut invalide.'}), 400

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Mise à jour dans la table configuration
        cur.execute("""
            INSERT INTO configuration (key, value) VALUES ('election_status', %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """, (new_status,))
        
        conn.commit()
        return jsonify({'success': f"Statut de l'élection mis à jour à : {new_status}."}), 200

    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour du statut: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur de traitement: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/admin/results_visibility', methods=['POST'])
@admin_required
def api_admin_results_visibility():
    """API pour basculer la visibilité des résultats."""
    data = request.get_json()
    is_visible = data.get('visible', False) # True/False

    new_visibility = 'True' if is_visible else 'False'

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Mise à jour dans la table configuration
        cur.execute("""
            INSERT INTO configuration (key, value) VALUES ('results_visible', %s)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
        """, (new_visibility,))
        
        conn.commit()
        
        message = "Résultats rendus visibles." if is_visible else "Résultats cachés."
        return jsonify({'success': message}), 200

    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de la visibilité: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur de traitement: {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()

@app.route('/api/admin/reset_all', methods=['POST'])
@admin_required
def api_admin_reset_all():
    """API pour réinitialiser complètement le système de vote (tables Votants, Candidats, Blockchain)."""
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Suppression des données
        cur.execute("TRUNCATE TABLE votants RESTART IDENTITY;")
        cur.execute("TRUNCATE TABLE candidats RESTART IDENTITY;")
        cur.execute("TRUNCATE TABLE blockchain RESTART IDENTITY;")
        
        # 2. Réinitialisation du statut
        cur.execute("UPDATE configuration SET value = 'SETUP' WHERE key = 'election_status'")
        cur.execute("UPDATE configuration SET value = 'False' WHERE key = 'results_visible'")
        
        conn.commit()
        
        # 3. Supprimer les photos (Nettoyage du répertoire)
        for filename in os.listdir(CANDIDATE_UPLOAD_FOLDER):
            file_path = os.path.join(CANDIDATE_UPLOAD_FOLDER, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            except Exception as e:
                logger.error(f"Erreur lors de la suppression de la photo {filename}: {e}")
        
        # 4. Recréer le bloc genesis (via init_db, qui est maintenant plus robuste)
        init_db()
        
        # 5. Déconnexion de l'administrateur
        session.pop('admin_logged_in', None)
        session.pop('admin_username', None)
        
        return jsonify({'success': "Système de vote entièrement réinitialisé. Les données Votants, Candidats, Blockchain et Éligibilité ont été effacées."}), 200
    except Exception as e:
        logger.error(f"Erreur de réinitialisation: {e}")
        if conn: conn.rollback()
        return jsonify({'error': f"Erreur critique lors de la réinitialisation : {e}"}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()


# --- HOOK D'APPLICATION ---
# S'assure que la base de données est initialisée au lancement de l'application
with app.app_context():
    try:
        init_db()
        # On peut charger la blockchain maintenant que les tables et le bloc genesis existent
        blockchain = Blockchain()
        if not isinstance(blockchain, Blockchain) or not blockchain.load_chain():
            logger.error("Démarrage critique: La blockchain n'a pas pu être initialisée/chargée après init_db.")
        else:
            logger.info(f"DB initialisée et Blockchain chargée (taille: {len(blockchain.load_chain())} blocs).")
    except Exception as e:
        logger.error(f"Erreur CRITIQUE au démarrage: {e}")
        # En production, cela peut entraîner l'échec de l'application si la DB est requise.
        
        
if __name__ == '__main__':
    # Ceci est utilisé seulement pour le développement local.
    # En production (Render), le 'Start Command' appelle gunicorn directement.
    print("ATTENTION: Pour la production, utilisez GUNICORN (Start Command: gunicorn serveur_vote:app).")
    # Pour le débogage local avec un serveur Flask de développement:
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000), debug=True)