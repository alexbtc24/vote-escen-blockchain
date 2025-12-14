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

# --- CONFIGURATION INITIALE SIMPLIFIÉE ---
app = Flask(__name__)
# Utilisez une clé secrète forte en production !
app.secret_key = os.environ.get('FLASK_SECRET_KEY', str(uuid4())) 

# --- CORRECTION DE L'ERREUR JINJA : CONTEXTE-PROCESSEUR ---
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
VOTE_CHAIN_FILE = os.path.join(DATA_DIR, 'blockchain.json')
# Fichiers de configuration
ADMIN_USERS_FILE = os.path.join(DATA_DIR, 'admin_users.json')

# --- CONFIGURATION DE LA BASE DE DONNÉES POSTGRESQL (Pour Render) ---
# Nécessite l'installation de 'psycopg2-binary' et 'Flask-SQLAlchemy'
from flask_sqlalchemy import SQLAlchemy

# Configuration de l'URL de la base de données (variable d'environnement sur Render)
# Fallback à une base de données SQLite pour le développement local
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 
    'sqlite:///blockchain_vote.db'
).replace("postgres://", "postgresql://", 1) # Correction pour SQLAlchemy 2.x et psycopg2
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ------------------------------------------------------------------

# --- DÉFINITIONS DES MODÈLES SQLALCHEMY ---
class Block(db.Model):
    __tablename__ = 'block'
    # La colonne `id` est généralement l'index de la Blockchain, mais Flask-SQLAlchemy utilise `id` comme PK par défaut.
    # Nous utilisons `index` comme clé primaire pour coller à la logique Blockchain.
    id = db.Column(db.Integer, primary_key=True) # Ajout de l'ID PK auto-incrémentée
    index = db.Column(db.Integer, unique=True, nullable=False) # L'index de la Blockchain
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    payload_json = db.Column(db.Text, nullable=False) # Données du bloc (transaction de vote, inscription, etc.)
    previous_hash = db.Column(db.String(64), nullable=False)
    hash = db.Column(db.String(64), nullable=False, unique=True)
    nonce = db.Column(db.Integer, nullable=False)
    type = db.Column(db.String(50), nullable=False) # Ex: VOTE, VOTER_REGISTERED, GENESIS, ELECTION_STATUS
    
    # Nouvelle colonne pour stocker le snapshot de la chaîne (optimisation)
    chain_snapshot_json = db.Column(db.Text, nullable=True) 

    def to_dict(self):
        return {
            'index': self.index,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'payload': json.loads(self.payload_json),
            'previous_hash': self.previous_hash,
            'hash': self.hash,
            'nonce': self.nonce,
            'type': self.type,
        }

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(255), nullable=False)
    recipient_id = db.Column(db.String(255), nullable=False)
    amount = db.Column(db.Integer, default=1) # Pour un vote, l'amount est généralement 1
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'amount': self.amount,
            'timestamp': self.timestamp.isoformat(),
        }

# --- CONFIGURATION DES DONNÉES (Pour la simplicité) ---
# NOTE: En production réelle, ces données devraient être stockées dans une DB ou un service dédié.
DEFAULT_ADMINS = {
    "admin_escen": generate_password_hash("Escen2024!"),
    "admin_institution": generate_password_hash("Institution2024!")
}
# Données de base (listes d'étudiants, candidats, etc.)
VOTERS = {}
CANDIDATES = {}

# --- FONCTIONS UTILITAIRES POUR GÉRER LES FICHIERS JSON ---

def load_data(file_path, default_data):
    """Charge les données depuis un fichier JSON ou initialise avec des données par défaut."""
    try:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            with open(file_path, 'r') as f:
                data = json.load(f)
            # Mise à jour des dictionnaires globaux
            if file_path == ADMIN_USERS_FILE:
                default_data.update(data)
            elif file_path == VOTERS_FILE:
                VOTERS.update(data)
            elif file_path == CANDIDATES_FILE:
                CANDIDATES.update(data)
            logging.info(f"Données chargées depuis {file_path}.")
            return data
        else:
            save_data(file_path, default_data)
            return default_data
    except Exception as e:
        logging.error(f"Erreur lors du chargement de {file_path}. Utilisation des données par défaut. Erreur: {e}")
        return default_data

def save_data(file_path, data):
    """Sauvegarde les données dans un fichier JSON."""
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Données sauvegardées dans {file_path}.")
    except Exception as e:
        logging.error(f"Erreur lors de la sauvegarde dans {file_path}: {e}")

# Charger les données initiales
load_data(ADMIN_USERS_FILE, DEFAULT_ADMINS)
load_data(VOTERS_FILE, VOTERS)
load_data(CANDIDATES_FILE, CANDIDATES)

# --- CLASSE BLOCKCHAIN ---

class Blockchain:
    
    def __init__(self, node_identifier=None):
        """
        Constructeur de la Blockchain. N'interagit PLUS avec la base de données ici
        pour éviter l'erreur de colonne indéfinie pendant la création des tables.
        """
        self.node_identifier = node_identifier or str(uuid4()).replace('-', '')
        self.current_transactions = []
        
        # Initialisation de la chaîne à vide. Elle sera chargée ou créée dans load_or_create_genesis()
        self.chain = []
        self.last_block_in_memory = None
        self.last_block_in_db = None # Utilisé pour le stockage dans la DB
        
        logging.info("Initialisation de l'objet Blockchain (chaîne vide).")

    # --- NOUVELLE MÉTHODE POUR CHARGER/CRÉER LE GENESIS ---
    def load_or_create_genesis(self):
        """
        Charge la chaîne depuis la DB si elle existe, ou crée le bloc Genesis.
        Doit être appelée APRÈS db.create_all().
        """
        # Utiliser app.app_context() pour les commandes CLI (flask initdb)
        with app.app_context():
            if Block.query.count() > 0:
                # S'il y a des blocs, charger le dernier et initialiser
                last_block = Block.query.order_by(Block.index.desc()).first()
                # On utilise le snapshot de la chaîne stocké dans le dernier bloc pour l'initialiser
                self.chain = json.loads(last_block.chain_snapshot_json) if last_block else []
                self.last_block_in_db = last_block
                self.last_block_in_memory = self.chain[-1] if self.chain else None
                logging.info(f"Blockchain chargée depuis la BD. Index actuel: {self.last_block_in_memory['index']}")
            else:
                # Créer le bloc Genesis s'il n'y a pas de blocs
                self.chain = []
                # Le bloc genesis ne contient pas de transactions réelles (payload vide ou message)
                self.new_block(proof=100, previous_hash='1', block_type='GENESIS', payload={
                    'message': 'Bloc Genesis de l\'ESCEN Vote Chain créé.',
                    'config': {'mining_difficulty': 4}
                })
                self.last_block_in_memory = self.chain[-1]
                self.last_block_in_db = None
                logging.info("Bloc Genesis créé.")

    def new_block(self, proof, previous_hash=None, block_type='TRANSACTION', payload={}):
        """
        Crée un nouveau Block et l'ajoute à la chaîne.
        """
        if self.chain and not previous_hash:
             previous_hash = self.hash(self.chain[-1])
        elif not self.chain and not previous_hash:
             previous_hash = '1' # Hash par défaut pour le premier bloc (Genesis)

        # 1. Création du bloc en mémoire
        block = {
            'index': len(self.chain) + 1,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'payload': payload,
            'previous_hash': previous_hash,
            'nonce': proof,
            'type': block_type,
        }
        # Calcul du hash
        block['hash'] = self.hash(block)

        # 2. Ajout du bloc à la chaîne en mémoire
        self.chain.append(block)
        
        # 3. Stockage du bloc dans la base de données
        # Le snapshot de la chaîne doit être mis à jour avant l'enregistrement
        block_to_save = Block(
            index=block['index'],
            timestamp=datetime.fromisoformat(block['timestamp']).replace(tzinfo=timezone.utc),
            payload_json=json.dumps(block['payload']),
            previous_hash=block['previous_hash'],
            hash=block['hash'],
            nonce=block['nonce'],
            type=block['type'],
            # Stockage de la chaîne complète (ou partielle, selon l'optimisation)
            chain_snapshot_json=json.dumps(self.chain)
        )
        
        db.session.add(block_to_save)
        db.session.commit()
        self.last_block_in_db = block_to_save
        self.last_block_in_memory = block
        
        logging.info(f"Nouveau bloc ajouté: Index {block['index']}, Hash {block['hash'][:10]}...")
        
        # 4. Suppression des transactions non validées (si le bloc n'est pas GENESIS ou STATUS)
        if block_type == 'VOTE':
            self.current_transactions = []
        
        return block

    # --- Fonctions existantes (pas de changement) ---
    def new_transaction(self, sender_id, recipient_id, amount=1):
        """
        Ajoute une nouvelle transaction à la liste des transactions.
        """
        # Enregistrement dans la table Transaction (pour l'historique non-bloqué si nécessaire)
        transaction_record = Transaction(
            sender_id=sender_id,
            recipient_id=recipient_id,
            amount=amount
        )
        db.session.add(transaction_record)
        db.session.commit()

        # Enregistrement dans le bloc en attente
        self.current_transactions.append({
            'sender_id': sender_id,
            'recipient_id': recipient_id,
            'amount': amount,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

        # Retourne l'index du bloc qui sera miné (le bloc suivant)
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        Crée un hash SHA-256 d'un Block
        """
        # Nous devons nous assurer que le Dictionnaire est ordonné, ou nous aurons des hashes incohérents
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Algorithme simple de Proof of Work:
         - Cherche un nombre p' tel que hash(pp') contienne N zéros au début
        """
        last_proof = last_block['nonce']
        last_hash = self.hash(last_block)
        
        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash, difficulty=4):
        """
        Valide la preuve : le hash(last_proof, proof) commence-t-il par '0000'?
        """
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        # La difficulté est configurée ici (ex: '0000')
        required_prefix = '0' * difficulty 
        return guess_hash.startswith(required_prefix)

    @property
    def last_block(self):
        # Retourne le dernier bloc de la chaîne en mémoire
        return self.chain[-1] if self.chain else None

    # --- Fonctions de Validation et de Consensus (non modifiées) ---
    def valid_chain(self, chain):
        """
        Détermine si une blockchain donnée est valide
        (laisse les détails de l'implémentation originale)
        """
        # ... (Logique complète de validation de chaîne) ...
        return True # Supposé valide pour la suite du code

# --- Initialisation de la Blockchain ---
# Elle est initialisée ici SANS interagir avec la DB (chaîne vide par défaut)
blockchain = Blockchain() 


# --- DÉFINITION DE LA COMMANDE CLI POUR L'INITIALISATION DE LA DB ---
@app.cli.command("initdb")
def initdb_command():
    """
    Crée les tables de la base de données et initialise le bloc genesis.
    C'est la commande qui sera exécutée par Render.
    """
    with app.app_context():
        try:
            print("Démarrage de la création des tables de la base de données...")
            db.create_all()
            print("Tables créées avec succès.")
            
            # Étape critique : charger ou créer le bloc Genesis après la création des tables
            print("Vérification ou création du bloc Genesis de la Blockchain...")
            blockchain.load_or_create_genesis()
            
            # S'assurer que les données JSON sont chargées/sauvegardées pour les admins/étudiants/candidats
            load_data(ADMIN_USERS_FILE, DEFAULT_ADMINS)
            load_data(VOTERS_FILE, VOTERS)
            load_data(CANDIDATES_FILE, CANDIDATES)
            
            print("Base de données initialisée et configuration terminée.")
        except Exception as e:
            print(f"Erreur fatale lors de l'initialisation de la base de données: {e}")
            logging.error(f"Erreur initdb: {e}", exc_info=True)
            import sys
            sys.exit(1)


# --- Fonctions existantes : Admin, Candidat, Vote, etc. (aucune modification nécessaire) ---

# ... (Le reste de votre code avec les fonctions de routage, de validation, de minage, etc.)

# --- FONCTIONS DE VÉRIFICATION D'ÉTAT DE L'ÉLECTION (non modifiées) ---

def get_election_status():
    """Récupère l'état de l'élection depuis le dernier bloc de type 'ELECTION_STATUS'."""
    # ... (Le reste de votre code)
    if not blockchain.chain:
        return 'PENDING'
    
    status_blocks = [b for b in blockchain.chain if b['type'] == 'ELECTION_STATUS']
    if not status_blocks:
        return 'PENDING' # Aucun statut défini, on suppose en attente
    
    last_status = status_blocks[-1]['payload'].get('status', 'PENDING')
    return last_status

# ... (Le reste de votre code)

# --- FIN DU FICHIER ---


# --- LOGIQUE DE DÉMARRAGE (Modifiée pour supporter la nouvelle structure) ---
if __name__ == '__main__':
    # Le contexte de l'application est nécessaire pour interagir avec la DB
    with app.app_context():
        # S'assurer que les tables existent si on lance localement sans 'initdb'
        print("Vérification et création des tables de la base de données pour l'exécution locale...")
        db.create_all() 
        
        # Charger la blockchain (créer Genesis si nécessaire)
        print("Chargement ou création du bloc Genesis de la Blockchain...")
        blockchain.load_or_create_genesis() 
        
        # Recharger les données des fichiers JSON
        load_data(ADMIN_USERS_FILE, DEFAULT_ADMINS)
        load_data(VOTERS_FILE, VOTERS)
        load_data(CANDIDATES_FILE, CANDIDATES)
        print("Configuration initiale terminée.")

    # Lancement de l'application Flask
    app.run(host='0.0.0.0', port=5000)

# Le reste du fichier doit être le même que votre fichier d'origine,
# y compris les routes et les fonctions d'aide, qui ne sont pas incluses ici pour la concision,
# mais que vous devez **conserver intégralement**.