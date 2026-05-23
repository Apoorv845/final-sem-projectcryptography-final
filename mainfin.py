import base64
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Initialize the App
app = FastAPI(
    title="6-Layer Crypto API",
    description="API exposing Symmetric Encryption and Asymmetric Authentication tools.",
    version="1.0.0"
)

# ==========================================
# PART 1: CORE LOGIC 
# ==========================================

def generate_fernet_key_from_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

class NodeAuth:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.key_backend = default_backend()

    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, self.key_backend)
        public_key = private_key.public_key()
        return private_key, public_key

    # REMOVED _hash_message: cryptography handles the hashing internally

    def sign_message(self, private_key, message: str) -> bytes:
        # Pass the raw message bytes directly. ec.ECDSA(hashes.SHA256()) tells it to hash it for you.
        message_bytes = message.encode('utf-8')
        signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, public_key, message: str, signature: bytes) -> bool:
        # Pass the raw message bytes directly to match the signing process.
        message_bytes = message.encode('utf-8')
        try:
            public_key.verify(signature, message_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    # Serialization Helpers
    @staticmethod
    def serialize_private_key(private_key, password: str) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
        )

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_private_key(pem_data: bytes, password: str):
        return serialization.load_pem_private_key(pem_data, password=password.encode('utf-8'), backend=default_backend())

    @staticmethod
    def deserialize_public_key(pem_data: bytes):
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

# Initialize Auth Tool globally
auth_tool = NodeAuth()

# ==========================================
# PART 2: API DATA MODELS (Pydantic)
# ==========================================

class EncryptRequest(BaseModel):
    key: str
    data: str

class DecryptRequest(BaseModel):
    key: str
    encrypted_data: str

class KeyGenPasswordRequest(BaseModel):
    password: str

# Added this model so password isn't passed in the URL query string
class GenerateKeysRequest(BaseModel):
    password: str

class SignRequest(BaseModel):
    private_key_pem: str
    private_key_password: str
    message: str

class VerifyRequest(BaseModel):
    public_key_pem: str
    message: str
    signature_hex: str

# ==========================================
# PART 3: API ENDPOINTS
# ==========================================

@app.get("/")
def home():
    return {"message": "Crypto API is running. Go to /docs for the UI."}

# --- Encryption Endpoints ---

@app.get("/encryption/generate-key")
def generate_key():
    """Generates a random Fernet key."""
    key = Fernet.generate_key()
    return {"key": key.decode()}

@app.post("/encryption/derive-key")
def derive_key(req: KeyGenPasswordRequest):
    """Derives a Fernet key from a password using a random salt."""
    salt = os.urandom(16)
    key = generate_fernet_key_from_password(req.password, salt)
    return {
        "key": key.decode(),
        "salt": base64.b64encode(salt).decode()
    }

@app.post("/encryption/encrypt")
def encrypt_data_endpoint(req: EncryptRequest):
    """Encrypts a string using a provided Fernet key."""
    try:
        f = Fernet(req.key.encode())
        token = f.encrypt(req.data.encode())
        return {"encrypted_data": token.decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Encryption Error: {str(e)}")

@app.post("/encryption/decrypt")
def decrypt_data_endpoint(req: DecryptRequest):
    """Decrypts data using a provided Fernet key."""
    try:
        f = Fernet(req.key.encode())
        decrypted_bytes = f.decrypt(req.encrypted_data.encode())
        return {"decrypted_data": decrypted_bytes.decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid Key or Data.")

# --- Authentication Endpoints ---

@app.post("/auth/generate-keys")
def generate_auth_keys(req: GenerateKeysRequest):
    """Generates ECC Private/Public keys. Private key is encrypted with the provided password."""
    private_key, public_key = auth_tool.generate_key_pair()
    
    # Serialize to PEM format so we can send them as strings
    priv_pem = NodeAuth.serialize_private_key(private_key, req.password)
    pub_pem = NodeAuth.serialize_public_key(public_key)
    
    return {
        "private_key_pem": priv_pem.decode(),
        "public_key_pem": pub_pem.decode()
    }

@app.post("/auth/sign")
def sign_message_endpoint(req: SignRequest):
    """Signs a message using an encrypted private key PEM."""
    try:
        # Load the private key
        private_key = NodeAuth.deserialize_private_key(req.private_key_pem.encode(), req.private_key_password)
        # Sign
        signature = auth_tool.sign_message(private_key, req.message)
        return {"signature_hex": signature.hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signing Error: {str(e)}")

@app.post("/auth/verify")
def verify_signature_endpoint(req: VerifyRequest):
    """Verifies a signature using the public key PEM."""
    try:
        # Load public key
        public_key = NodeAuth.deserialize_public_key(req.public_key_pem.encode())
        # Convert hex signature back to bytes
        signature_bytes = bytes.fromhex(req.signature_hex)
        # Verify
        is_valid = auth_tool.verify_signature(public_key, req.message, signature_bytes)
        return {"is_valid": is_valid}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Hex Signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification Error: {str(e)}")