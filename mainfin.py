import base64
import os
import binascii
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Initialize the App
app = FastAPI(
    title="6-Layer Crypto API",
    description="API exposing Symmetric Encryption and Asymmetric Authentication tools.",
    version="1.1.0"
)

# Enable CORS for Cross-Device Access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins; restrict this in production!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# PART 1: CORE LOGIC 
# ==========================================

def generate_fernet_key_from_password(password: str, salt: bytes) -> bytes:
    # Explicitly enforce UTF-8 to prevent OS-level encoding differences
    password_bytes = password.encode("utf-8")
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

    def generate_key_pair(self):
        # Deprecated backend removed
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        return private_key, public_key

    def sign_message(self, private_key, message: str) -> bytes:
        message_bytes = message.encode("utf-8")
        signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, public_key, message: str, signature: bytes) -> bool:
        message_bytes = message.encode("utf-8")
        try:
            public_key.verify(signature, message_bytes, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def serialize_private_key(private_key, password: str) -> bytes:
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8"))
        )

    @staticmethod
    def serialize_public_key(public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_private_key(pem_data: bytes, password: str):
        return serialization.load_pem_private_key(pem_data, password=password.encode("utf-8"))

    @staticmethod
    def deserialize_public_key(pem_data: bytes):
        return serialization.load_pem_public_key(pem_data)

auth_tool = NodeAuth()

# ==========================================
# PART 2: API DATA MODELS
# ==========================================

class EncryptRequest(BaseModel):
    key: str
    data: str

class DecryptRequest(BaseModel):
    key: str
    encrypted_data: str

class KeyGenPasswordRequest(BaseModel):
    password: str
    salt_b64: Optional[str] = None

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

@app.get("/encryption/generate-key")
def generate_key():
    key = Fernet.generate_key()
    return {"key": key.decode("utf-8")}

@app.post("/encryption/derive-key")
def derive_key(req: KeyGenPasswordRequest):
    if req.salt_b64:
        try:
            salt = base64.b64decode(req.salt_b64)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="Invalid base64 salt provided.")
    else:
        salt = os.urandom(16)

    key = generate_fernet_key_from_password(req.password, salt)
    
    return {
        "key": key.decode("utf-8"),
        "salt": base64.b64encode(salt).decode("utf-8")
    }

@app.post("/encryption/encrypt")
def encrypt_data_endpoint(req: EncryptRequest):
    try:
        f = Fernet(req.key.encode("utf-8"))
        token = f.encrypt(req.data.encode("utf-8"))
        return {"encrypted_data": token.decode("utf-8")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Encryption Error: {str(e)}")

@app.post("/encryption/decrypt")
def decrypt_data_endpoint(req: DecryptRequest):
    try:
        f = Fernet(req.key.encode("utf-8"))
        decrypted_bytes = f.decrypt(req.encrypted_data.encode("utf-8"))
        return {"decrypted_data": decrypted_bytes.decode("utf-8")}
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid Key or Data.")

@app.post("/auth/generate-keys")
def generate_auth_keys(req: GenerateKeysRequest):
    private_key, public_key = auth_tool.generate_key_pair()
    
    priv_pem = NodeAuth.serialize_private_key(private_key, req.password)
    pub_pem = NodeAuth.serialize_public_key(public_key)
    
    return {
        "private_key_pem": priv_pem.decode("utf-8"),
        "public_key_pem": pub_pem.decode("utf-8")
    }

@app.post("/auth/sign")
def sign_message_endpoint(req: SignRequest):
    try:
        private_key = NodeAuth.deserialize_private_key(req.private_key_pem.encode("utf-8"), req.private_key_password)
        signature = auth_tool.sign_message(private_key, req.message)
        return {"signature_hex": signature.hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Signing Error: {str(e)}")

@app.post("/auth/verify")
def verify_signature_endpoint(req: VerifyRequest):
    try:
        public_key = NodeAuth.deserialize_public_key(req.public_key_pem.encode("utf-8"))
        signature_bytes = bytes.fromhex(req.signature_hex)
        is_valid = auth_tool.verify_signature(public_key, req.message, signature_bytes)
        return {"is_valid": is_valid}
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Hex Signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification Error: {str(e)}")