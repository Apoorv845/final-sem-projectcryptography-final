import base64
import os
import io
import uvicorn
from typing import Union
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Initialize the App
app = FastAPI(title="6-Layer Crypto API", version="1.4.0")

# Enable CORS for cross-device API access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (good for local network testing)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# ==========================================
# CORE LOGIC
# ==========================================

class NodeAuth:
    def __init__(self):
        self.curve = ec.SECP256R1()
        self.key_backend = default_backend()

    def generate_key_pair(self):
        private_key = ec.generate_private_key(self.curve, self.key_backend)
        return private_key, private_key.public_key()

    def sign_data(self, private_key, data: Union[str, bytes]) -> bytes:
        content = data.encode() if isinstance(data, str) else data
        return private_key.sign(content, ec.ECDSA(hashes.SHA256()))

    def verify_signature(self, public_key, data: Union[str, bytes], signature: bytes) -> bool:
        content = data.encode() if isinstance(data, str) else data
        try:
            public_key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

auth_tool = NodeAuth()

# ==========================================
# UI HTML CONTENT (Upgraded UX)
# ==========================================

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Crypto Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Custom scrollbar for textareas handling large data */
        textarea::-webkit-scrollbar { width: 8px; }
        textarea::-webkit-scrollbar-track { background: #1e293b; border-radius: 4px; }
        textarea::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        textarea::-webkit-scrollbar-thumb:hover { background: #64748b; }
    </style>
</head>
<body class="bg-slate-950 text-slate-200 min-h-screen p-6 md:p-12 font-sans selection:bg-indigo-500 selection:text-white">

    <div id="toast-container" class="fixed top-5 right-5 z-50 flex flex-col gap-2"></div>

    <div class="max-w-5xl mx-auto space-y-8">
        <header class="border-b border-slate-800 pb-6 mb-8">
            <h1 class="text-4xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-indigo-400 to-cyan-400">
                Advanced Crypto Studio
            </h1>
            <p class="text-slate-400 mt-2">Enterprise-grade symmetric encryption and ECDSA file authentication.</p>
        </header>
        
        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-cyan-400">1. Symmetric Encryption (Fernet)</h2>
                <button onclick="genSymKey()" class="text-sm bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 px-4 py-2 rounded-lg transition">
                    + Generate New Key
                </button>
            </div>
            <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="space-y-4">
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Secret Key</label>
                        <div class="flex gap-2">
                            <input id="symKey" type="text" placeholder="Paste or generate key..." class="flex-1 p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none text-sm font-mono">
                            <button onclick="copyToClipboard('symKey')" class="px-4 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition" title="Copy Key">📋</button>
                        </div>
                    </div>
                    <div>
                        <label class="block text-xs font-medium text-slate-400 mb-1">Input Data (Text or Cipher)</label>
                        <textarea id="symData" placeholder="Enter large amounts of text here..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 outline-none h-32 text-sm resize-y"></textarea>
                    </div>
                    <div class="flex gap-3">
                        <button onclick="doEncrypt()" class="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-cyan-900/20">Encrypt Data</button>
                        <button onclick="doDecrypt()" class="flex-1 bg-slate-700 hover:bg-slate-600 text-white font-medium py-3 rounded-lg transition">Decrypt Data</button>
                    </div>
                </div>
                <div class="flex flex-col h-full">
                    <div class="flex justify-between items-end mb-1">
                        <label class="block text-xs font-medium text-slate-400">Result Output</label>
                        <button onclick="copyContent('symOut')" class="text-xs text-slate-400 hover:text-white transition">Copy Result</button>
                    </div>
                    <div id="symOut" class="flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap"></div>
                </div>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                <h2 class="text-xl font-semibold text-purple-400">2. Identity & Keys (ECDSA)</h2>
            </div>
            <div class="p-6 space-y-6">
                <div class="flex flex-col md:flex-row gap-4 items-end">
                    <div class="flex-1 w-full">
                        <label class="block text-xs font-medium text-slate-400 mb-1">Private Key Password (Required)</label>
                        <input id="authPass" type="password" placeholder="Enter a strong password..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none text-sm">
                    </div>
                    <button onclick="genAuthKeys()" class="w-full md:w-auto bg-purple-600 hover:bg-purple-500 px-6 py-3 rounded-lg font-medium transition shadow-lg shadow-purple-900/20 whitespace-nowrap">
                        Generate Identity Keys
                    </button>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                        <div class="flex justify-between items-end mb-1">
                            <label class="block text-xs font-medium text-slate-400">Public Key (Shareable)</label>
                            <button onclick="copyToClipboard('pubKey')" class="text-xs text-slate-400 hover:text-white transition">Copy</button>
                        </div>
                        <textarea id="pubKey" placeholder="Generated Public Key PEM..." readonly class="w-full p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 font-mono text-[11px] h-40 resize-y focus:outline-none"></textarea>
                    </div>
                    <div>
                        <div class="flex justify-between items-end mb-1">
                            <label class="block text-xs font-medium text-slate-400">Encrypted Private Key (Keep Secret)</label>
                            <button onclick="copyToClipboard('privKey')" class="text-xs text-slate-400 hover:text-white transition">Copy</button>
                        </div>
                        <textarea id="privKey" placeholder="Generated Private Key PEM..." readonly class="w-full p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-500 font-mono text-[11px] h-40 resize-y focus:outline-none"></textarea>
                    </div>
                </div>
            </div>
        </section>

        <section class="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden mb-12">
            <div class="bg-slate-800/50 px-6 py-4 border-b border-slate-800">
                <h2 class="text-xl font-semibold text-pink-400">3. File Integrity Engine</h2>
            </div>
            <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-8 items-start">
                
                <div class="space-y-4">
                    <div class="border-2 border-dashed border-slate-700 hover:border-pink-500 bg-slate-950 rounded-xl p-8 text-center transition group relative">
                        <input type="file" id="fileInput" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10" onchange="updateFileName()">
                        <div class="text-slate-400 group-hover:text-pink-400 transition">
                            <span class="text-4xl block mb-2">📁</span>
                            <span id="fileNameDisplay" class="font-medium">Click or Drag to Upload File</span>
                            <p class="text-xs mt-1 opacity-70">Supports PNG, JPG, PDF, TXT</p>
                        </div>
                    </div>
                    
                    <div>
                        <div class="flex justify-between items-end mb-1">
                            <label class="block text-xs font-medium text-slate-400">File Signature (Hex)</label>
                            <button onclick="copyToClipboard('sigHex')" class="text-xs text-slate-400 hover:text-white transition">Copy</button>
                        </div>
                        <textarea id="sigHex" placeholder="Generated or pasted signature hex will appear here..." class="w-full p-3 bg-slate-950 rounded-lg border border-slate-700 focus:border-pink-500 outline-none text-sm font-mono h-24 resize-y"></textarea>
                    </div>
                </div>

                <div class="space-y-4 bg-slate-950/50 p-6 rounded-xl border border-slate-800">
                    <p class="text-sm text-slate-400 mb-4">Ensure your keys and password are filled out in Section 2 before proceeding.</p>
                    
                    <button onclick="signFile()" class="w-full bg-pink-600 hover:bg-pink-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-pink-900/20 flex justify-center items-center gap-2">
                        <span>🖋️</span> 1. Generate Signature
                    </button>
                    
                    <button onclick="verifyFile()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-3 rounded-lg transition shadow-lg shadow-indigo-900/20 flex justify-center items-center gap-2 mt-2">
                        <span>🛡️</span> 2. Verify Authenticity
                    </button>

                    <div id="fileResult" class="mt-6 p-4 rounded-lg text-center font-bold text-lg hidden border"></div>
                </div>
            </div>
        </section>
    </div>

    <script>
        // --- UI Helpers ---
        function showToast(message, type="success") {
            const toast = document.createElement('div');
            const color = type === "error" ? "bg-red-500" : "bg-emerald-500";
            toast.className = `${color} text-white px-6 py-3 rounded-lg shadow-lg transform transition-all duration-300 translate-x-full opacity-0 flex items-center gap-2 font-medium text-sm`;
            toast.innerText = message;
            
            const container = document.getElementById('toast-container');
            container.appendChild(toast);
            
            setTimeout(() => { toast.classList.remove('translate-x-full', 'opacity-0'); }, 10);
            
            setTimeout(() => {
                toast.classList.add('opacity-0');
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        function copyToClipboard(elementId) {
            const el = document.getElementById(elementId);
            if (!el.value) return showToast("Nothing to copy!", "error");
            navigator.clipboard.writeText(el.value);
            showToast("Copied to clipboard!");
        }

        function copyContent(elementId) {
            const el = document.getElementById(elementId);
            if (!el.innerText) return showToast("Nothing to copy!", "error");
            navigator.clipboard.writeText(el.innerText);
            showToast("Copied result!");
        }

        function updateFileName() {
            const file = document.getElementById('fileInput').files[0];
            const display = document.getElementById('fileNameDisplay');
            if(file) display.innerText = `Selected: ${file.name}`;
        }

        // --- API Calls ---
        async function genSymKey() {
            try {
                const r = await fetch('/encryption/generate-key');
                const d = await r.json();
                document.getElementById('symKey').value = d.key;
                showToast("New Symmetric Key Generated");
            } catch(e) { showToast("Error generating key", "error"); }
        }

        async function doEncrypt() {
            try {
                const r = await fetch('/encryption/encrypt', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: document.getElementById('symKey').value, data: document.getElementById('symData').value})
                });
                const d = await r.json();
                if(r.ok) {
                    document.getElementById('symOut').innerText = d.encrypted_data;
                    document.getElementById('symOut').className = "flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-cyan-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap";
                    showToast("Encryption Successful");
                } else { throw new Error(d.detail); }
            } catch(e) { 
                document.getElementById('symOut').innerText = e.message;
                document.getElementById('symOut').className = "flex-1 p-4 bg-red-950/30 rounded-lg border border-red-800 text-red-400 font-mono text-sm break-all overflow-y-auto";
            }
        }

        async function doDecrypt() {
            try {
                const r = await fetch('/encryption/decrypt', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key: document.getElementById('symKey').value, data: document.getElementById('symData').value})
                });
                const d = await r.json();
                if(r.ok) {
                    document.getElementById('symOut').innerText = d.decrypted_data;
                    document.getElementById('symOut').className = "flex-1 p-4 bg-slate-950 rounded-lg border border-slate-800 text-emerald-300 font-mono text-sm break-all overflow-y-auto whitespace-pre-wrap";
                    showToast("Decryption Successful");
                } else { throw new Error(d.detail); }
            } catch(e) { 
                document.getElementById('symOut').innerText = "Failed: Check your key and cipher formatting.";
                document.getElementById('symOut').className = "flex-1 p-4 bg-red-950/30 rounded-lg border border-red-800 text-red-400 font-mono text-sm break-all overflow-y-auto";
            }
        }

        async function genAuthKeys() {
            const p = document.getElementById('authPass').value;
            if(!p) return showToast("Password is required to secure private key!", "error");
            
            try {
                const r = await fetch(`/auth/generate-keys?password=${encodeURIComponent(p)}`, {method: 'POST'});
                const d = await r.json();
                document.getElementById('pubKey').value = d.public_key_pem;
                document.getElementById('privKey').value = d.private_key_pem;
                showToast("Identity Keys Generated");
            } catch(e) { showToast("Failed to generate keys", "error"); }
        }

        async function signFile() {
            const file = document.getElementById('fileInput').files[0];
            const privKey = document.getElementById('privKey').value;
            const pass = document.getElementById('authPass').value;
            
            if(!file) return showToast("Please select a file first.", "error");
            if(!privKey || !pass) return showToast("Private key and password required.", "error");

            const fd = new FormData();
            fd.append('file', file);
            fd.append('private_key_pem', privKey);
            fd.append('private_key_password', pass);
            
            try {
                showToast("Processing Signature...");
                const r = await fetch('/auth/sign-file', {method: 'POST', body: fd});
                const d = await r.json();
                if(r.ok) {
                    document.getElementById('sigHex').value = d.signature_hex;
                    showToast("File Signed Successfully!");
                } else { throw new Error(d.detail); }
            } catch(e) { showToast("Signing failed: " + e.message, "error"); }
        }

        async function verifyFile() {
            const file = document.getElementById('fileInput').files[0];
            const pubKey = document.getElementById('pubKey').value;
            const sigHex = document.getElementById('sigHex').value;

            if(!file || !pubKey || !sigHex) return showToast("File, Public Key, and Signature are all required.", "error");

            const fd = new FormData();
            fd.append('file', file);
            fd.append('public_key_pem', pubKey);
            fd.append('signature_hex', sigHex.trim());
            
            try {
                const r = await fetch('/auth/verify-file', {method: 'POST', body: fd});
                const d = await r.json();
                
                const resEl = document.getElementById('fileResult');
                resEl.classList.remove('hidden');
                
                if(d.is_valid) {
                    resEl.innerText = "✅ FILE IS AUTHENTIC AND UNTAMPERED";
                    resEl.className = "mt-6 p-4 rounded-lg text-center font-bold text-lg border border-emerald-500/50 bg-emerald-500/10 text-emerald-400 tracking-wide";
                    showToast("Verification Passed");
                } else {
                    resEl.innerText = "❌ CORRUPTED OR INVALID SIGNATURE";
                    resEl.className = "mt-6 p-4 rounded-lg text-center font-bold text-lg border border-red-500/50 bg-red-500/10 text-red-400 tracking-wide shadow-[0_0_15px_rgba(239,68,68,0.2)]";
                    showToast("Verification Failed", "error");
                }
            } catch(e) { showToast("Verification Request Failed", "error"); }
        }
    </script>
</body>
</html>
"""

# ==========================================
# API ENDPOINTS
# ==========================================

@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
def serve_ui():
    return HTML_CONTENT

@app.get("/encryption/generate-key")
def generate_key():
    return {"key": Fernet.generate_key().decode()}

class EnDecryptRequest(BaseModel):
    key: str
    data: str

@app.post("/encryption/encrypt")
def encrypt_data_endpoint(req: EnDecryptRequest):
    try:
        f = Fernet(req.key.encode())
        return {"encrypted_data": f.encrypt(req.data.encode()).decode()}
    except Exception: 
        raise HTTPException(status_code=400, detail="Invalid Key/Data")

@app.post("/encryption/decrypt")
def decrypt_data_endpoint(req: EnDecryptRequest):
    try:
        f = Fernet(req.key.encode())
        return {"decrypted_data": f.decrypt(req.data.encode()).decode()}
    except Exception: 
        raise HTTPException(status_code=400, detail="Decryption Failed")

@app.post("/auth/generate-keys")
def generate_auth_keys(password: str):
    priv, pub = auth_tool.generate_key_pair()
    return {
        "private_key_pem": priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password.encode())).decode(),
        "public_key_pem": pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    }

@app.post("/auth/sign-file")
async def sign_file(private_key_pem: str = Form(...), private_key_password: str = Form(...), file: UploadFile = File(...)):
    fb = await file.read()
    pk = serialization.load_pem_private_key(private_key_pem.encode(), password=private_key_password.encode())
    return {"signature_hex": auth_tool.sign_data(pk, fb).hex()}

@app.post("/auth/verify-file")
async def verify_file(public_key_pem: str = Form(...), signature_hex: str = Form(...), file: UploadFile = File(...)):
    fb = await file.read()
    pbk = serialization.load_pem_public_key(public_key_pem.encode())
    return {"is_valid": auth_tool.verify_signature(pbk, fb, bytes.fromhex(signature_hex))}

# ==========================================
# SERVER RUNNER (Enables Multi-Device Access)
# ==========================================
if __name__ == "__main__":
    # Host 0.0.0.0 binds to all network interfaces so other devices can access it
    uvicorn.run(app, host="0.0.0.0", port=8000)