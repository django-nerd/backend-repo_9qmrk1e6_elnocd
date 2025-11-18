import os
import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List

import requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo.collection import Collection
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Utilities --------------------

def pbkdf2_hash(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


def derive_kek(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    # key encryption key
    return pbkdf2_hash(password, salt, iterations)


from cryptography.fernet import Fernet


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode())


# -------------------- Models --------------------
class RegisterRequest(BaseModel):
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_in: int


class VaultItemIn(BaseModel):
    title: str
    username: str
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None


class VaultItemOut(BaseModel):
    id: str
    title: str
    username: str
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None


class SeedIn(BaseModel):
    label: str
    seed_phrase: str


# -------------------- Helpers --------------------

def users_col() -> Collection:
    return db["user"]


def sessions_col() -> Collection:
    return db["session"]


def vault_col() -> Collection:
    return db["vaultitem"]


def seed_col() -> Collection:
    return db["seedphrase"]


def create_user(email: str, password: str):
    if users_col().find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    # hash login password
    pw_salt = secrets.token_bytes(16)
    pw_hash = pbkdf2_hash(password, pw_salt)

    # derive KEK and encrypt a fresh vault key
    kek_salt = secrets.token_bytes(16)
    kek = derive_kek(password, kek_salt)
    vault_key = Fernet.generate_key()  # base64 key for Fernet

    # encrypt vault_key with KEK using HMAC-based one-time pad (XOR) or Fernet? We'll use HMAC-derived 32 bytes turned into Fernet key
    # To encrypt safely, we create a Fernet from KEK transformed to 32 urlsafe base64
    kek_32 = hashlib.sha256(kek).digest()
    kek_fernet_key = base64.urlsafe_b64encode(kek_32)
    f_kek = Fernet(kek_fernet_key)
    enc_vault_key = f_kek.encrypt(vault_key).decode()

    doc = {
        "email": email,
        "password_hash": pw_hash.hex(),
        "password_salt": pw_salt.hex(),
        "iterations": 200000,
        "encryption_salt": kek_salt.hex(),
        "encrypted_vault_key": enc_vault_key,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = users_col().insert_one(doc)
    return str(res.inserted_id)


def verify_password(pw: str, salt_hex: str, hash_hex: str, iterations: int) -> bool:
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    actual = pbkdf2_hash(pw, salt, iterations)
    return hmac.compare_digest(actual, expected)


def create_session(user_id: str, password: str) -> LoginResponse:
    user = users_col().find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(400, "Invalid user")

    # derive KEK and decrypt vault key
    kek = derive_kek(password, bytes.fromhex(user["encryption_salt"]))
    kek_fernet_key = base64.urlsafe_b64encode(hashlib.sha256(kek).digest())
    f_kek = Fernet(kek_fernet_key)
    try:
        vault_key = f_kek.decrypt(user["encrypted_vault_key"].encode())
    except Exception:
        raise HTTPException(401, "Invalid credentials")

    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    expires_at = datetime.now(timezone.utc) + timedelta(hours=12)

    sessions_col().insert_one({
        "user_id": user_id,
        "token": token,
        "vault_key_b64": vault_key.decode(),
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc)
    })
    return LoginResponse(token=token, expires_in=int(12*3600))


def auth(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    token = authorization.split(" ")[1]
    ses = sessions_col().find_one({"token": token})
    if not ses:
        raise HTTPException(401, "Invalid token")
    if ses.get("expires_at") and ses["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(401, "Session expired")
    return ses


def get_vault_key_from_session(session_doc) -> bytes:
    return session_doc["vault_key_b64"].encode()


# Encryption helpers for fields

def encrypt_with_vault(vault_key_b64: bytes, plaintext: str) -> str:
    f = Fernet(vault_key_b64)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_with_vault(vault_key_b64: bytes, ciphertext: str) -> str:
    f = Fernet(vault_key_b64)
    return f.decrypt(ciphertext.encode()).decode()


# -------------------- Routes --------------------
@app.get("/")
def root():
    return {"message": "Password Manager API running"}


@app.post("/auth/register")
def register(req: RegisterRequest):
    user_id = create_user(req.email, req.password)
    return {"user_id": user_id}


@app.post("/auth/login", response_model=LoginResponse)
def login(req: LoginRequest):
    user = users_col().find_one({"email": req.email})
    if not user:
        raise HTTPException(401, "Invalid credentials")
    if not verify_password(req.password, user["password_salt"], user["password_hash"], user.get("iterations", 200000)):
        raise HTTPException(401, "Invalid credentials")
    return create_session(str(user["_id"]), req.password)


@app.post("/vault", response_model=VaultItemOut)
def add_item(item: VaultItemIn, session=Depends(auth)):
    vault_key_b64 = get_vault_key_from_session(session)
    doc = {
        "user_id": session["user_id"],
        "title": item.title,
        "username_enc": encrypt_with_vault(vault_key_b64, item.username),
        "password_enc": encrypt_with_vault(vault_key_b64, item.password),
        "url": item.url,
        "notes_enc": encrypt_with_vault(vault_key_b64, item.notes) if item.notes else None,
        "created_at": datetime.now(timezone.utc)
    }
    res = vault_col().insert_one(doc)
    return VaultItemOut(
        id=str(res.inserted_id),
        title=item.title,
        username=item.username,
        password=item.password,
        url=item.url,
        notes=item.notes
    )


@app.get("/vault", response_model=List[VaultItemOut])
def list_items(session=Depends(auth)):
    vault_key_b64 = get_vault_key_from_session(session)
    docs = vault_col().find({"user_id": session["user_id"]}).sort("created_at", -1)
    out: List[VaultItemOut] = []
    for d in docs:
        out.append(VaultItemOut(
            id=str(d["_id"]),
            title=d.get("title", ""),
            username=decrypt_with_vault(vault_key_b64, d["username_enc"]),
            password=decrypt_with_vault(vault_key_b64, d["password_enc"]),
            url=d.get("url"),
            notes=decrypt_with_vault(vault_key_b64, d["notes_enc"]) if d.get("notes_enc") else None
        ))
    return out


@app.delete("/vault/{item_id}")
def delete_item(item_id: str, session=Depends(auth)):
    d = vault_col().find_one({"_id": ObjectId(item_id)})
    if not d or d["user_id"] != session["user_id"]:
        raise HTTPException(404, "Not found")
    vault_col().delete_one({"_id": ObjectId(item_id)})
    return {"ok": True}


@app.post("/seed")
def add_seed(data: SeedIn, session=Depends(auth)):
    vault_key_b64 = get_vault_key_from_session(session)
    enc = encrypt_with_vault(vault_key_b64, data.seed_phrase)
    seed_col().insert_one({
        "user_id": session["user_id"],
        "label": data.label,
        "seed_enc": enc,
        "created_at": datetime.now(timezone.utc)
    })
    return {"ok": True}


@app.get("/seed")
def list_seeds(session=Depends(auth)):
    vault_key_b64 = get_vault_key_from_session(session)
    docs = list(seed_col().find({"user_id": session["user_id"]}).sort("created_at", -1))
    return [{"id": str(d["_id"]), "label": d["label"], "seed_phrase": decrypt_with_vault(vault_key_b64, d["seed_enc"]) } for d in docs]


@app.delete("/seed/{seed_id}")
def delete_seed(seed_id: str, session=Depends(auth)):
    d = seed_col().find_one({"_id": ObjectId(seed_id)})
    if not d or d["user_id"] != session["user_id"]:
        raise HTTPException(404, "Not found")
    seed_col().delete_one({"_id": ObjectId(seed_id)})
    return {"ok": True}


# Password breach checker using HIBP k-anonymity API
@app.get("/breach/{password}")
def breach_check(password: str):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        raise HTTPException(502, "HIBP service error")
    lines = r.text.splitlines()
    count = 0
    for line in lines:
        sfx, cnt = line.split(":")
        if sfx == suffix:
            count = int(cnt)
            break
    return {"breached": count > 0, "count": count}


# Simple AI suggestion feature (local heuristic)
class SuggestRequest(BaseModel):
    context: str


@app.post("/ai/suggest")
def ai_suggest(req: SuggestRequest):
    # Lightweight heuristic suggestions (no external LLM call to avoid dependency)
    tips = []
    text = req.context.lower()
    if "password" in text:
        tips.append("Use at least 12 characters with a mix of upper, lower, numbers, and symbols.")
    if "seed" in text:
        tips.append("Store seed phrases offline and never share them. Consider a hardware wallet.")
    if "reuse" in text:
        tips.append("Avoid reusing passwords across sites.")
    if not tips:
        tips.append("Enable 2FA where possible and rotate high-value credentials periodically.")
    return {"suggestions": tips}


# Endpoint to logout (invalidate session)
@app.post("/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return {"ok": True}
    token = authorization.split(" ")[1]
    sessions_col().delete_one({"token": token})
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
