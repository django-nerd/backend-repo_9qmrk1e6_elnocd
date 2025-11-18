"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    email: str = Field(..., description="Email address")
    password_hash: str = Field(..., description="PBKDF2-SHA256 hash of the password (hex)")
    password_salt: str = Field(..., description="Salt for password hashing (hex)")
    iterations: int = Field(200000, description="PBKDF2 iterations")
    encryption_salt: str = Field(..., description="Salt used to derive KEK (hex)")
    encrypted_vault_key: str = Field(..., description="Fernet-encrypted vault key (base64)")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Session(BaseModel):
    """
    Active sessions mapped to user and token. Vault key is stored only for the session lifetime.
    """
    user_id: str
    token: str
    vault_key_b64: str
    expires_at: datetime

class VaultItem(BaseModel):
    """
    Encrypted vault items (all sensitive fields are encrypted using user's vault key via Fernet)
    Collection name: "vaultitem" -> we will query by user_id
    """
    user_id: str
    title: str
    username_enc: str
    password_enc: str
    url: Optional[str] = None
    notes_enc: Optional[str] = None

class SeedPhrase(BaseModel):
    """
    Encrypted seed phrase linked to a user
    """
    user_id: str
    label: str
    seed_enc: str
