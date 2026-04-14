from pydantic import BaseModel
from typing import Optional, Dict, Any, List

class RegisterRequest(BaseModel):
    username: str
    credential_id: str
    prf_salt_hex: str
    public_identity_key_hex: str  # Ed25519
    public_messaging_key_hex: str # X25519
    vault_ciphertext_hex: str
    vault_nonce_hex: str

class LoginContextResponse(BaseModel):
    prf_salt_hex: str
    credential_id: str
    vault_ciphertext_hex: str
    vault_nonce_hex: str

class AuthVerifyRequest(BaseModel):
    username: str
    signature_hex: str  # Client signs their username with Ed25519 identity key
    timestamp: int

class EncryptedMessage(BaseModel):
    id: str = None
    from_id: str
    to_id: str
    ciphertext_hex: str
    nonce_hex: str
    timestamp: int = None
    signature_hex: str  # From Ed25519 identity key for authenticity
