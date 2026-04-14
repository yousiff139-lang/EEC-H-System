import time
import json
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List

from models import RegisterRequest, LoginContextResponse, AuthVerifyRequest, EncryptedMessage
from auth import create_jwt, decode_jwt
from crypto_utils import verify_ed25519_signature
from ws import manager

app = FastAPI(title="Zero-Knowledge E2EE Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- In-Memory DB for Demo ---
# user db maps username -> RegisterRequest (which contains public keys and ciphertext)
users_db: Dict[str, RegisterRequest] = {}
# messages db maps username -> List[EncryptedMessage]
messages_db: Dict[str, List[EncryptedMessage]] = {}

@app.post("/register")
async def register(req: RegisterRequest):
    if req.username in users_db:
        raise HTTPException(status_code=400, detail="User already registered")
    users_db[req.username] = req
    messages_db[req.username] = []
    return {"status": "success", "message": "Opaque vault stored."}

@app.get("/login-context/{username}", response_model=LoginContextResponse)
async def get_login_context(username: str):
    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return LoginContextResponse(
        prf_salt_hex=user.prf_salt_hex,
        credential_id=user.credential_id,
        vault_ciphertext_hex=user.vault_ciphertext_hex,
        vault_nonce_hex=user.vault_nonce_hex
    )

@app.post("/auth")
async def authenticate(req: AuthVerifyRequest):
    """
    Zero-Knowledge Proof of Identity. 
    Client signs a timestamp string using their private Ed25519 key (which they just unwrapped).
    We verify with their public Ed25519 key.
    """
    user = users_db.get(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Reconstruct message
    msg = str(req.timestamp).encode('utf-8')
    
    # 5 minute tolerance
    if abs(int(time.time() * 1000) - req.timestamp) > 300000:
        raise HTTPException(status_code=400, detail="Timestamp expired")

    is_valid = verify_ed25519_signature(user.public_identity_key_hex, msg, req.signature_hex)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid signature")

    jwt_token = create_jwt(req.username)
    return {"token": jwt_token}

@app.get("/directory/{username}")
async def get_public_key(username: str):
    user = users_db.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": username,
        "public_messaging_key_hex": user.public_messaging_key_hex,
        "public_identity_key_hex": user.public_identity_key_hex
    }

@app.post("/messages")
async def send_message(msg: EncryptedMessage):
    """
    Server receives an opaque message blob.
    It verifies the sender's signature, then stores and forwards it to the recipient.
    """
    sender = users_db.get(msg.from_id)
    recipient = users_db.get(msg.to_id)
    if not sender or not recipient:
        raise HTTPException(status_code=404, detail="Sender or recipient not found")

    # Verify message authenticity via Ed25519
    payload_to_verify = f"{msg.from_id}:{msg.to_id}:{msg.ciphertext_hex}:{msg.nonce_hex}".encode('utf-8')
    is_valid = verify_ed25519_signature(sender.public_identity_key_hex, payload_to_verify, msg.signature_hex)
    
    if not is_valid:
        raise HTTPException(status_code=401, detail="Message signature invalid")

    msg.id = str(int(time.time() * 1000))
    msg.timestamp = int(time.time() * 1000)

    # Persist opaque blob
    messages_db[msg.to_id].append(msg)
    messages_db[msg.from_id].append(msg)

    # Real-time forward if recipient is online
    await manager.send_to_user(msg.to_id, {"type": "new_message", "message": msg.model_dump()})
    
    return {"status": "success", "id": msg.id}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    username = decode_jwt(token)
    if not username:
        await websocket.close(code=1008)
        return
    
    await manager.connect(websocket, username)
    try:
        # Send miss messages sync
        await websocket.send_json({"type": "sync", "messages": [m.model_dump() for m in messages_db.get(username, [])]})
        while True:
            # We just keep connection alive, messages are pushed from POST /messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(username)
