import jwt
import time
from typing import Optional

# In a real app, this should be generated cryptographically and stored securely
SECRET_KEY = "SUPER_SECRET_ZK_DEMO_KEY_DONT_USE_IN_PROD"

def create_jwt(username: str) -> str:
    payload = {
        "sub": username, 
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_jwt(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
        return None
