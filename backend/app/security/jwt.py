from datetime import datetime, timedelta, timezone
from jose import jwt
from app.config import get_settings

def create_access_token(user_id: int) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": str(user_id), "type": "access", "iat": now, "exp": now + timedelta(minutes=s.access_token_minutes)}, s.jwt_secret, algorithm=s.jwt_algorithm)

def decode_access_token(token: str) -> int:
    s = get_settings()
    payload = jwt.decode(token, s.jwt_secret, algorithms=[s.jwt_algorithm])
    if payload.get("type") != "access":
        raise ValueError("Invalid token type")
    return int(payload["sub"])
