import hmac
import hashlib
import time
import base64
import json
import os
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from config import JWT_SECRET, TOKEN_EXPIRY


def sign(payload: dict, secret: str = None) -> str:
    secret = secret or JWT_SECRET
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {**payload, "exp": int(time.time()) + TOKEN_EXPIRY, "iat": int(time.time())}
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
    h = b64(header)
    p = b64(payload)
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{sig_b64}"


def verify(token: str, secret: str = None) -> Optional[dict]:
    secret = secret or JWT_SECRET
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        h, p, sig = parts
        expected = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        sig_padded = sig + "=" * (4 - len(sig) % 4) if len(sig) % 4 else sig
        sig_bytes = base64.urlsafe_b64decode(sig_padded)
        if not hmac.compare_digest(sig_bytes, expected):
            return None
        p_padded = p + "=" * (4 - len(p) % 4) if len(p) % 4 else p
        payload = json.loads(base64.urlsafe_b64decode(p_padded))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def hash_password(password: str, salt: str = None) -> dict:
    if salt is None:
        salt = os.urandom(16).hex()
    h = hashlib.pbkdf2_hmac("sha512", password.encode(), salt.encode(), 10000, 64).hex()
    return {"hash": h, "salt": salt}


# Rate limiting
_login_attempts: Dict[str, Dict[str, Any]] = {}


def check_login_rate(ip: str) -> bool:
    entry = _login_attempts.get(ip)
    if not entry:
        return True
    if time.time() * 1000 - entry["last_attempt"] > 300000:
        del _login_attempts[ip]
        return True
    return entry["count"] < 5


def record_failed_login(ip: str):
    entry = _login_attempts.get(ip, {"count": 0, "last_attempt": 0})
    entry["count"] += 1
    entry["last_attempt"] = time.time() * 1000
    _login_attempts[ip] = entry


def clear_login_attempts(ip: str):
    _login_attempts.pop(ip, None)


# Simple manual auth — reads Bearer token from header.
# Using plain function instead of FastAPI security scheme to avoid Body parsing issues.
async def auth_required(request: Request) -> dict:
    auth_header = request.headers.get("Authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = verify(token)
    if not user:
        raise HTTPException(status_code=403, detail="Invalid token")
    return user
