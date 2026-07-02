# Auth routes
import json
from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
from auth import sign, verify, hash_password, check_login_rate, record_failed_login, clear_login_attempts, auth_required
from config import JWT_SECRET
from db import get_db, get_user, update_password

router = APIRouter()


@router.post("/login")
async def login(request: Request):
    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For", "unknown")
    if not check_login_rate(ip):
        return JSONResponse({"error": "Too many attempts. Try again later."}, status_code=429)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    username = body.get("username", "")
    password = body.get("password", "")
    if not username or not password:
        return JSONResponse({"error": "Username and password required"}, status_code=400)

    user = get_user(username)
    if not user:
        record_failed_login(ip)
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    h = hash_password(password, user["salt"])
    if h["hash"] != user["password"]:
        record_failed_login(ip)
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)

    clear_login_attempts(ip)
    token = sign({"username": user["username"]})
    is_default = username == "admin" and password == "vkomari"
    return {"token": token, "isDefault": is_default}
