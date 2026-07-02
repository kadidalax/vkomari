import os

JWT_SECRET = os.getenv("JWT_SECRET", "vkomari-secret-key-2026")
DB_PATH = os.getenv("DB_PATH", "/app/data/vkomari.db")
TOKEN_EXPIRY = 86400
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_MS = 300000
