"""
Authentication and authorization helpers for AEGIS.
"""

from datetime import datetime, timedelta, timezone
import secrets
from typing import Dict, Any
import os
import hashlib
import hmac
import base64

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from .config import settings


bearer_scheme = HTTPBearer(auto_error=False)
AUTH_COOKIE_NAME = "aegis_access_token"


def auth_cookie_secure() -> bool:
    """Use Secure cookies only outside local debug (http://127.0.0.1 needs secure=False)."""
    return not settings.debug


def _build_admin_user() -> Dict[str, Any]:
    return {
        "username": settings.admin_email,
        "email": settings.admin_email,
        "role": "admin",
    }


def verify_admin_credentials(username: str, password: str) -> bool:
    return secrets.compare_digest(username.lower(), settings.admin_email.lower()) and secrets.compare_digest(password, settings.admin_password)


def hash_password(password: str) -> str:
    iterations = 390000
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256${}${}${}".format(
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if hashed_password.startswith("pbkdf2_sha256$"):
            _, iter_str, salt_b64, digest_b64 = hashed_password.split("$", 3)
            iterations = int(iter_str)
            salt = base64.b64decode(salt_b64.encode("ascii"))
            expected = base64.b64decode(digest_b64.encode("ascii"))
            actual = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(actual, expected)

        # Backward compatibility for existing bcrypt hashes if present.
        if hashed_password.startswith("$2a$") or hashed_password.startswith("$2b$") or hashed_password.startswith("$2y$"):
            import bcrypt
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False
    return False


def create_access_token(subject: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.auth_token_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=["HS256"])
        return payload
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc


def require_authenticated_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> Dict[str, Any]:
    token = credentials.credentials if credentials else request.cookies.get(AUTH_COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = decode_access_token(token)
    username = payload.get("sub")
    role = payload.get("role")
    if not username or not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    return {"username": username, "role": role}


def require_admin_user(user: Dict[str, Any] = Depends(require_authenticated_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def get_default_admin_user() -> Dict[str, Any]:
    return _build_admin_user()


async def ensure_default_admin_user(db) -> Dict[str, Any]:
    """
    Ensure default admin user from env exists in database.
    Returns the admin user identity metadata.
    """
    from sqlalchemy import select
    from .models import User

    admin = get_default_admin_user()
    existing = (await db.execute(select(User).where(User.username == admin["username"]))).scalar_one_or_none()
    if existing is None:
        db.add(
            User(
                username=admin["username"],
                password_hash=hash_password(settings.admin_password),
                role="admin",
                is_active=True,
            )
        )
        await db.flush()
    return admin
