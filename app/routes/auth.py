"""
Authentication routes.
"""

from fastapi import APIRouter, HTTPException, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import re

from ..security import (
    verify_admin_credentials,
    create_access_token,
    get_default_admin_user,
    require_authenticated_user,
    AUTH_COOKIE_NAME,
    hash_password,
    verify_password,
    auth_cookie_secure,
)
from ..database import get_db
from ..models import User

router = APIRouter()


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _is_valid_email(value: str) -> bool:
    pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
    return bool(pattern.fullmatch(value))


def _validate_password_rules(password: str) -> str:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password must be at most 128 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character."
    return ""


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    email: str
    role: str


class SignupRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=6, max_length=200)


@router.post("/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    email = _normalize_email(request.email)
    if not _is_valid_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")

    if verify_admin_credentials(email, request.password):
        admin = get_default_admin_user()
        token = create_access_token(subject=admin["username"], role=admin["role"])
        response.set_cookie(
            key=AUTH_COOKIE_NAME,
            value=token,
            httponly=True,
            secure=auth_cookie_secure(),
            samesite="lax",
            max_age=60 * 60 * 8,
            path="/",
        )
        return LoginResponse(email=admin["username"], role=admin["role"])

    user = (await db.execute(select(User).where(User.username == email))).scalar_one_or_none()
    if not user or not user.is_active or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(subject=user.username, role=user.role)
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=auth_cookie_secure(),
        samesite="lax",
        max_age=60 * 60 * 8,
        path="/",
    )
    return LoginResponse(email=user.username, role=user.role)


@router.post("/auth/signup", response_model=LoginResponse)
async def signup(request: SignupRequest, response: Response, db: AsyncSession = Depends(get_db)):
    email = _normalize_email(request.email)
    if not _is_valid_email(email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    password_issue = _validate_password_rules(request.password)
    if password_issue:
        raise HTTPException(status_code=400, detail=password_issue)
    if email == get_default_admin_user()["username"].lower():
        raise HTTPException(status_code=400, detail="Email reserved")

    existing = (await db.execute(select(User).where(User.username == email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already exists")

    user = User(
        username=email,
        password_hash=hash_password(request.password),
        role="user",
        is_active=True,
    )
    db.add(user)
    await db.flush()
    token = create_access_token(subject=user.username, role=user.role)
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=auth_cookie_secure(),
        samesite="lax",
        max_age=60 * 60 * 8,
        path="/",
    )
    return LoginResponse(email=user.username, role=user.role)


@router.get("/auth/me")
async def me(user=Depends(require_authenticated_user)):
    return user


@router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie(key=AUTH_COOKIE_NAME, path="/")
    return {"status": "ok"}
