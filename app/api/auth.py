"""Authentication API."""

import base64
import hashlib
import hmac
import os
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse
from app.services.events import record_security_event

router = APIRouter()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    encode = lambda value: base64.urlsafe_b64encode(value).decode().rstrip("=")
    return f"scrypt${encode(salt)}${encode(derived)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt_text, digest_text = stored.split("$", 2)
        pad = lambda value: value + "=" * (-len(value) % 4)
        salt = base64.urlsafe_b64decode(pad(salt_text))
        expected = base64.urlsafe_b64decode(pad(digest_text))
        actual = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _token(username: str) -> str:
    expires = int(time.time()) + settings.AUTH_TOKEN_TTL_SECONDS
    message = f"{username}:{expires}"
    signature = hmac.new(settings.AUTH_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{message}:{signature}".encode()).decode().rstrip("=")


@router.post("/login", response_model=LoginResponse)
def login(login_request: LoginRequest, request: Request, db: Session = Depends(get_db)) -> LoginResponse:
    user = db.scalar(select(User).where(User.username == login_request.username))
    authenticated = user is not None and user.is_active and verify_password(login_request.password, user.password_hash)

    event_id = str(uuid.uuid4())
    record_security_event(
        db=db,
        event_id=event_id,
        event_type="authentication.login",
        actor=login_request.username,
        outcome="success" if authenticated else "failure",
        payload={
            "username": login_request.username,
            "ip_address": request.client.host if request.client else "unknown",
        },
    )

    if not authenticated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return LoginResponse(access_token=_token(login_request.username), expires_in=settings.AUTH_TOKEN_TTL_SECONDS)
