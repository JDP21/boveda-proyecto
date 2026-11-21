"""Sesiones del servidor (token opaco aleatorio de 256 bits almacenado como hash SHA-256)."""
import hashlib
import secrets
from datetime import timedelta

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import delete
from sqlalchemy.orm import Session as DBSession

from .config import SESSION_TTL_MINUTES
from .models import Challenge, Session, User, get_db, utcnow


def hash_token(token: str) -> str:
    """Calcula el digest SHA-256 hexadecimal del token de sesión."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_session(db: DBSession, user: User) -> str:
    token = secrets.token_hex(32)  # 256 bits, CSPRNG (se devuelve al cliente)
    db.add(
        Session(
            token=hash_token(token),  # en SQLite solo se guarda el hash
            user_id=user.id,
            expires_at=utcnow() + timedelta(minutes=SESSION_TTL_MINUTES),
        )
    )
    db.commit()
    return token


def revoke_session(db: DBSession, token: str) -> None:
    """Invalida una sesión buscando por el hash SHA-256 de su token."""
    db.execute(delete(Session).where(Session.token == hash_token(token)))
    db.commit()


def purge_expired(db: DBSession) -> None:
    """Elimina retos y sesiones vencidos (se llama en cada inicio de registro/login)."""
    now = utcnow()
    db.execute(delete(Challenge).where(Challenge.expires_at < now))
    db.execute(delete(Session).where(Session.expires_at < now))
    db.commit()


def bearer_token(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Falta token de sesión")
    return authorization.removeprefix("Bearer ").strip()


def current_user(token: str = Depends(bearer_token), db: DBSession = Depends(get_db)) -> User:
    sess = db.get(Session, hash_token(token))
    if not sess or sess.expires_at < utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sesión inválida o expirada")
    user = db.get(User, sess.user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario no existe")
    return user