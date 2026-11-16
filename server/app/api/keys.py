"""Directorio de claves públicas + respaldo de claves privadas ENVUELTAS.

El servidor nunca recibe claves privadas en claro: el cliente las envuelve con
AES-256-GCM usando una KEK derivada con Argon2id de la frase de recuperación.
Al recibir claves públicas, el servidor exige la política mínima (RSA-OAEP ≥ 3072, ECDSA P-256).
"""
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from ..crypto import b64decode_strict, load_ecdsa_p256_public, load_rsa_oaep_public
from ..models import User, UserKeys, get_db
from ..security import current_user

router = APIRouter(prefix="/keys", tags=["keys"])


class KeysIn(BaseModel):
    enc_public_key: str = Field(..., description="RSA-OAEP ≥ 3072 bits, SPKI DER en base64")
    sig_public_key: str = Field(..., description="ECDSA P-256, SPKI DER en base64")
    wrapped_private_keys: str = Field(..., description='JSON en texto: {"iv": base64(12 B), "ct": base64}')
    kdf_salt: str = Field(..., description="Sal de Argon2id en base64 (≥ 16 bytes)")
    kdf_params: str = Field(..., description='JSON en texto, p. ej. {"alg":"argon2id","m":65536,"t":3,"p":1}')


def _validate(body: KeysIn) -> None:
    load_rsa_oaep_public(body.enc_public_key)
    load_ecdsa_p256_public(body.sig_public_key)
    if len(b64decode_strict(body.kdf_salt, "kdf_salt")) < 16:
        raise HTTPException(400, "kdf_salt debe tener al menos 16 bytes")
    try:
        wrapped = json.loads(body.wrapped_private_keys)
        params = json.loads(body.kdf_params)
    except ValueError:
        raise HTTPException(400, "wrapped_private_keys y kdf_params deben ser JSON")
    if not isinstance(wrapped, dict) or not {"iv", "ct"} <= wrapped.keys():
        raise HTTPException(400, 'wrapped_private_keys debe ser {"iv": ..., "ct": ...}')
    if len(b64decode_strict(wrapped["iv"], "wrapped_private_keys.iv")) != 12:
        raise HTTPException(400, "El IV de AES-GCM debe medir 12 bytes")
    if not isinstance(params, dict) or params.get("alg") not in ("argon2id", "pbkdf2"):
        raise HTTPException(400, 'kdf_params.alg debe ser "argon2id" o "pbkdf2"')


@router.put("/me")
def put_my_keys(body: KeysIn, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Crea o reemplaza las claves del usuario. Si las claves públicas cambian, la huella cambia
    y los demás clientes deben alertar (posible sustitución de clave)."""
    _validate(body)
    keys = db.get(UserKeys, user.id)
    rotated = bool(keys) and (keys.enc_public_key != body.enc_public_key
                              or keys.sig_public_key != body.sig_public_key)
    if keys:
        for k, v in body.model_dump().items():
            setattr(keys, k, v)
    else:
        db.add(UserKeys(user_id=user.id, **body.model_dump()))
    db.commit()
    return {"ok": True, "rotated": rotated}


@router.get("/me")
def get_my_keys(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    keys = db.get(UserKeys, user.id)
    if not keys:
        raise HTTPException(404, "Aún no has generado tus claves")
    return {"username": user.username, "enc_public_key": keys.enc_public_key,
            "sig_public_key": keys.sig_public_key,
            "wrapped_private_keys": keys.wrapped_private_keys,
            "kdf_salt": keys.kdf_salt, "kdf_params": keys.kdf_params,
            "updated_at": keys.updated_at.isoformat()}


@router.get("/{username}")
def get_public_keys(username: str, _: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Devuelve SOLO las claves públicas. El cliente DEBE verificar la huella antes de usarlas."""
    other = db.scalar(select(User).where(User.username == username.lower()))
    keys = db.get(UserKeys, other.id) if other else None
    if not keys:
        raise HTTPException(404, "Usuario o claves no encontrados")
    return {"username": other.username, "enc_public_key": keys.enc_public_key,
            "sig_public_key": keys.sig_public_key, "updated_at": keys.updated_at.isoformat()}


def require_keys(db: DBSession, user: User) -> UserKeys:
    keys = db.get(UserKeys, user.id)
    if not keys:
        raise HTTPException(409, f"{user.username} aún no ha generado sus claves")
    return keys
