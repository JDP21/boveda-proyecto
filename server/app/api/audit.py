"""Log de auditoría encadenado por hash y firmado (HU-07).

    h_i = SHA-256( bytes(h_{i-1}) ‖ UTF-8(evento_i) ),  h_0 = 64 ceros

El cliente arma el evento (JSON canónico), calcula entry_hash, lo FIRMA con su clave
ECDSA P-256 y lo envía. El servidor comprueba que encadena con la cabeza actual y
que la firma es válida con la clave pública del actor, y guarda esa clave junto a la
entrada para que la verificación siga siendo posible aunque el actor rote sus claves.
"""
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from ..crypto import verify_signature
from ..models import AuditEntry, User, UserKeys, get_db
from ..security import current_user

router = APIRouter(prefix="/audit", tags=["audit"])

GENESIS = "0" * 64
ACTIONS = {"register", "keys", "upload", "new_version", "download", "share", "revoke", "delete"}


def chain_hash(prev_hash: str, event: str) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash) + event.encode("utf-8")).hexdigest()


class AuditIn(BaseModel):
    event: str = Field(..., description='JSON canónico en texto, p. ej. {"action":"upload","file":"<id>","version":1}')
    prev_hash: str = Field(..., description="Hash de la cabeza actual (GET /audit/head), 64 hex")
    entry_hash: str = Field(..., description="SHA-256(bytes(prev_hash) ‖ UTF-8(event)) en hex")
    signature: str = Field(..., description="ECDSA P-256/SHA-256 (r‖s, base64) sobre el texto de entry_hash")


@router.get("/head")
def head(_: User = Depends(current_user), db: DBSession = Depends(get_db)):
    last = db.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
    return {"seq": last.seq if last else 0, "hash": last.entry_hash if last else GENESIS}


def append_entry(db: DBSession, user: User, body: AuditIn) -> AuditEntry:
    """Valida encadenamiento, formato y firma, y agrega la entrada (sin commit)."""
    keys = db.get(UserKeys, user.id)
    if not keys:
        raise HTTPException(409, "Debes generar tus claves antes de registrar eventos")
    try:
        ev = json.loads(body.event)
    except ValueError:
        raise HTTPException(400, "El evento no es JSON válido")
    if not isinstance(ev, dict) or ev.get("action") not in ACTIONS:
        raise HTTPException(400, f"event.action debe ser uno de {sorted(ACTIONS)}")
    last = db.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
    tip = last.entry_hash if last else GENESIS
    if body.prev_hash != tip:
        raise HTTPException(409, "prev_hash no coincide con la cabeza del log; vuelve a pedir /audit/head")
    if chain_hash(body.prev_hash, body.event) != body.entry_hash:
        raise HTTPException(400, "entry_hash incorrecto")
    if not verify_signature(keys.sig_public_key, body.entry_hash, body.signature):
        raise HTTPException(400, "Firma de la entrada de auditoría inválida")
    entry = AuditEntry(actor_id=user.id, event=body.event, prev_hash=body.prev_hash,
                       entry_hash=body.entry_hash, signature=body.signature,
                       signer_key=keys.sig_public_key)
    db.add(entry)
    db.flush()
    return entry


@router.post("")
def append(body: AuditIn, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    entry = append_entry(db, user, body)
    db.commit()
    return {"ok": True, "seq": entry.seq}


@router.get("")
def get_log(_: User = Depends(current_user), db: DBSession = Depends(get_db)):
    rows = db.execute(select(AuditEntry, User.username).join(User, User.id == AuditEntry.actor_id)
                      .order_by(AuditEntry.seq)).all()
    return [{"seq": e.seq, "actor": name, "event": e.event, "prev_hash": e.prev_hash,
             "entry_hash": e.entry_hash, "signature": e.signature, "signer_key": e.signer_key,
             "created_at": e.created_at.isoformat()} for e, name in rows]


@router.get("/verify-chain")
def verify_chain(_: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Recalcula la cadena y verifica cada firma. El cliente puede (y debe) repetir esta
    verificación por su cuenta con GET /audit, porque el servidor no es de confianza."""
    prev, count = GENESIS, 0
    for e in db.scalars(select(AuditEntry).order_by(AuditEntry.seq)):
        if e.prev_hash != prev or chain_hash(prev, e.event) != e.entry_hash:
            return {"ok": False, "broken_at": e.seq, "reason": "hash"}
        if not verify_signature(e.signer_key, e.entry_hash, e.signature):
            return {"ok": False, "broken_at": e.seq, "reason": "firma"}
        prev, count = e.entry_hash, count + 1
    return {"ok": True, "entries": count}
