"""Archivos cifrados (cifrado de sobre) — HU-05, HU-06, HU-10, HU-11.

El cliente envía: el archivo YA cifrado (IV de 12 B ‖ ciphertext AES-256-GCM ‖ tag), la
DEK envuelta con RSA-OAEP y un manifiesto JSON firmado con ECDSA P-256:

    manifest = {"id": <uuid>, "version": <int>, "sha256": <hex del blob cifrado>, ...metadatos}

El servidor NO puede descifrar nada, pero antes de guardar comprueba:
  - que el manifiesto corresponde al id y la versión,
  - que el SHA-256 del blob recibido coincide con el del manifiesto,
  - que la firma del manifiesto es válida con la clave pública del propietario,
  - que cada DEK envuelta mide lo que mide el módulo RSA de su destinatario,
  - que la versión siempre aumenta (anti-rollback).
El cliente vuelve a verificar firma, hash y etiqueta GCM al descargar (no confía en el servidor).

Todas las operaciones que modifican aceptan, opcionalmente, la entrada de auditoría FIRMADA
del evento; si se envía, se guarda en la misma transacción que la operación.
"""
import json
import os
import re
import uuid

from fastapi import APIRouter, Body, Depends, Form, HTTPException, UploadFile
from fastapi import File as FileParam
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DBSession

from ..config import BLOB_DIR, MAX_FILE_BYTES
from ..crypto import check_wrapped_dek, sha256_hex, verify_signature
from ..models import File, FileKey, User, UserKeys, get_db
from ..security import current_user
from .audit import AuditIn, append_entry
from .keys import require_keys

router = APIRouter(prefix="/files", tags=["files"])

MIN_BLOB = 12 + 16  # IV de AES-GCM + etiqueta de autenticación
HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ---------------------------------------------------------------- utilidades
def _blob_path(file_id: str, version: int) -> str:
    os.makedirs(BLOB_DIR, exist_ok=True)
    return os.path.join(BLOB_DIR, f"{file_id}.v{version}.enc")


def _write_atomic(path: str, data: bytes) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


async def _read_blob(upload: UploadFile) -> bytes:
    data = await upload.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(413, "Archivo demasiado grande")
    if len(data) < MIN_BLOB:
        raise HTTPException(400, "El blob es demasiado corto para ser IV ‖ ciphertext ‖ tag de AES-GCM")
    return data


def _check_manifest(manifest: str, signature: str, file_id: str, version: int,
                    blob: bytes, owner_keys: UserKeys) -> None:
    try:
        m = json.loads(manifest)
    except ValueError:
        raise HTTPException(400, "El manifiesto no es JSON válido")
    if not isinstance(m, dict) or m.get("id") != file_id or m.get("version") != version:
        raise HTTPException(400, "El manifiesto no coincide con el id o la versión")
    if not isinstance(m.get("sha256"), str) or not HEX64.match(m["sha256"]):
        raise HTTPException(400, "manifest.sha256 debe ser el SHA-256 del blob en hexadecimal (minúsculas)")
    if sha256_hex(blob) != m["sha256"]:
        raise HTTPException(400, "El SHA-256 del blob no coincide con el del manifiesto")
    if not verify_signature(owner_keys.sig_public_key, manifest, signature):
        raise HTTPException(400, "Firma del manifiesto inválida")


def _maybe_audit(db: DBSession, user: User, audit: AuditIn | None, action: str, file_id: str) -> bool:
    if audit is None:
        return False
    try:
        ev = json.loads(audit.event)
    except ValueError:
        raise HTTPException(400, "El evento de auditoría no es JSON válido")
    if not isinstance(ev, dict) or ev.get("action") != action or ev.get("file") != file_id:
        raise HTTPException(400, f'El evento de auditoría debe ser {{"action":"{action}","file":"{file_id}",...}}')
    append_entry(db, user, audit)
    return True


def _audit_form(raw: str | None) -> AuditIn | None:
    if not raw:
        return None
    try:
        return AuditIn(**json.loads(raw))
    except Exception:
        raise HTTPException(400, "El campo audit debe ser el JSON {event, prev_hash, entry_hash, signature}")


def _user_by_name(db: DBSession, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username.lower()))


def _get_accessible(db: DBSession, file_id: str, user: User) -> tuple[File, FileKey]:
    f = db.get(File, file_id)
    fk = db.scalar(select(FileKey).where(FileKey.file_id == file_id, FileKey.user_id == user.id)) if f else None
    if not f or not fk:
        raise HTTPException(404, "Archivo no encontrado")
    return f, fk


def _owned(db: DBSession, file_id: str, user: User) -> File:
    f = db.get(File, file_id)
    if not f or f.owner_id != user.id:
        raise HTTPException(404, "Archivo no encontrado")
    return f


# ---------------------------------------------------------------- subir / nueva versión
@router.post("/new-id")
def new_file_id(_: User = Depends(current_user)):
    """El cliente pide un id para incluirlo en el manifiesto y en los datos asociados (AD) de GCM."""
    return {"id": str(uuid.uuid4())}


@router.post("")
async def upload(file_id: str = Form(...), version: int = Form(1),
                 wrapped_dek: str = Form(..., description="DEK envuelta con TU clave pública RSA-OAEP (base64)"),
                 manifest: str = Form(..., description="JSON en texto, exactamente el que se firmó"),
                 manifest_signature: str = Form(..., description="ECDSA P-256 r‖s en base64"),
                 audit: str | None = Form(None, description='Opcional: entrada firmada {"action":"upload",...}'),
                 blob: UploadFile = FileParam(..., description="IV(12) ‖ ciphertext ‖ tag"),
                 user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """HU-05 — Sube un archivo nuevo cifrado."""
    try:
        uuid.UUID(file_id)
    except ValueError:
        raise HTTPException(400, "id inválido (debe ser un UUID de POST /files/new-id)")
    if version < 1:
        raise HTTPException(400, "La versión inicial debe ser ≥ 1")
    if db.get(File, file_id):
        raise HTTPException(409, "Ya existe; usa PUT /files/{id} para una nueva versión")
    keys = require_keys(db, user)
    data = await _read_blob(blob)
    _check_manifest(manifest, manifest_signature, file_id, version, data, keys)
    check_wrapped_dek(wrapped_dek, keys.enc_public_key)
    audited = _maybe_audit(db, user, _audit_form(audit), "upload", file_id)

    path = _blob_path(file_id, version)
    _write_atomic(path, data)
    db.add(File(id=file_id, owner_id=user.id, version=version, blob_path=path, size=len(data),
                manifest=manifest, manifest_signature=manifest_signature))
    db.add(FileKey(file_id=file_id, user_id=user.id, wrapped_dek=wrapped_dek))
    try:
        db.commit()
    except Exception:
        os.remove(path)
        raise
    return {"ok": True, "id": file_id, "version": version, "audited": audited}


WRAPPED_DEKS_DOC = 'JSON [{"username","wrapped_dek"}]; debe incluir al propietario'
AUDIT_NV_DOC = 'Opcional: entrada firmada {"action":"new_version"|"revoke",...}'


class WrappedFor(BaseModel):
    username: str
    wrapped_dek: str


@router.put("/{file_id}")
async def new_version(file_id: str, version: int = Form(...),
                      manifest: str = Form(...), manifest_signature: str = Form(...),
                      wrapped_deks: str = Form(..., description=WRAPPED_DEKS_DOC),
                      audit: str | None = Form(None, description=AUDIT_NV_DOC),
                      blob: UploadFile = FileParam(...),
                      user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """HU-06 — Nueva versión o re-cifrado tras revocar, con DEK NUEVA para quienes conservan acceso.
    Reemplaza TODAS las DEK envueltas: quien no esté en `wrapped_deks` pierde el acceso."""
    f = _owned(db, file_id, user)
    if version <= f.version:
        raise HTTPException(409, f"La versión debe ser mayor que la actual ({f.version}) (anti-rollback)")
    keys = require_keys(db, user)
    data = await _read_blob(blob)
    _check_manifest(manifest, manifest_signature, file_id, version, data, keys)
    try:
        entries = [WrappedFor(**k) for k in json.loads(wrapped_deks)]
    except Exception:
        raise HTTPException(400, 'wrapped_deks debe ser JSON [{"username": ..., "wrapped_dek": ...}]')
    recipients: dict[int, str] = {}
    for e in entries:
        u = _user_by_name(db, e.username)
        if not u:
            raise HTTPException(400, f"Usuario desconocido en wrapped_deks: {e.username}")
        check_wrapped_dek(e.wrapped_dek, require_keys(db, u).enc_public_key)
        recipients[u.id] = e.wrapped_dek
    if user.id not in recipients:
        raise HTTPException(400, "wrapped_deks debe incluir la DEK envuelta para el propietario")

    audited = False
    if audit:
        parsed = _audit_form(audit)
        action = json.loads(parsed.event).get("action") if parsed else None
        audited = _maybe_audit(db, user, parsed, action if action in ("new_version", "revoke") else "new_version",
                               file_id)

    path = _blob_path(file_id, version)
    _write_atomic(path, data)
    old_path = f.blob_path
    f.version, f.blob_path, f.size = version, path, len(data)
    f.manifest, f.manifest_signature = manifest, manifest_signature
    db.query(FileKey).filter(FileKey.file_id == file_id).delete()
    for uid, wd in recipients.items():
        db.add(FileKey(file_id=file_id, user_id=uid, wrapped_dek=wd))
    try:
        db.commit()
    except Exception:
        os.remove(path)
        raise
    if old_path != path and os.path.exists(old_path):
        os.remove(old_path)
    return {"ok": True, "version": version, "recipients": len(recipients), "audited": audited}


# ---------------------------------------------------------------- listar / descargar / eliminar
@router.get("")
def list_files(user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """HU-10 / TK-10.1 — Manifiestos de los archivos a los que el usuario tiene acceso
    (propios y compartidos con él). El cliente muestra id, versión y metadatos del manifiesto
    y puede verificar `manifest_signature` con la clave pública del propietario."""
    rows = db.execute(select(File, User.username).join(FileKey, FileKey.file_id == File.id)
                      .join(User, User.id == File.owner_id)
                      .where(FileKey.user_id == user.id)
                      .order_by(File.updated_at.desc())).all()
    return [{"id": f.id, "owner": owner, "is_owner": f.owner_id == user.id,
             "version": f.version, "size": f.size,
             "manifest": f.manifest, "manifest_signature": f.manifest_signature,
             "created_at": f.created_at.isoformat(), "updated_at": f.updated_at.isoformat()}
            for f, owner in rows]


@router.get("/{file_id}/meta")
def file_meta(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """HU-11 — Manifiesto, firma y la DEK envuelta PARA EL USUARIO que pregunta."""
    f, fk = _get_accessible(db, file_id, user)
    owner = db.get(User, f.owner_id)
    return {"id": f.id, "owner": owner.username, "version": f.version,
            "manifest": f.manifest, "manifest_signature": f.manifest_signature,
            "wrapped_dek": fk.wrapped_dek}


@router.get("/{file_id}/blob")
def file_blob(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """HU-11 — Blob cifrado (IV ‖ ciphertext ‖ tag)."""
    f, _ = _get_accessible(db, file_id, user)
    if not os.path.exists(f.blob_path):
        raise HTTPException(410, "El archivo cifrado ya no está en el almacenamiento")
    return FileResponse(f.blob_path, media_type="application/octet-stream")


@router.delete("/{file_id}")
def delete_file(file_id: str, audit: AuditIn | None = Body(default=None),
                user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """HU-10 / TK-10.2 — Elimina el archivo (solo el propietario): borra el ciphertext del
    volumen vault-object-storage, todas las DEK envueltas y el registro del archivo.
    Cuerpo opcional: entrada de auditoría firmada {"action":"delete","file":"<id>",...}."""
    f = _owned(db, file_id, user)
    audited = _maybe_audit(db, user, audit, "delete", file_id)
    blob_path = f.blob_path
    db.query(FileKey).filter(FileKey.file_id == file_id).delete()
    db.delete(f)
    db.commit()
    # El archivo físico se borra después del commit: si la BD falla, no se pierde el ciphertext
    if os.path.exists(blob_path):
        os.remove(blob_path)
    return {"ok": True, "id": file_id, "audited": audited}


# ---------------------------------------------------------------- compartir / revocar (HU-06)
class ShareIn(BaseModel):
    username: str
    wrapped_dek: str             # DEK envuelta con la clave pública (verificada por huella) del destinatario
    audit: AuditIn | None = None  # opcional: {"action":"share","file":"<id>",...}


@router.get("/{file_id}/access")
def list_access(file_id: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    _owned(db, file_id, user)
    rows = db.execute(select(User.username).join(FileKey, FileKey.user_id == User.id)
                      .where(FileKey.file_id == file_id)).scalars().all()
    return {"users": rows}


@router.post("/{file_id}/share")
def share(file_id: str, body: ShareIn, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    _owned(db, file_id, user)
    target = _user_by_name(db, body.username)
    if not target:
        raise HTTPException(404, "Destinatario no encontrado")
    if target.id == user.id:
        raise HTTPException(400, "No puedes compartir contigo mismo")
    check_wrapped_dek(body.wrapped_dek, require_keys(db, target).enc_public_key)
    audited = _maybe_audit(db, user, body.audit, "share", file_id)
    existing = db.scalar(select(FileKey).where(FileKey.file_id == file_id, FileKey.user_id == target.id))
    if existing:
        existing.wrapped_dek = body.wrapped_dek
    else:
        db.add(FileKey(file_id=file_id, user_id=target.id, wrapped_dek=body.wrapped_dek))
    db.commit()
    return {"ok": True, "audited": audited}


@router.delete("/{file_id}/share/{username}")
def revoke(file_id: str, username: str, user: User = Depends(current_user), db: DBSession = Depends(get_db)):
    """Quita la DEK envuelta del usuario. OJO: esto NO basta; si el usuario ya guardó la DEK
    puede seguir descifrando. El cliente debe a continuación subir una nueva versión con DEK
    nueva (PUT /files/{id}, evento "revoke") para que la revocación sea efectiva."""
    _owned(db, file_id, user)
    target = _user_by_name(db, username)
    if not target or target.id == user.id:
        raise HTTPException(400, "Usuario inválido")
    deleted = db.query(FileKey).filter(FileKey.file_id == file_id, FileKey.user_id == target.id).delete()
    db.commit()
    if not deleted:
        raise HTTPException(404, f"{target.username} no tenía acceso a este archivo")
    return {"ok": True, "next_step": "re-cifrar con una DEK nueva (PUT /files/{id})"}
