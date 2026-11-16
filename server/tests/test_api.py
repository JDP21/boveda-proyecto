"""Pruebas de extremo a extremo con criptografía real y un autenticador WebAuthn virtual.

Ejecutar desde server/:  pytest -q
"""
import json
import os
import sqlite3

import pytest
from sim_client import VaultUser, b64, canonical_json, sign_p1363


# ---------------------------------------------------------------- básicos
def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_requiere_sesion(client):
    assert client.get("/files").status_code == 401
    assert client.get("/files", headers={"Authorization": "Bearer nope"}).status_code == 401


# ---------------------------------------------------------------- HU-03: passkeys
def test_registro_login_me_logout(client, new_user):
    u = new_user("ana", keys=False)
    assert u.req("GET", "/auth/me").json()["has_keys"] is False
    u.login()
    assert u.req("GET", "/auth/me").json()["username"] == u.username
    u.req("POST", "/auth/logout")
    u.req("GET", "/auth/me", expect=401)                      # token invalidado en el servidor


def test_usuario_duplicado(client, new_user):
    u = new_user("dup", keys=False)
    u.req("POST", "/auth/register/options", expect=409, json={"username": u.username})


def test_replay_webauthn_rechazado(client, new_user):
    """Ataque obligatorio HU-08: reenviar una respuesta WebAuthn capturada."""
    u = new_user("replay", keys=False)
    capturada = u.login()
    r = client.post("/auth/login/verify", json={"username": u.username, "credential": capturada})
    assert r.status_code == 400 and "utilizado" in r.json()["detail"]


def test_origen_distinto_rechazado(client):
    """Phishing: la respuesta viene firmada desde otro origen."""
    u = VaultUser(client, "phish1").register()
    opts = u.req("POST", "/auth/login/options", json={"username": u.username}).json()
    cred = u.authenticator.get(opts, origin="https://evil.example")
    r = client.post("/auth/login/verify", json={"username": u.username, "credential": cred})
    assert r.status_code == 401


def test_origen_vite_aceptado(client):
    u = VaultUser(client, "vite1", origin="http://localhost:5173").register()
    u.login()


def test_contador_de_firmas(client, new_user):
    """Un autenticador clonado (contador que retrocede) es rechazado."""
    u = new_user("clon", keys=False)
    u.login()
    u.authenticator.sign_count = 0
    opts = u.req("POST", "/auth/login/options", json={"username": u.username}).json()
    r = client.post("/auth/login/verify", json={"username": u.username, "credential": u.authenticator.get(opts)})
    assert r.status_code == 401


# ---------------------------------------------------------------- HU-04: claves
def test_politica_de_claves(client, new_user):
    u = new_user("pol", keys=False)
    debil = u.generate_keys(rsa_bits=2048)
    assert "3072" in u.req("PUT", "/keys/me", expect=400, json=debil).json()["detail"]
    ok = u.generate_keys()
    assert u.req("PUT", "/keys/me", json=ok).json() == {"ok": True, "rotated": False}
    assert u.req("PUT", "/keys/me", json=u.generate_keys()).json()["rotated"] is True
    otro = new_user("pol")
    pub = otro.req("GET", f"/keys/{u.username}").json()
    assert "wrapped_private_keys" not in pub and "kdf_salt" not in pub


# ---------------------------------------------------------------- HU-05 / HU-11: subir y descargar
def test_subir_y_descargar(client, new_user):
    a = new_user("alice")
    fid = a.upload("informe.txt", b"contenido secreto")
    data, m = a.download(fid)
    assert data == b"contenido secreto" and m["name"] == "informe.txt"


def test_subida_requiere_claves(client, new_user):
    u = new_user("sinclaves", keys=False)
    fid = u.req("POST", "/files/new-id").json()["id"]
    u.req("POST", "/files", expect=409, data={"file_id": fid, "wrapped_dek": "x", "manifest": "{}",
                                              "manifest_signature": "x"}, files={"blob": ("b", b"0" * 40)})


@pytest.mark.parametrize("ataque", ["hash", "firma", "dek", "version"])
def test_subida_rechaza_datos_manipulados(client, new_user, ataque):
    a = new_user("manip")
    fid = a.req("POST", "/files/new-id").json()["id"]
    dek, blob, manifest, sig = a.encrypt(fid, 1, "x.txt", b"hola")
    wrapped = a.wrap(dek, a.req("GET", "/keys/me").json()["enc_public_key"])
    if ataque == "hash":
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    elif ataque == "firma":
        sig = sign_p1363(new_user("mallory").sig_key, manifest)
    elif ataque == "dek":
        wrapped = b64(os.urandom(256))
    elif ataque == "version":
        manifest = manifest.replace('"version":1', '"version":2')
    a.req("POST", "/files", expect=400, data={"file_id": fid, "version": "1", "wrapped_dek": wrapped,
                                              "manifest": manifest, "manifest_signature": sig},
          files={"blob": ("b", blob)})


def test_blob_alterado_en_disco_es_detectado(client, new_user, tmp_paths):
    """Ataque obligatorio HU-08: modificar un byte del ciphertext almacenado."""
    a = new_user("tamper")
    fid = a.upload("x.txt", b"datos importantes")
    path = os.path.join(tmp_paths["objects"], f"{fid}.v1.enc")
    raw = bytearray(open(path, "rb").read())
    raw[20] ^= 1
    open(path, "wb").write(raw)
    with pytest.raises(ValueError, match="Hash"):
        a.download(fid)


def test_volcado_bd_no_revela_contenido(client, new_user, tmp_paths):
    """Ataque obligatorio HU-08: el volcado de BD y almacenamiento solo tiene material cifrado."""
    secreto = b"NUMERO-DE-CUENTA-1234567890"
    a = new_user("dump")
    a.upload("secreto.txt", secreto)
    dump = b"\n".join(str(row).encode() for table in
                      ["users", "credentials", "user_keys", "files", "file_keys", "audit_log"]
                      for row in sqlite3.connect(tmp_paths["db"]).execute(f"SELECT * FROM {table}"))
    blobs = b"".join(open(os.path.join(tmp_paths["objects"], f), "rb").read()
                     for f in os.listdir(tmp_paths["objects"]))
    assert secreto not in dump and secreto not in blobs
    assert b"PRIVATE KEY" not in dump


# ---------------------------------------------------------------- HU-06: compartir y revocar
def test_compartir_revocar_y_rollback(client, new_user):
    a, b, c = new_user("owner"), new_user("bob"), new_user("carol")
    fid = a.upload("plan.txt", b"v1")
    a.share(fid, b.username)
    a.share(fid, c.username)
    assert b.download(fid)[0] == b"v1"
    meta_v1 = b.req("GET", f"/files/{fid}/meta").json()

    version = a.revoke(fid, b.username)
    assert version == 2
    b.req("GET", f"/files/{fid}/meta", expect=404)                 # bob sin acceso
    assert c.download(fid)[0] == b"v1"                            # carol conserva acceso con DEK nueva
    assert c.req("GET", f"/files/{fid}/meta").json()["wrapped_dek"] != meta_v1["wrapped_dek"]

    # El servidor rechaza volver a una versión anterior
    dek, blob, manifest, sig = a.encrypt(fid, 1, "plan.txt", b"viejo")
    mio = a.wrap(dek, a.req("GET", "/keys/me").json()["enc_public_key"])
    a.req("PUT", f"/files/{fid}", expect=409, data={
        "version": "1", "manifest": manifest, "manifest_signature": sig,
        "wrapped_deks": json.dumps([{"username": a.username, "wrapped_dek": mio}])},
        files={"blob": ("b", blob)})


def test_nueva_version_debe_incluir_al_propietario(client, new_user):
    a, b = new_user("own2"), new_user("bob2")
    fid = a.upload("x.txt", b"1")
    dek, blob, manifest, sig = a.encrypt(fid, 2, "x.txt", b"2")
    pub_bob = b.trusted_public_keys(b.username)["enc_public_key"]
    solo_bob = [{"username": b.username, "wrapped_dek": a.wrap(dek, pub_bob)}]
    a.req("PUT", f"/files/{fid}", expect=400, data={"version": "2", "manifest": manifest, "manifest_signature": sig,
                                                    "wrapped_deks": json.dumps(solo_bob)}, files={"blob": ("b", blob)})


def test_cambio_de_huella_detectado(client, new_user):
    """El servidor sustituye la clave pública del destinatario (MITM): el cliente lo detecta."""
    a, b = new_user("vic"), new_user("dest")
    a.trusted_public_keys(b.username)                             # huella verificada por canal externo
    b.upload_keys()                                               # la clave "cambia"
    fid = a.upload("x.txt", b"1")
    with pytest.raises(PermissionError, match="CAMBIÓ"):
        a.share(fid, b.username)


def test_compartir_requiere_claves_del_destinatario(client, new_user):
    a, sin = new_user("own3"), new_user("nokeys", keys=False)
    fid = a.upload("x.txt", b"1")
    a.req("POST", f"/files/{fid}/share", expect=409, json={"username": sin.username, "wrapped_dek": "AAAA"})


# ---------------------------------------------------------------- HU-10: listar y eliminar
def test_listar_y_aislamiento(client, new_user):
    a, b = new_user("lst"), new_user("lst")
    fid = a.upload("informe.pdf", b"pdf")
    item = next(x for x in a.req("GET", "/files").json() if x["id"] == fid)
    assert item["is_owner"] and item["version"] == 1 and json.loads(item["manifest"])["name"] == "informe.pdf"
    assert all(x["id"] != fid for x in b.req("GET", "/files").json())
    a.share(fid, b.username)
    item_b = next(x for x in b.req("GET", "/files").json() if x["id"] == fid)
    assert item_b["is_owner"] is False and item_b["owner"] == a.username


def test_eliminar_purga_y_audita(client, new_user, tmp_paths):
    a, b = new_user("del"), new_user("del")
    fid = a.upload("x.txt", b"borrar")
    path = os.path.join(tmp_paths["objects"], f"{fid}.v1.enc")
    b.req("DELETE", f"/files/{fid}", expect=404)                  # solo el propietario
    mal = a.audit_entry("upload", file=fid)
    a.req("DELETE", f"/files/{fid}", expect=400, json=mal)        # evento equivocado: no borra
    assert os.path.exists(path)
    assert a.delete(fid)["audited"] is True
    assert not os.path.exists(path)
    a.req("GET", f"/files/{fid}/meta", expect=404)
    last = a.req("GET", "/audit").json()[-1]
    assert json.loads(last["event"]) == {"action": "delete", "actor": a.username, "file": fid}


# ---------------------------------------------------------------- HU-07: auditoría
def test_auditoria_firma_y_cadena(client, new_user, tmp_paths):
    a, mallory = new_user("aud"), new_user("mal")
    entry = a.audit_entry("download", file="x")
    forjada = dict(entry, signature=sign_p1363(mallory.sig_key, entry["entry_hash"]))
    a.req("POST", "/audit", expect=400, json=forjada)              # firma de otro: rechazada
    a.req("POST", "/audit", json=entry)
    a.req("POST", "/audit", expect=409, json=entry)                # prev_hash viejo: rechazado
    assert a.req("GET", "/audit/verify-chain").json()["ok"] is True

    con = sqlite3.connect(tmp_paths["db"])                         # el servidor altera una entrada vieja
    seq = con.execute("SELECT min(seq) FROM audit_log").fetchone()[0]
    con.execute("UPDATE audit_log SET event=? WHERE seq=?", (canonical_json({"action": "keys"}), seq))
    con.commit()
    r = a.req("GET", "/audit/verify-chain").json()
    assert r == {"ok": False, "broken_at": seq, "reason": "hash"}
