"""Cliente simulado de la bóveda: hace en Python exactamente lo que hará el navegador.

Sirve para tres cosas:
  1. Pruebas de extremo a extremo del servidor (tests/), con criptografía REAL.
  2. Demostrar el flujo completo contra un servidor corriendo (scripts/demo_e2e.py).
  3. Referencia para el front: los formatos de cada campo son los mismos que produce la
     Web Crypto API (SPKI base64, firmas ECDSA r‖s, JSON canónico, IV ‖ ciphertext ‖ tag).

Incluye un autenticador WebAuthn virtual (credencial ES256, attestation "none") que sustituye
a navigator.credentials.create()/get() del navegador.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass, field

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
ARGON2 = {"alg": "argon2id", "m": 65536, "t": 3, "p": 1}


# ---------------------------------------------------------------- formatos
def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.b64decode(data)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def canonical_json(obj) -> str:
    """Igual que canonicalJSON() del cliente: claves ordenadas, sin espacios, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign_p1363(key: ec.EllipticCurvePrivateKey, text: str) -> str:
    """ECDSA P-256/SHA-256 en formato r‖s (64 B), como crypto.subtle.sign del navegador."""
    r, s = decode_dss_signature(key.sign(text.encode("utf-8"), ec.ECDSA(hashes.SHA256())))
    return b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def verify_p1363(pub: ec.EllipticCurvePublicKey, text: str, sig_b64: str) -> bool:
    raw = unb64(sig_b64)
    try:
        pub.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   text.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def spki(pub) -> str:
    return b64(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def fingerprint(enc_spki_b64: str, sig_spki_b64: str) -> str:
    h = hashlib.sha256(unb64(enc_spki_b64) + unb64(sig_spki_b64)).hexdigest().upper()
    return " ".join(h[i:i + 4] for i in range(0, 64, 4))


# ---------------------------------------------------------------- autenticador WebAuthn virtual
@dataclass
class VirtualAuthenticator:
    rp_id: str = "localhost"
    origin: str = "http://localhost:8080"
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    sign_count: int = 0

    def _client_data(self, typ: str, challenge_b64url: str, origin: str | None) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge_b64url, "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def _rp_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest()

    def create(self, options: dict, origin: str | None = None) -> dict:
        """Equivale a navigator.credentials.create() + startRegistration()."""
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        attested = bytes(16) + struct.pack(">H", len(self.credential_id)) + self.credential_id + cose
        auth_data = self._rp_hash() + bytes([0x45]) + struct.pack(">I", self.sign_count) + attested  # UP|UV|AT
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = b64url(self.credential_id)
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        return {"id": cid, "rawId": cid, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64url(client_data),
                             "attestationObject": b64url(att_obj), "transports": ["internal"]}}

    def get(self, options: dict, origin: str | None = None) -> dict:
        """Equivale a navigator.credentials.get() + startAuthentication()."""
        self.sign_count += 1
        auth_data = self._rp_hash() + bytes([0x05]) + struct.pack(">I", self.sign_count)  # UP|UV
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        cid = b64url(self.credential_id)
        return {"id": cid, "rawId": cid, "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64url(client_data), "authenticatorData": b64url(auth_data),
                             "signature": b64url(sig), "userHandle": None}}


# ---------------------------------------------------------------- usuario con sus claves
class VaultUser:
    """Un usuario del navegador: passkey + claves RSA-OAEP 3072 / ECDSA P-256 + sesión."""

    def __init__(self, http, username: str, prefix: str = "", rp_id: str = "localhost",
                 origin: str = "http://localhost:8080"):
        self.http, self.username, self.prefix = http, username, prefix
        self.authenticator = VirtualAuthenticator(rp_id=rp_id, origin=origin)
        self.token: str | None = None
        self.enc_key: rsa.RSAPrivateKey | None = None
        self.sig_key: ec.EllipticCurvePrivateKey | None = None
        self.seen_versions: dict[str, int] = {}
        self.trusted: dict[str, str] = {}  # username -> huella verificada por canal externo

    # -- HTTP
    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def req(self, method: str, path: str, expect: int = 200, **kw):
        r = self.http.request(method, self.prefix + path, headers=self._h(), **kw)
        if r.status_code != expect:
            raise AssertionError(f"{method} {path} -> {r.status_code} (esperado {expect}): {r.text}")
        return r

    # -- HU-03: passkeys
    def register(self):
        opts = self.req("POST", "/auth/register/options", json={"username": self.username}).json()
        cred = self.authenticator.create(opts)
        self.token = self.req("POST", "/auth/register/verify",
                              json={"username": self.username, "credential": cred}).json()["token"]
        return self

    def login(self):
        opts = self.req("POST", "/auth/login/options", json={"username": self.username}).json()
        cred = self.authenticator.get(opts)
        self.token = self.req("POST", "/auth/login/verify",
                              json={"username": self.username, "credential": cred}).json()["token"]
        return cred

    # -- HU-04: claves
    def generate_keys(self, phrase: str = "frase de recuperacion de prueba", rsa_bits: int = 3072):
        self.enc_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        self.sig_key = ec.generate_private_key(ec.SECP256R1())
        salt = os.urandom(16)
        kek = Argon2id(salt=salt, length=32, iterations=ARGON2["t"], lanes=ARGON2["p"],
                       memory_cost=ARGON2["m"]).derive(phrase.encode())
        privs = json.dumps({
            "enc": b64(self.enc_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption())),
            "sig": b64(self.sig_key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))}).encode()
        iv = os.urandom(12)
        ct = AESGCM(kek).encrypt(iv, privs, b"user-private-keys")
        return {"enc_public_key": spki(self.enc_key.public_key()), "sig_public_key": spki(self.sig_key.public_key()),
                "wrapped_private_keys": json.dumps({"iv": b64(iv), "ct": b64(ct)}),
                "kdf_salt": b64(salt), "kdf_params": json.dumps(ARGON2)}

    def upload_keys(self, **kw):
        return self.req("PUT", "/keys/me", json=self.generate_keys(**kw)).json()

    @property
    def fingerprint(self) -> str:
        return fingerprint(spki(self.enc_key.public_key()), spki(self.sig_key.public_key()))

    def trusted_public_keys(self, username: str) -> dict:
        """Obtiene claves públicas ajenas y exige que la huella coincida con la verificada."""
        pk = self.req("GET", f"/keys/{username}").json()
        fp = fingerprint(pk["enc_public_key"], pk["sig_public_key"])
        if username in self.trusted and self.trusted[username] != fp:
            raise PermissionError(f"La huella de {username} CAMBIÓ: posible sustitución de clave")
        self.trusted.setdefault(username, fp)
        return pk

    # -- HU-07: auditoría
    def audit_entry(self, action: str, **fields) -> dict:
        head = self.req("GET", "/audit/head").json()["hash"]
        event = canonical_json({"action": action, "actor": self.username, **fields})
        entry_hash = hashlib.sha256(bytes.fromhex(head) + event.encode()).hexdigest()
        return {"event": event, "prev_hash": head, "entry_hash": entry_hash,
                "signature": sign_p1363(self.sig_key, entry_hash)}

    # -- HU-05: cifrado de sobre
    def encrypt(self, file_id: str, version: int, name: str, data: bytes):
        dek, iv = os.urandom(32), os.urandom(12)
        blob = iv + AESGCM(dek).encrypt(iv, data, f"{file_id}|{version}".encode())
        manifest = canonical_json({"id": file_id, "version": version, "name": name, "size": len(data),
                                   "sha256": hashlib.sha256(blob).hexdigest()})
        return dek, blob, manifest, sign_p1363(self.sig_key, manifest)

    @staticmethod
    def wrap(dek: bytes, enc_public_spki_b64: str) -> str:
        pub = serialization.load_der_public_key(unb64(enc_public_spki_b64))
        return b64(pub.encrypt(dek, OAEP))

    def upload(self, name: str, data: bytes, audit: bool = True) -> str:
        file_id = self.req("POST", "/files/new-id").json()["id"]
        dek, blob, manifest, sig = self.encrypt(file_id, 1, name, data)
        form = {"file_id": file_id, "version": "1", "manifest": manifest, "manifest_signature": sig,
                "wrapped_dek": self.wrap(dek, spki(self.enc_key.public_key()))}
        if audit:
            form["audit"] = json.dumps(self.audit_entry("upload", file=file_id, version=1))
        self.req("POST", "/files", data=form, files={"blob": ("blob.enc", blob, "application/octet-stream")})
        return file_id

    # -- HU-11: descarga verificada
    def download(self, file_id: str) -> tuple[bytes, dict]:
        meta = self.req("GET", f"/files/{file_id}/meta").json()
        blob = self.req("GET", f"/files/{file_id}/blob").content
        owner = self.trusted_public_keys(meta["owner"]) if meta["owner"] != self.username else \
            {"sig_public_key": spki(self.sig_key.public_key())}
        owner_sig = serialization.load_der_public_key(unb64(owner["sig_public_key"]))
        if not verify_p1363(owner_sig, meta["manifest"], meta["manifest_signature"]):
            raise ValueError("Firma del manifiesto inválida")
        m = json.loads(meta["manifest"])
        if m["id"] != meta["id"] or m["version"] != meta["version"]:
            raise ValueError("Manifiesto no corresponde al archivo")
        if m["version"] < self.seen_versions.get(file_id, 0):
            raise ValueError("Rollback detectado")
        if hashlib.sha256(blob).hexdigest() != m["sha256"]:
            raise ValueError("Hash no coincide: archivo modificado")
        dek = self.enc_key.decrypt(unb64(meta["wrapped_dek"]), OAEP)
        data = AESGCM(dek).decrypt(blob[:12], blob[12:], f"{m['id']}|{m['version']}".encode())
        self.seen_versions[file_id] = m["version"]
        return data, m

    # -- HU-06: compartir y revocar
    def share(self, file_id: str, username: str) -> dict:
        pk = self.trusted_public_keys(username)
        meta = self.req("GET", f"/files/{file_id}/meta").json()
        dek = self.enc_key.decrypt(unb64(meta["wrapped_dek"]), OAEP)
        return self.req("POST", f"/files/{file_id}/share", json={
            "username": username, "wrapped_dek": self.wrap(dek, pk["enc_public_key"]),
            "audit": self.audit_entry("share", file=file_id, to=username)}).json()

    def revoke(self, file_id: str, username: str) -> int:
        """Quita el acceso y RE-CIFRA con una DEK nueva para quienes lo conservan."""
        self.req("DELETE", f"/files/{file_id}/share/{username}")
        data, m = self.download(file_id)
        version = m["version"] + 1
        dek, blob, manifest, sig = self.encrypt(file_id, version, m["name"], data)
        users = self.req("GET", f"/files/{file_id}/access").json()["users"]
        wrapped = []
        for u in users:
            if u == self.username:
                pub = spki(self.enc_key.public_key())
            else:
                pub = self.trusted_public_keys(u)["enc_public_key"]
            wrapped.append({"username": u, "wrapped_dek": self.wrap(dek, pub)})
        self.req("PUT", f"/files/{file_id}", data={
            "version": str(version), "manifest": manifest, "manifest_signature": sig,
            "wrapped_deks": json.dumps(wrapped),
            "audit": json.dumps(self.audit_entry("revoke", file=file_id, user=username, version=version))},
            files={"blob": ("blob.enc", blob, "application/octet-stream")})
        return version

    def delete(self, file_id: str) -> dict:
        return self.req("DELETE", f"/files/{file_id}", json=self.audit_entry("delete", file=file_id)).json()
