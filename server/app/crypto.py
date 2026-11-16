"""Validaciones criptográficas del lado del servidor (biblioteca `cryptography`, permitida).

El servidor NUNCA descifra: solo comprueba que lo que recibe cumple la política
(tamaños de clave, curvas) y que las firmas son válidas. Así rechaza basura o
manipulaciones antes de guardarlas, aunque el cliente vuelve a verificar todo al
descargar (no confía en el servidor).

Formatos (deben coincidir con la Web Crypto API del navegador):
- Claves públicas: SPKI DER en base64 (crypto.subtle.exportKey("spki", ...)).
- Firmas ECDSA P-256/SHA-256: formato IEEE P1363 = r ‖ s (64 bytes) en base64, que es lo
  que devuelve crypto.subtle.sign({name:"ECDSA", hash:"SHA-256"}, ...). Se firma el texto
  UTF-8 exacto (manifiesto JSON o entry_hash en hexadecimal).
- DEK envuelta: salida de RSA-OAEP(SHA-256) en base64; su longitud es la del módulo (384 B en 3072 bits).
"""
import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import HTTPException

from .config import MIN_RSA_BITS


def b64decode_strict(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(400, f"{what}: base64 inválido")


def load_rsa_oaep_public(spki_b64: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_der_public_key(b64decode_strict(spki_b64, "enc_public_key"))
    except ValueError:
        raise HTTPException(400, "enc_public_key: no es una clave SPKI válida")
    if not isinstance(key, rsa.RSAPublicKey):
        raise HTTPException(400, "enc_public_key debe ser RSA (RSA-OAEP)")
    if key.key_size < MIN_RSA_BITS:
        raise HTTPException(400, f"enc_public_key: RSA de {key.key_size} bits; se exige ≥ {MIN_RSA_BITS}")
    if key.public_numbers().e != 65537:
        raise HTTPException(400, "enc_public_key: el exponente público debe ser 65537")
    return key


def load_ecdsa_p256_public(spki_b64: str) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_der_public_key(b64decode_strict(spki_b64, "sig_public_key"))
    except ValueError:
        raise HTTPException(400, "sig_public_key: no es una clave SPKI válida")
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise HTTPException(400, "sig_public_key debe ser ECDSA sobre la curva P-256")
    return key


def verify_signature(sig_public_key_b64: str, message: str, signature_b64: str) -> bool:
    """Verifica una firma ECDSA P-256/SHA-256 en formato P1363 (r‖s) sobre el texto UTF-8."""
    try:
        key = load_ecdsa_p256_public(sig_public_key_b64)
        raw = base64.b64decode(signature_b64, validate=True)
    except (HTTPException, binascii.Error, ValueError):
        return False
    if len(raw) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        key.verify(der, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def check_wrapped_dek(wrapped_b64: str, enc_public_key_b64: str) -> None:
    """La DEK envuelta con RSA-OAEP debe medir exactamente lo que mide el módulo RSA del destinatario."""
    size = load_rsa_oaep_public(enc_public_key_b64).key_size // 8
    if len(b64decode_strict(wrapped_b64, "wrapped_dek")) != size:
        raise HTTPException(400, f"wrapped_dek debe medir {size} bytes (RSA-OAEP con la clave del destinatario)")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
