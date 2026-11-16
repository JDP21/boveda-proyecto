"""Demostración del flujo completo contra un servidor corriendo (útil para la demo E2 y para
comprobar que Docker quedó bien montado).

Uso (desde server/, con las dependencias de requirements-dev.txt instaladas):
    python scripts/demo_e2e.py                                  # API directa en http://localhost:8000
    python scripts/demo_e2e.py http://localhost:8080/api        # a través de nginx (cliente)

El ORIGIN configurado en el servidor debe incluir el origen que usa la demo
(por defecto http://localhost:8080; se cambia con --origin).
"""
import argparse
import sys
import time

import httpx
from sim_client import VaultUser


def step(msg: str) -> None:
    print(f"\033[1;34m▶\033[0m {msg}")


def ok(msg: str) -> None:
    print(f"  \033[32m✔\033[0m {msg}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base_url", nargs="?", default="http://localhost:8000")
    ap.add_argument("--origin", default="http://localhost:8080")
    ap.add_argument("--rp-id", default="localhost")
    args = ap.parse_args()

    http = httpx.Client(base_url=args.base_url.rstrip("/"), timeout=60)
    http.get("/health").raise_for_status()
    sufijo = str(int(time.time()))[-6:]
    mk = lambda n: VaultUser(http, f"{n}{sufijo}", rp_id=args.rp_id, origin=args.origin)  # noqa: E731

    step("HU-03 Registro e inicio de sesión con passkey (autenticador virtual)")
    alice, bob = mk("alice").register(), mk("bob").register()
    capturada = alice.login()
    ok(f"{alice.username} y {bob.username} registrados; login correcto")
    r = http.post("/auth/login/verify", json={"username": alice.username, "credential": capturada})
    ok(f"Replay de la respuesta WebAuthn rechazado ({r.status_code}: {r.json()['detail']})")

    step("HU-04 Claves RSA-OAEP 3072 + ECDSA P-256, privadas envueltas con Argon2id → AES-256-GCM")
    alice.upload_keys()
    bob.upload_keys()
    ok(f"Huella de {bob.username}: {bob.fingerprint}")

    step("HU-05 Cifrado de sobre y manifiesto firmado")
    fid = alice.upload("informe.txt", "Contenido confidencial de la bóveda".encode())
    ok(f"Subido archivo {fid}")

    step("HU-10 Listar archivos")
    for f in alice.req("GET", "/files").json():
        ok(f"{f['id'][:8]}… v{f['version']} {f['size']} B propietario={f['owner']}")

    step("HU-06 Compartir con verificación de huella y descarga verificada (HU-11)")
    alice.share(fid, bob.username)
    data, m = bob.download(fid)
    ok(f"{bob.username} verificó firma + SHA-256 + GCM y leyó: {data.decode()!r}")

    step("HU-06 Revocar con re-cifrado (DEK nueva)")
    v = alice.revoke(fid, bob.username)
    r = bob.http.get(f"/files/{fid}/meta", headers=bob._h())
    ok(f"Archivo en versión {v}; {bob.username} ya no tiene acceso ({r.status_code})")

    step("HU-07 Log de auditoría encadenado y firmado")
    chain = alice.req("GET", "/audit/verify-chain").json()
    ok(f"Cadena íntegra: {chain}")

    step("HU-10 Eliminar con evento de auditoría")
    ok(f"{alice.delete(fid)}")
    print("\n\033[1;32mFlujo completo OK\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
