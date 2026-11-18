"""Ataque 3: se captura una respuesta WebAuthn válida y se reenvía. Esperado: rechazo."""
import pathlib
import sys
import time

import httpx

sys.path.insert(0, "server/scripts")
from sim_client import VaultUser

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
http = httpx.Client(base_url=BASE)
u = VaultUser(http, f"victima{int(time.time())}").register()
capturada = u.login()
r = http.post("/auth/login/verify", json={"username": u.username, "credential": capturada})
OUT = pathlib.Path("attacks/evidencias")
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "05_replay_webauthn.txt").write_text(
    f"Reenvío de la respuesta capturada -> HTTP {r.status_code}: {r.text}\n",
    encoding="utf-8",
)
print(r.status_code, r.json())
