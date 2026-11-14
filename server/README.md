# server — vault-api-server

**Responsable: Persona 2.** API del proyecto **Bóveda de archivos compartidos con cifrado del lado del cliente y autenticación sin contraseña** (Criptografía Aplicada — UD, Alternativa B).

El servidor es **honesto pero curioso**: verifica passkeys, controla el acceso y almacena datos, pero **nunca puede descifrar nada**. Solo guarda claves públicas, claves privadas envueltas, DEK envueltas, archivos cifrados, manifiestos firmados y el log encadenado.

## Stack
- Python 3.12 + FastAPI
- `py_webauthn` para registrar y verificar passkeys
- SQLAlchemy + SQLite (`data/db/database.db`); los archivos cifrados van en `data/objects/*.enc`
- ruff + pytest (se ejecutan en el CI)

## Ejecutar
Con Docker, desde la raíz del repositorio: `docker compose up --build server`

Sin Docker, desde esta carpeta:
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```
Documentación interactiva (Swagger): http://localhost:8000/docs

Pruebas y estilo: `pytest -q` y `ruff check app tests`

## Estructura
| Ruta | Contenido |
|---|---|
| `app/api/` | Endpoints: `auth.py`, `keys.py`, `files.py`, `audit.py` |
| `app/models/` | Modelos SQLAlchemy y conexión a la BD |
| `app/security.py` | Sesiones (token opaco de 256 bits) |
| `app/config.py` | Configuración desde variables de entorno |
| `tests/` | Pruebas |

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/auth/register/options` | Reto de registro (32 B, un solo uso, expira) |
| POST | `/auth/register/verify` | Verifica la credencial y guarda su clave pública y contador → token |
| POST | `/auth/login/options` | Reto de inicio de sesión |
| POST | `/auth/login/verify` | Verifica la firma, consume el reto y actualiza el contador → token |
| PUT / GET | `/keys/me` | Guarda o lee tus claves públicas y privadas **envueltas** |
| GET | `/keys/{usuario}` | Claves **públicas** de otro usuario (el cliente debe verificar la huella) |
| POST | `/files/new-id` | Id para incluir en el manifiesto y en los datos asociados de GCM |
| POST | `/files` | Sube el archivo cifrado, la DEK envuelta y el manifiesto firmado |
| PUT | `/files/{id}` | Nueva versión o re-cifrado tras revocar (exige versión mayor: anti-rollback) |
| GET | `/files` | **HU-10.** Manifiestos de tus archivos y de los compartidos contigo: `id`, `owner`, `is_owner`, `version`, `size`, `manifest`, `manifest_signature` y fechas |
| GET | `/files/{id}/meta` | Manifiesto, firma y tu DEK envuelta |
| GET | `/files/{id}/blob` | Archivo cifrado |
| DELETE | `/files/{id}` | **HU-10.** Elimina (solo el propietario): borra el `.enc`, las DEK envueltas y el registro. Cuerpo opcional: entrada de auditoría firmada `{"action":"delete","file":id}`, que se guarda en la misma transacción |
| GET | `/files/{id}/access` | Quién tiene acceso |
| POST | `/files/{id}/share` | Compartir (DEK envuelta para el destinatario) |
| DELETE | `/files/{id}/share/{usuario}` | Revocar (luego hay que re-cifrar con DEK nueva) |
| GET | `/audit/head` | Último hash del log |
| POST | `/audit` | Agrega un evento: `h_i = SHA-256(h_{i-1} ‖ evento)` firmado por el actor |
| GET | `/audit`, `/audit/verify-chain` | Lee el log y verifica la cadena |

Autenticación: encabezado `Authorization: Bearer <token>`, con un token opaco de 256 bits que expira.

## Defensas implementadas en el servidor
- **Replay de WebAuthn:** el reto es de un solo uso y se marca como usado **antes** de verificar.
- **Phishing desde otro dominio:** se valida `expected_origin` y `expected_rp_id`.
- **Rollback:** no se acepta una versión menor o igual a la actual (además, la versión va en el manifiesto firmado).
- **Log alterado:** cada entrada debe encadenar con la cabeza actual; `/audit/verify-chain` detecta rupturas.
- **Volcado de la BD:** solo contiene material público o cifrado por el cliente.

## Secretos
El archivo `.env` (en la raíz del repositorio) está en `.gitignore`, y Gitleaks lo verifica en cada push. Nunca subas claves, contraseñas ni tokens: si aparecen en el historial de Git, el criterio C8 queda en insuficiente.

## Uso desde el front (HU-10)
Todas las rutas llevan el prefijo `/api` cuando se llaman desde el navegador.

```ts
// Listar (TK-10.1)
const files = await fetch("/api/files", { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json());
// files[i].manifest es un JSON en texto: JSON.parse(files[i].manifest) -> { id, version, name, size, sha256 }

// Eliminar con evento de auditoría firmado (TK-10.2)
const { hash } = await fetch("/api/audit/head", { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json());
const entry = await auditEntry(hash, { action: "delete", file: id, ts: new Date().toISOString() }, sigPrivateKey);
await fetch(`/api/files/${id}`, {
  method: "DELETE",
  headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
  body: JSON.stringify(entry),   // { event, prev_hash, entry_hash, signature }; también se puede omitir
});
```
`auditEntry` calcula `entry_hash = SHA-256(prev_hash ‖ event)` sobre el JSON canónico del evento y firma `entry_hash` con ECDSA P-256.
