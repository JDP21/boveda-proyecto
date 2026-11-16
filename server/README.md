# server — vault-api-server

**Responsable: Persona 2 (Jonathan Yasno).** API de la bóveda (Alternativa B).

El servidor es **honesto pero curioso**: verifica passkeys, controla el acceso y almacena, pero **nunca puede descifrar**. Aun así, **valida todo lo que recibe** antes de guardarlo:
- política de claves (RSA-OAEP ≥ 3072 bits, ECDSA P-256);
- firma del manifiesto y SHA-256 del blob;
- tamaño de cada DEK envuelta;
- firma y encadenamiento del log;
- versiones crecientes.

## Stack
- Python 3.12 + FastAPI
- `py_webauthn` (passkeys) y `cryptography` (validación de claves y firmas), ambas permitidas por el enunciado
- SQLAlchemy + SQLite (`data/db/database.db`); archivos cifrados en `data/objects/*.enc`
- ruff + pytest

## Ejecutar
Con Docker, desde la raíz del repositorio:
```bash
cp .env.example .env
docker compose up --build server        # Swagger en http://localhost:8000/docs
```
Sin Docker, desde `server/`:
```bash
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --port 8000
```

**Comprobar que todo funciona** con el servidor arriba (registro, claves, subir, compartir, descargar, revocar, auditoría y eliminar, con criptografía real y una passkey virtual):
```bash
python scripts/demo_e2e.py                              # contra http://localhost:8000
python scripts/demo_e2e.py http://localhost:8080/api    # pasando por nginx
```

Pruebas y estilo: `pytest -q` (24 pruebas de extremo a extremo) y `ruff check app tests scripts`

> Si actualizas desde una versión anterior y el servidor falla al arrancar, borra `data/db/database.db`: el esquema cambió (columna `signer_key` del log).

## Estructura
| Ruta | Contenido |
|---|---|
| `app/api/auth.py` | HU-03: registro e inicio de sesión con passkeys, `/auth/me`, `/auth/logout` |
| `app/api/keys.py` | HU-04: claves públicas y privadas envueltas |
| `app/api/files.py` | HU-05, 06, 10 y 11: subir, versiones, listar, descargar, eliminar, compartir y revocar |
| `app/api/audit.py` | HU-07: log encadenado y firmado |
| `app/crypto.py` | Validación de claves, firmas ECDSA y DEK envueltas |
| `app/models/` | Modelos SQLAlchemy |
| `app/security.py` | Sesiones (token opaco de 256 bits) |
| `scripts/sim_client.py` | **Cliente de referencia en Python**: hace lo mismo que debe hacer el navegador |
| `scripts/demo_e2e.py` | Demostración del flujo completo contra un servidor vivo |
| `tests/` | Pruebas de extremo a extremo |

---

## Contrato para el front
Desde el navegador todas las rutas llevan el prefijo **`/api`** (nginx o el proxy de Vite lo quitan). Todas, salvo las de registro e inicio de sesión, llevan el encabezado `Authorization: Bearer <token>`. Los errores llegan como `{"detail": "mensaje"}`.

### Formatos (deben coincidir exactamente)
| Dato | Formato | Cómo se obtiene con Web Crypto |
|---|---|---|
| Clave pública | SPKI DER en **base64** | `exportKey("spki", key)` |
| Firma | ECDSA P-256/SHA-256 **r‖s (64 bytes)** en base64, sobre el **texto UTF-8 exacto** | `sign({name:"ECDSA",hash:"SHA-256"}, priv, new TextEncoder().encode(texto))` |
| DEK envuelta | RSA-OAEP/SHA-256 en base64 (384 bytes con RSA-3072) | `encrypt({name:"RSA-OAEP"}, pubDestinatario, dekRaw)` |
| Blob | `IV (12 B) ‖ ciphertext ‖ tag` | `encrypt({name:"AES-GCM", iv, additionalData: "id\|version"}, dek, archivo)` y concatenar el IV delante |
| Manifiesto | **JSON canónico** (claves ordenadas, sin espacios) con `id`, `version` y `sha256` (hex en minúsculas **del blob completo**), más metadatos libres (`name`, `size`…) | Se firma y se envía **el mismo string** |
| Evento de log | JSON canónico con `action` ∈ {register, keys, upload, new_version, download, share, revoke, delete} | `entry_hash = SHA-256(bytes(prev_hash) ‖ UTF-8(event))` en hex; se firma el **string hex** de `entry_hash` |

`scripts/sim_client.py` implementa todos estos formatos y sirve de referencia: sus funciones se corresponden una a una con lo que debe hacer el front.

### Endpoints
| Método | Ruta | Cuerpo | Respuesta / notas |
|---|---|---|---|
| POST | `/auth/register/options` | `{username}` | Opciones para `startRegistration({optionsJSON})` |
| POST | `/auth/register/verify` | `{username, credential}` | `{token}`; `credential` es lo que devuelve `startRegistration` |
| POST | `/auth/login/options` | `{username}` | Opciones para `startAuthentication({optionsJSON})` |
| POST | `/auth/login/verify` | `{username, credential}` | `{token}` |
| GET | `/auth/me` | — | `{username, has_keys, created_at}`: si `has_keys` es false, el front debe generar las claves |
| POST | `/auth/logout` | — | Invalida el token |
| PUT | `/keys/me` | `{enc_public_key, sig_public_key, wrapped_private_keys, kdf_salt, kdf_params}` | `{rotated}`; `wrapped_private_keys` = JSON `{"iv","ct"}` (IV de 12 B); `kdf_params.alg` = `argon2id` o `pbkdf2` |
| GET | `/keys/me` | — | Lo anterior, para desbloquear con la frase |
| GET | `/keys/{usuario}` | — | `{enc_public_key, sig_public_key, updated_at}`: **verificar la huella antes de usarlas** |
| POST | `/files/new-id` | — | `{id}` (UUID que va en el manifiesto y en el AD de GCM) |
| POST | `/files` | multipart: `file_id, version=1, wrapped_dek, manifest, manifest_signature, blob, audit?` | Subida (HU-05) |
| PUT | `/files/{id}` | multipart: `version, manifest, manifest_signature, wrapped_deks, blob, audit?` | Nueva versión o re-cifrado (HU-06). `wrapped_deks` = JSON `[{username, wrapped_dek}]` **con el propietario incluido**; reemplaza todos los accesos |
| GET | `/files` | — | **HU-10.** `[{id, owner, is_owner, version, size, manifest, manifest_signature, created_at, updated_at}]` |
| GET | `/files/{id}/meta` | — | **HU-11.** `{owner, version, manifest, manifest_signature, wrapped_dek}` (la DEK envuelta **para ti**) |
| GET | `/files/{id}/blob` | — | Blob cifrado (`arrayBuffer()`) |
| DELETE | `/files/{id}` | JSON opcional: entrada de log `delete` | **HU-10.** Borra el `.enc`, las DEK envueltas y el registro |
| GET | `/files/{id}/access` | — | `{users}` con acceso (solo el propietario) |
| POST | `/files/{id}/share` | `{username, wrapped_dek, audit?}` | Compartir (HU-06) |
| DELETE | `/files/{id}/share/{usuario}` | — | Revocar; **después** hay que hacer `PUT /files/{id}` con una DEK nueva |
| GET | `/audit/head` | — | `{seq, hash}`: cabeza actual para encadenar |
| POST | `/audit` | `{event, prev_hash, entry_hash, signature}` | Agrega una entrada (HU-07) |
| GET | `/audit` | — | Log completo con `signer_key`, para verificarlo en el navegador |
| GET | `/audit/verify-chain` | — | `{ok, entries}` o `{ok:false, broken_at, reason}` |

El campo `audit?` es opcional en todas las operaciones que modifican. Si se envía, el evento queda en el log **en la misma transacción** que la operación. En los formularios multipart va como un string JSON.

### Ejemplo: listar y eliminar (HU-10)
```ts
const auth = { Authorization: `Bearer ${token}` };
const files = await fetch("/api/files", { headers: auth }).then(r => r.json());
// JSON.parse(files[i].manifest) -> { id, version, name, size, sha256 }

const { hash } = await fetch("/api/audit/head", { headers: auth }).then(r => r.json());
const entry = await auditEntry(hash, { action: "delete", file: id }, sigPrivateKey);
await fetch(`/api/files/${id}`, { method: "DELETE", headers: { ...auth, "Content-Type": "application/json" },
                                  body: JSON.stringify(entry) });
```

---

## Defensas del servidor
| Ataque | Defensa | Prueba |
|---|---|---|
| Replay de una respuesta WebAuthn | Reto de 32 B de un solo uso, que se marca como usado **antes** de verificar | `test_replay_webauthn_rechazado` |
| Phishing desde otro dominio | `expected_origin` y `expected_rp_id` | `test_origen_distinto_rechazado` |
| Autenticador clonado | Contador de firmas | `test_contador_de_firmas` |
| Volcado de la BD | Solo hay material público o cifrado | `test_volcado_bd_no_revela_contenido` |
| Archivo modificado | SHA-256 del manifiesto firmado y etiqueta GCM | `test_blob_alterado_en_disco_es_detectado`, `test_subida_rechaza_datos_manipulados` |
| Rollback | La versión siempre aumenta y va en el manifiesto firmado | `test_compartir_revocar_y_rollback` |
| Sustitución de clave pública | El cliente verifica la huella | `test_cambio_de_huella_detectado` |
| Log alterado | Cadena de hashes y firma por entrada | `test_auditoria_firma_y_cadena` |
| Claves débiles | RSA < 3072, exponente distinto de 65537 o curva distinta de P-256: se rechazan | `test_politica_de_claves` |

## Secretos
El archivo `.env` (en la raíz) está en `.gitignore` y Gitleaks lo verifica en cada push.
