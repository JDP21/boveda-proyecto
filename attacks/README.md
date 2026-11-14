# attacks — scripts Red Team (Hito E5)

**Responsable: Persona 4.** Cada ataque debe ser **reproducible**: un script, su salida guardada en `attacks/evidencias/` y una captura del cliente rechazando el ataque.

| Script | Ataque | Mecanismo que lo detiene |
|---|---|---|
| `01_db_dump.py` | Volcado de `data/db/database.db` y `data/objects/*.enc` | Solo hay cifrados, DEK envueltas y claves públicas |
| `02_mitm_pubkey.py` | El servidor sustituye la clave pública del destinatario en `user_keys` | Verificación de la huella en el cliente |
| `03_tamper_ciphertext.py` | Cambiar un byte de un `*.enc` | SHA-256 del manifiesto firmado y etiqueta GCM |
| `04_rollback_version.py` | Volver a servir una versión antigua del archivo (tabla `files`) | Versión en el manifiesto firmado y última versión vista |

Opcionales: replay de una respuesta WebAuthn (el reto es de un solo uso) y alteración de `audit_log` (se rompe la cadena de hashes).

## Datos útiles
- Base de datos SQLite: `data/db/database.db`. Se puede abrir con Python (`sqlite3`) o con DB Browser for SQLite.
- Tablas: `users`, `credentials`, `challenges`, `sessions`, `user_keys`, `files`, `file_keys`, `audit_log` (ver `server/app/models/`).
- Archivos cifrados: `data/objects/<id>.v<versión>.enc`.
- Los scripts deben usar solo la biblioteca estándar de Python o las bibliotecas permitidas por el enunciado.
