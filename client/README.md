# client — vault-web-client (React + TypeScript + Vite)

**Responsable: Cesar Soriano (Persona 3).** Todo el cifrado ocurre aquí; el servidor solo recibe material público o cifrado.

## Desarrollo local
Con la API arriba (`docker compose up --build server` o `uvicorn` en `server/`):
```bash
cd client
npm install
npm run dev    # http://localhost:5173  (proxy /api → :8000)
```

Abre siempre con **`localhost`**, nunca `127.0.0.1` (WebAuthn liga la passkey al origen).

<<<<<<< HEAD
## Pruebas y validación
```bash
npm test       # Vitest: integridad, acceso, revocación y descargas
npm run lint
npm run build
=======
## Pruebas
```bash
npm test       # Vitest: auditoría, navegación y operaciones de archivos
npm run build  # TypeScript + build de producción
>>>>>>> main
```

Producción / Docker (nginx sirve el build y reenvía `/api`):
```bash
docker compose up --build
# http://localhost:8080
```

## Estructura
| Ruta | Contenido |
|---|---|
| `src/api.ts` | Cliente HTTP + token Bearer |
| `src/auth/` | Passkeys (`@simplewebauthn/browser`) — TK-03.2 |
| `src/auth/api.ts` | Construcción, firma y verificación del log de auditoría |
| `src/crypto/` | Web Crypto + Argon2id (`hash-wasm`): encoding, firmas, claves, sobre |
| `src/files/` | Manifiesto firmado, subida, listado/borrado, descarga, compartir |
| `src/components/` | UI: auth, desbloqueo, tabla de archivos y bitácora |

## Contrato de la API
Ver la sección **Contrato para el front** de `server/README.md` o http://localhost:8000/docs.
Referencia de formatos: `server/scripts/sim_client.py`.

## Primitivas (documento de diseño)
| Uso | Primitiva | Parámetros |
|---|---|---|
| Archivos | AES-256-GCM | DEK por archivo/versión, IV 96 bits, AD = `id\|versión` |
| Envoltura DEK | RSA-OAEP | 3072 bits, SHA-256 |
| Firmas | ECDSA P-256 | SHA-256 (manifiestos) |
| Claves privadas | Argon2id → AES-256-GCM | m = 64 MiB, t = 3, p = 1, sal 16 B |
| Huellas | SHA-256 | SHA-256(SPKI cifrado ‖ SPKI firma) |

Al descargar: firma del manifiesto → versión (anti-rollback) → SHA-256 del blob → unwrap DEK → AES-GCM.
