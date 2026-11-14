# client — vault-web-client (React + TypeScript + Vite)

**Responsable: Persona 3.** Todo el cifrado ocurre aquí; el servidor solo recibe material público o cifrado.

## Crear el proyecto
Desde esta carpeta (los archivos `Dockerfile`, `nginx.conf` y `src/` ya existen; no los borres):
```bash
npm create vite@latest . -- --template react-ts
npm install
npm install @simplewebauthn/browser
```

Para desarrollar con recarga en caliente, reenvía `/api` al servidor en `vite.config.ts` y pon `ORIGIN=http://localhost:5173` en el `.env` de la raíz:
```ts
export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": { target: "http://localhost:8000", rewrite: (p) => p.replace(/^\/api/, "") } } },
});
```
```bash
npm run dev    # http://localhost:5173  (con la API corriendo: docker compose up server)
```

## Estructura
| Carpeta | Contenido |
|---|---|
| `src/crypto/` | Web Crypto API: AES-256-GCM, RSA-OAEP 3072, ECDSA P-256, SHA-256; Argon2id para la KEK |
| `src/auth/` | Registro e inicio de sesión con passkeys (`@simplewebauthn/browser`) |
| `src/components/` | Interfaz |

## Contrato de la API
Lo define el servidor: ver `server/README.md` o http://localhost:8000/docs. Todas las rutas se llaman con el prefijo `/api` (por ejemplo `/api/auth/login/options`) y el encabezado `Authorization: Bearer <token>`.

## Primitivas (documento de diseño, sección 4.1)
| Uso | Primitiva | Parámetros |
|---|---|---|
| Archivos | AES-256-GCM | DEK aleatoria por archivo y versión, IV de 96 bits, AD = `id\|versión` |
| Envoltura de la DEK | RSA-OAEP | 3072 bits, SHA-256 |
| Firmas | ECDSA P-256 | SHA-256 (manifiestos y log) |
| Claves privadas | Argon2id → AES-256-GCM | m = 64 MiB, t = 3, p = 1, sal de 16 B |
| Huellas | SHA-256 | SHA-256(SPKI de cifrado ‖ SPKI de firma) |

Al descargar se verifica, en este orden: la huella del propietario, la firma del manifiesto, la versión (anti-rollback), el SHA-256 del blob y la etiqueta GCM.
