# Bóveda Zero-Knowledge

Bóveda de archivos compartidos con **cifrado del lado del cliente** y **autenticación sin contraseña (passkeys)**.
Proyecto final de Criptografía Aplicada, Universidad Distrital Francisco José de Caldas, 2026-1. **Alternativa B.**

## Estructura
```
boveda-proyecto/
├── .github/workflows/security-ci.yml   Gitleaks + ruff/pytest (servidor) + lint/build (cliente)
├── client/     vault-web-client  — React + TS + Vite, servido por nginx       (Persona 3)
├── server/     vault-api-server  — Python + FastAPI + py_webauthn + SQLite    (Persona 2)
├── attacks/    Scripts Red Team del hito E5                                   (Persona 4)
├── docs/       Entregables E1 (diseño) y E4 (informe IEEE)
├── data/       Volúmenes locales, ignorados en Git: db/ (SQLite) y objects/ (*.enc)
├── .env.example
├── docker-compose.yml
└── README.md
```

| Componente | Estado |
|---|---|
| `server/` | Estructura inicial lista: WebAuthn, claves, archivos, compartir/revocar, log encadenado y pruebas |
| `client/` | `Dockerfile` y `nginx.conf` listos; falta crear el proyecto Vite (ver `client/README.md`) |
| `attacks/` | Por desarrollar (ver `attacks/README.md`) |

## Ejecución
Requisitos: Git y Docker Desktop.
```bash
git clone https://github.com/JDP21/boveda-proyecto.git
cd boveda-proyecto
cp .env.example .env
docker compose up --build
```
- Aplicación: **http://localhost:8080**
- API (Swagger): **http://localhost:8000/docs**

Mientras el cliente no exista, se puede levantar solo la API: `docker compose up --build server`

Para borrar todos los datos y empezar de cero: detén los contenedores y vacía `data/db/` y `data/objects/` (sin borrar los `.gitkeep`).

## Arquitectura
- **Cliente (navegador):** genera las claves, cifra y descifra los archivos (AES-256-GCM), envuelve las DEK (RSA-OAEP 3072), firma los manifiestos (ECDSA P-256) y verifica las huellas. Las claves privadas se protegen con Argon2id y nunca salen sin cifrar.
- **Servidor:** es honesto pero curioso. Verifica las passkeys, controla el acceso y almacena, pero **nunca puede descifrar**.
- **Almacenamiento:** SQLite y archivos `*.enc`. Solo contienen material público o cifrado por el cliente.

nginx sirve el cliente y reenvía `/api/*` al servidor, así que todo queda en el mismo origen, como exige WebAuthn.

## Reglas del repositorio
- **Nunca** subir `.env`, claves ni contraseñas. Gitleaks revisa todo el historial en cada push; un secreto en el historial deja el criterio C8 en insuficiente.
- Solo bibliotecas criptográficas permitidas: `cryptography`, PyNaCl, Web Crypto API, OpenSSL, `py_webauthn` y SimpleWebAuthn.
- Cada integrante trabaja en su carpeta, con commits propios. Lo ideal es usar ramas y pull requests hacia `main`.
