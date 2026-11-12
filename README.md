# Bóveda de archivos compartidos con cifrado del lado del cliente y autenticación sin contraseña

Proyecto final de **Criptografía Aplicada** (Universidad Distrital Francisco José de Caldas, 2026-1). **Alternativa B.**

Este repositorio reúne los tres componentes del sistema como **submódulos de Git**:

| Carpeta | Repositorio | Contenido | Responsable |
|---|---|---|---|
| `boveda-servidor/` | [JDP21/boveda-servidor](https://github.com/JDP21/boveda-servidor) | API FastAPI, WebAuthn (passkeys), base de datos, directorio de claves públicas, log de auditoría | Persona 2 |
| `boveda-cliente/` | [JDP21/boveda-cliente](https://github.com/JDP21/boveda-cliente) | Interfaz web y criptografía en el navegador (Web Crypto API) — *por desarrollar* | Persona 3 |
| `boveda-infra/` | [JDP21/boveda-infra](https://github.com/JDP21/boveda-infra) | `docker-compose`, scripts de ataque y evidencias — *por desarrollar* | Persona 4 |

> **Estado:** `boveda-servidor` ya tiene su estructura inicial. `boveda-cliente` y `boveda-infra` están vacíos para que sus responsables los desarrollen. Ambos deben respetar el contrato de la API documentado en el README de `boveda-servidor` (y en `/docs` con el servidor corriendo).

## Clonar
```bash
git clone --recurse-submodules https://github.com/JDP21/boveda-proyecto.git
```

**Servidor (disponible ya):**
```bash
cd boveda-proyecto/boveda-servidor
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000     # documentación en http://localhost:8000/docs
```

**Sistema completo:** cuando `boveda-infra` tenga su `docker-compose.yml`, se levantará con `docker compose up --build` desde esa carpeta.

Si ya clonaste sin `--recurse-submodules` y las carpetas están vacías:
```bash
git submodule update --init
```

## Trabajo diario
Cada integrante trabaja **dentro de su carpeta**, que es un repositorio independiente:
```bash
cd boveda-servidor
git checkout main && git pull
# ... cambios ...
git add . && git commit -m "Descripción" && git push
```

Este repositorio guarda un puntero a un commit concreto de cada submódulo. Para apuntar a lo último (hacerlo antes de cada entrega):
```bash
git submodule update --remote
git add . && git commit -m "Actualiza submódulos" && git push
```

## Arquitectura
- **Cliente web:** genera las claves, cifra y descifra archivos (AES-256-GCM), envuelve las DEK (RSA-OAEP 3072), firma los manifiestos (ECDSA P-256) y verifica las huellas. Las claves privadas se protegen con Argon2id y nunca salen del navegador sin cifrar.
- **Servidor:** es honesto pero curioso. Verifica las passkeys, controla el acceso y almacena; **nunca puede descifrar**.
- **Almacenamiento:** PostgreSQL y un volumen de archivos cifrados. Solo contiene material público o cifrado.

El detalle está en el documento de diseño (E1) y en el README de cada submódulo.
