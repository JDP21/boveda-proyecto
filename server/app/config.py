"""Configuración leída de variables de entorno (.env). Nunca poner secretos aquí."""
import os

# WebAuthn: la credencial queda ligada a este dominio (relying party)
RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "Bóveda Segura UD")

# Orígenes desde los que se abre el cliente. Se aceptan varios separados por coma, p. ej.
# "http://localhost:8080,http://localhost:5173" (Docker + Vite en desarrollo).
# WebAuthn rechaza cualquier respuesta firmada desde un origen que no esté aquí (anti-phishing).
ORIGINS = [o.strip() for o in os.getenv("ORIGIN", "http://localhost:8080").split(",") if o.strip()]

# Base de datos: SQLite (vault-db)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/db/database.db")

# Carpeta donde se guardan los archivos YA CIFRADOS por el cliente (vault-object-storage)
BLOB_DIR = os.getenv("BLOB_DIR", "./data/objects")

# Tiempos de vida
CHALLENGE_TTL_SECONDS = int(os.getenv("CHALLENGE_TTL_SECONDS", "300"))
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60"))

# Tamaño máximo de archivo (bytes)
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(50 * 1024 * 1024)))

# Política criptográfica mínima exigida a las claves públicas que suben los clientes
MIN_RSA_BITS = 3072
