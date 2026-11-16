import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .api import audit, auth, files, keys
from .config import ORIGINS
from .models import SessionLocal, init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


# ROOT_PATH=/api cuando corre detrás de nginx, para que /api/docs funcione
app = FastAPI(lifespan=lifespan, root_path=os.getenv("ROOT_PATH", ""), title="Bóveda Segura — API", version="0.2.0",
              description="Servidor 'honesto pero curioso': solo almacena material público o cifrado.")

# En Docker el cliente y la API comparten origen vía nginx (/api); CORS solo para desarrollo local.
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_credentials=False,
                   allow_methods=["*"], allow_headers=["Authorization", "Content-Type"])


@app.get("/health", tags=["health"])
def health():
    """Comprueba que la API responde y que la base de datos está accesible."""
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok"}


for r in (auth.router, keys.router, files.router, audit.router):
    app.include_router(r)
