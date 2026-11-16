import os
import sys
import tempfile

# Base de datos y almacenamiento temporales ANTES de importar la app
_tmp = tempfile.mkdtemp(prefix="boveda-test-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/db/database.db"
os.environ["BLOB_DIR"] = f"{_tmp}/objects"
os.environ["ORIGIN"] = "http://localhost:8080,http://localhost:5173"
os.environ["RP_ID"] = "localhost"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import itertools  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

_ids = itertools.count(1)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def tmp_paths():
    return {"db": f"{_tmp}/db/database.db", "objects": f"{_tmp}/objects"}


@pytest.fixture
def new_user(client):
    """Fábrica de usuarios: registro real con passkey virtual y, opcionalmente, claves."""
    from sim_client import VaultUser

    def make(prefix: str = "user", keys: bool = True) -> VaultUser:
        u = VaultUser(client, f"{prefix}{next(_ids)}").register()
        if keys:
            u.upload_keys()
        return u
    return make
