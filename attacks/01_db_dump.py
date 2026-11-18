"""Ataque 1: el atacante obtiene la BD y el almacenamiento. Esperado: nada legible."""
import pathlib
import sqlite3
import sys

SECRETO = (sys.argv[1] if len(sys.argv) > 1 else "").encode()
DB, OBJ = pathlib.Path("data/db/database.db"), pathlib.Path("data/objects")
OUT = pathlib.Path("attacks/evidencias")
OUT.mkdir(parents=True, exist_ok=True)

con = sqlite3.connect(DB)
volcado = []
with open(OUT / "01_db_dump.txt", "w", encoding="utf-8") as f:
    for (tabla,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        f.write(f"\n===== {tabla} =====\n")
        for fila in con.execute(f"SELECT * FROM {tabla}"):
            volcado.append(repr(fila).encode())
            f.write(repr(fila)[:300] + "\n")
    for p in OBJ.glob("*.enc"):
        datos = p.read_bytes()
        volcado.append(datos)
        f.write(f"\n{p.name}: {datos[:48].hex()}...\n")
    todo = b"".join(volcado)
    f.write(f"\n¿Aparece el secreto en claro? {'SÍ' if SECRETO and SECRETO in todo else 'NO'}\n")
    f.write(f"¿Aparece alguna clave privada en claro? {'SÍ' if b'PRIVATE KEY' in todo else 'NO'}\n")
print(open(OUT / "01_db_dump.txt", encoding="utf-8").read()[-400:])
