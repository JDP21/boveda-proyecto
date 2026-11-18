"""Ataque 2: el servidor (o un atacante) modifica un byte del archivo cifrado almacenado."""
import pathlib
import sys

file_id = sys.argv[1]
p = max(pathlib.Path("data/objects").glob(f"{file_id}.v*.enc"), key=lambda x: x.stat().st_mtime)
datos = bytearray(p.read_bytes())
antes = datos[16:32].hex()
datos[20] ^= 0x01
p.write_bytes(datos)
OUT = pathlib.Path("attacks/evidencias")
OUT.mkdir(parents=True, exist_ok=True)
(OUT / "03_tamper_ciphertext.txt").write_text(
    f"Archivo: {p.name}\nBytes 16-31 antes:   {antes}\nBytes 16-31 después: {datos[16:32].hex()}\n",
    encoding="utf-8",
)
print(f"Modificado {p.name}. Ahora descárgalo en el navegador.")
