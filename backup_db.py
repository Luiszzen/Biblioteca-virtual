"""Copia de seguridad de library.db.
python3 backup_db.py
(fuera de Git), conserva las últimas 14 copias.
"""
import glob
import os
import sqlite3
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SOURCE = os.path.join(BASE_DIR, "library.db")
BACKUP_DIR = os.path.join(os.path.dirname(BASE_DIR), "backups")
KEEP = 14


def main():
    if not os.path.exists(SOURCE):
        raise SystemExit(f"No se encontró la base de datos: {SOURCE}")

    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now(timezone(timedelta(hours=-5))).strftime("%Y-%m-%d_%H%M%S")
    target = os.path.join(BACKUP_DIR, f"library-{stamp}.db")

    source = sqlite3.connect(SOURCE)
    destination = sqlite3.connect(target)
    with destination:
        source.backup(destination)
    source.close()
    destination.close()

    for old in sorted(glob.glob(os.path.join(BACKUP_DIR, "library-*.db")))[:-KEEP]:
        os.remove(old)

    print("Copia creada:", target)


if __name__ == "__main__":
    main()