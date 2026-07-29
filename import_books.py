import sqlite3
import csv

conn = sqlite3.connect("library.db")
cur = conn.cursor()

with open("libros_tabla.csv", "r", encoding="utf-8-sig", newline="") as f:
    content = f.read()

content = content.replace('"AÑO DE \nPUBLICACIÓN"', '"AÑO DE PUBLICACIÓN"')
content = content.replace('"ÚLTIMO \nUSUARIO"', '"ÚLTIMO USUARIO"')
content = content.replace('"FECHA \nÚLTIMO PRÉSTAMO"', '"FECHA ÚLTIMO PRÉSTAMO"')

rows = list(csv.DictReader(content.splitlines()))

cur.execute("DELETE FROM books")

for row in rows:
    title = (row.get("TÍTULO") or "").strip()
    author = (row.get("AUTOR") or "").strip()
    publisher = (row.get("EDITORIAL") or "").strip()
    year = (row.get("AÑO DE PUBLICACIÓN") or "").strip()
    isbn = (row.get("ISBN") or "").strip()
    language = (row.get("IDIOMA") or "").strip()
    category = (row.get("CATEGORÍA") or "").strip()
    estado = (row.get("ESTADO") or "").strip().lower()

    if not title:
        continue

    if estado == "disponible":
        status = "available"
    else:
        status = "borrowed"

    year_value = int(year) if year.isdigit() else None

    cur.execute("""
        INSERT INTO books (title, author, publisher, year, isbn, language, category, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (title, author, publisher, year_value, isbn, language, category, status))

conn.commit()
conn.close()

print("Importación completada.")