import os
from functools import wraps

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from better_profanity import profanity
from datetime import datetime


#app = Flask(__name__)

#app.config["SESSION_PERMANENT"] = False
#app.config["SESSION_TYPE"] = "filesystem"
#Session(app)
#profanity.load_censor_words()
#db = SQL("sqlite:///library.db")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-solo-local")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(BASE_DIR, "flask_session")
os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
Session(app)

profanity.load_censor_words()

db = SQL("sqlite:///" + os.path.join(BASE_DIR, "library.db"))

TURNOS = {"manana": "Mañana", "tarde": "Tarde"}
GRADOS = ["1", "2", "3", "4", "5", "6"]
SECCIONES = ["A", "B", "C"]


def render_register():
    """Muestra el formulario de registro con las opciones de perfil."""
    return render_template(
        "register.html",
        turnos=TURNOS, grados=GRADOS, secciones=SECCIONES, form=request.form,
    )


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


def login_required(f):
    """
    Decorator: redirect to /login if the user isn't logged in.
    Put this on every route that a book-lending action needs
    (borrow, return, add_book, history...). Public pages like
    index/search/login/register don't need it.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = db.execute("SELECT is_admin FROM users WHERE id = ?", session["user_id"])
        if not user or not user[0]["is_admin"]:
            return apology("admin access required", 403)
        return f(*args, **kwargs)
    return decorated_function

@app.route("/")
def index():
    """Homepage informativa, sin lógica de libros."""
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")   # <- esto faltaba

        if not username:
            flash("must provide username")
            return render_template("login.html")

        if not password:
            flash("must provide password")
            return render_template("login.html")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("invalid username and/or password")
            return render_template("login.html")

        session["user_id"] = rows[0]["id"]
        session["is_admin"] = bool(rows[0]["is_admin"])
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registra un usuario nuevo (no admin) con su perfil escolar."""
    if request.method == "GET":
        return render_register()

    username = (request.form.get("username") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    turno = request.form.get("turno")
    grado = request.form.get("grado")
    seccion = request.form.get("seccion")

    if not username:
        flash("Escribe un nombre de usuario.")
        return render_register()
    if not full_name:
        flash("Escribe tus nombres y apellidos.")
        return render_register()
    if not password:
        flash("Escribe una contraseña.")
        return render_register()
    if password != confirmation:
        flash("Las contraseñas no coinciden.")
        return render_register()
    if turno not in TURNOS or grado not in GRADOS or seccion not in SECCIONES:
        flash("Elige tu turno, grado y sección.")
        return render_register()

    if db.execute("SELECT id FROM users WHERE username = ?", username):
        flash("Ese nombre de usuario ya está en uso.")
        return render_register()

    try:
        user_id = db.execute(
            """INSERT INTO users (username, hash, full_name, turno, grado, seccion)
               VALUES (?, ?, ?, ?, ?, ?)""",
            username, generate_password_hash(password), full_name, turno, int(grado), seccion,
        )
    except ValueError:
        # Dos registros con el mismo usuario al mismo tiempo
        flash("Ese nombre de usuario ya está en uso.")
        return render_register()

    session["user_id"] = user_id
    session["is_admin"] = False
    return redirect("/")



@app.route("/add_book", methods=["GET", "POST"])
@login_required
def add_book():
    """Solicita agregar un libro nuevo -- queda pendiente hasta que un admin lo apruebe."""

    if request.method == "POST":
        title = request.form.get("title")
        author = request.form.get("author")
        publisher = request.form.get("publisher")
        year = request.form.get("year")
        isbn = request.form.get("isbn")
        language = request.form.get("language")
        category = request.form.get("category")

        if not title:
            return apology("must provide a title", 400)

        if profanity.contains_profanity(title) or profanity.contains_profanity(author or ""):
            return apology("inappropriate content detected", 400)

        db.execute(
            """INSERT INTO requests (type, user_id, title, author, publisher, year, isbn, language, category, created_at)
               VALUES ('add_book', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            session["user_id"], title, author, publisher, year, isbn, language, category,
            datetime.now().isoformat()
        )

        flash("Solicitud enviada. Un administrador debe aprobarla.")
        return redirect("/add_book")

    return render_template("add_book.html")


@app.route("/borrow", methods=["POST"])
@login_required
def borrow():
    """Solicita prestar un libro -- queda pendiente hasta que un admin lo apruebe."""

    book_id = request.form.get("book_id")
    if not book_id:
        return apology("must select a book", 400)

    book = db.execute("SELECT * FROM books WHERE id = ?", book_id)
    if len(book) != 1:
        return apology("book not found", 404)
    if book[0]["status"] != "available":
        return apology("book is already borrowed", 400)

    # Evita que se manden dos solicitudes de préstamo pendientes para el mismo libro
    existing = db.execute(
        "SELECT id FROM requests WHERE type = 'borrow' AND book_id = ? AND status = 'pending'",
        book_id
    )
    if existing:
        return apology("this book already has a pending request", 400)

    db.execute(
        "INSERT INTO requests (type, user_id, book_id, created_at) VALUES ('borrow', ?, ?, ?)",
        session["user_id"], book_id, datetime.now().isoformat()
    )

    flash("Solicitud de préstamo enviada. Un administrador debe aprobarla.")
    return redirect(f"/book/{book_id}")


# Columnas permitidas para buscar -- whitelist para evitar SQL injection,
# ya que el nombre de columna no se puede parametrizar con "?"
SEARCH_COLUMNS = {
    "title": "title",
    "author": "author",
    "category": "category",
    "status": "status",
    "language": "language",
    "publisher": "publisher",
}


@app.route("/search")
def search():
    query = request.args.get("q", "")
    category = request.args.get("category", "title")

    if category not in SEARCH_COLUMNS:
        category = "title"

    column = SEARCH_COLUMNS[category]
    books = []

    categories = db.execute("SELECT DISTINCT category FROM books WHERE category IS NOT NULL AND category != '' ORDER BY category")

    if query:
        like_query = f"%{query}%"
        books = db.execute(f"SELECT * FROM books WHERE {column} LIKE ?", like_query)

    return render_template(
        "search.html",
        books=books,
        query=query,
        category=category,
        categories=categories
    )


@app.route("/search_live")
def search_live():
    query = request.args.get("q", "").strip()

    if not query:
        return jsonify([])

    like_query = f"%{query}%"
    books = db.execute(
        "SELECT id, title, author FROM books WHERE title LIKE ? ORDER BY title LIMIT 8",
        like_query
    )
    return jsonify(books)

@app.route("/book/<int:book_id>")
def book_detail(book_id):
    book = db.execute("SELECT * FROM books WHERE id = ?", book_id)

    if len(book) != 1:
        return apology("book not found", 404)

    return render_template("book_detail.html", book=book[0])





# ---------------------------------------------------------------------------
# Panel de administrador
# ---------------------------------------------------------------------------
@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    """Muestra todas las solicitudes pendientes para aprobar o rechazar."""

    pending = db.execute(
        """SELECT requests.*, users.username
           FROM requests JOIN users ON requests.user_id = users.id
           WHERE requests.status = 'pending'
           ORDER BY requests.created_at ASC"""
    )

    # Para las solicitudes de tipo 'borrow'/'return', trae el título del libro
    for r in pending:
        if r["book_id"]:
            book = db.execute("SELECT title FROM books WHERE id = ?", r["book_id"])
            r["book_title"] = book[0]["title"] if book else None

    # FRONTEND: admin.html -> loop sobre `pending`, un formulario POST por cada
    # solicitud, apuntando a /admin/approve/<id> o /admin/reject/<id>
    return render_template("admin.html", pending=pending)


@app.route("/admin/approve/<int:request_id>", methods=["POST"])
@login_required
@admin_required
def admin_approve(request_id):
    """Aprueba una solicitud y ejecuta la acción real (prestar/devolver/agregar)."""

    req = db.execute("SELECT * FROM requests WHERE id = ? AND status = 'pending'", request_id)
    if len(req) != 1:
        return apology("request not found", 404)
    req = req[0]

    if req["type"] == "borrow":
        db.execute(
            "INSERT INTO loans (book_id, user_id, borrowed_at) VALUES (?, ?, ?)",
            req["book_id"], req["user_id"], datetime.now().isoformat()
        )
        db.execute("UPDATE books SET status = 'borrowed' WHERE id = ?", req["book_id"])

    elif req["type"] == "add_book":
        # El admin pudo haber corregido los datos en el formulario de /admin --
        # si vienen en request.form, se usan esos; si no, se usa lo original de la solicitud
        title = request.form.get("title") or req["title"]
        author = request.form.get("author") or req["author"]
        publisher = request.form.get("publisher") or req["publisher"]
        year = request.form.get("year") or req["year"]
        isbn = request.form.get("isbn") or req["isbn"]
        language = request.form.get("language") or req["language"]
        category = request.form.get("category") or req["category"]

        if not title:
            return apology("must provide a title", 400)

        db.execute(
            """INSERT INTO books (title, author, publisher, year, isbn, language, category, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'available')""",
            title, author, publisher, year, isbn, language, category
        )

    db.execute(
        "UPDATE requests SET status = 'approved', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
        datetime.now().isoformat(), session["user_id"], request_id
    )

    flash("Solicitud aprobada.")
    return redirect("/admin")

@app.route("/admin/reject/<int:request_id>", methods=["POST"])
@login_required
@admin_required
def admin_reject(request_id):
    """Rechaza una solicitud sin ejecutar ninguna acción."""

    db.execute(
        "UPDATE requests SET status = 'rejected', reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending'",
        datetime.now().isoformat(), session["user_id"], request_id
    )

    flash("Solicitud rechazada.")
    return redirect("/admin")

@app.route("/admin/books")
@login_required
@admin_required
def admin_books():
    """
    Vista de admin: todos los libros con su estado, y si están prestados,
    quién los tiene y hace cuántos días.
    """

    rows = db.execute(
        """SELECT books.id, books.title, books.author, books.status,
                  users.username AS borrowed_by, loans.borrowed_at
           FROM books
           LEFT JOIN loans ON loans.book_id = books.id AND loans.returned_at IS NULL
           LEFT JOIN users ON loans.user_id = users.id
           ORDER BY books.title"""
    )

    # Calcula los días prestado en Python (SQLite no tiene un tipo fecha nativo)
    for row in rows:
        if row["borrowed_at"]:
            borrowed_date = datetime.fromisoformat(row["borrowed_at"])
            row["days_borrowed"] = (datetime.now() - borrowed_date).days
        else:
            row["days_borrowed"] = None

    return render_template("admin_books.html", books=rows)

@app.route("/admin/toggle_status/<int:book_id>", methods=["POST"])
@login_required
@admin_required
def admin_toggle_status(book_id):
    """
    Cambia manualmente el estado de un libro (available <-> borrowed).
    Si se marca como disponible, cierra cualquier préstamo activo
    de ese libro para que la tabla deje de mostrar usuario/días.
    """

    book = db.execute("SELECT * FROM books WHERE id = ?", book_id)
    if len(book) != 1:
        return apology("book not found", 404)

    current_status = book[0]["status"]

    if current_status == "available":
        db.execute("UPDATE books SET status = 'borrowed' WHERE id = ?", book_id)
    else:
        # Vuelve a disponible: cierra el préstamo activo (si existía uno real)
        db.execute(
            "UPDATE loans SET returned_at = ? WHERE book_id = ? AND returned_at IS NULL",
            datetime.now().isoformat(), book_id
        )
        db.execute("UPDATE books SET status = 'available' WHERE id = ?", book_id)

    flash("Estado del libro actualizado.")
    return redirect("/admin/books")


@app.route("/history")
@login_required
def history():
    """Historial del usuario: sus solicitudes y sus préstamos."""

    loans = db.execute(
        """SELECT books.title, loans.borrowed_at, loans.returned_at
           FROM loans JOIN books ON loans.book_id = books.id
           WHERE loans.user_id = ?
           ORDER BY loans.borrowed_at DESC""",
        session["user_id"]
    )

    # Solicitudes del propio usuario (préstamo o agregar libro), de la más nueva a la más antigua.
    # Para 'borrow' el título viene del libro; para 'add_book' viene de la propia solicitud.
    my_requests = db.execute(
        """SELECT requests.type, requests.status, requests.created_at,
                  COALESCE(books.title, requests.title) AS title
           FROM requests LEFT JOIN books ON requests.book_id = books.id
           WHERE requests.user_id = ? AND requests.type IN ('borrow', 'add_book')
           ORDER BY requests.created_at DESC""",
        session["user_id"]
    )

    return render_template("history.html", loans=loans, my_requests=my_requests)


@app.route("/report")
@login_required
def report():
    """Simple stats: most-borrowed books and currently overdue-looking loans."""

    most_borrowed = db.execute(
        """SELECT books.title, COUNT(*) AS times_borrowed
           FROM loans JOIN books ON loans.book_id = books.id
           GROUP BY loans.book_id
           ORDER BY times_borrowed DESC
           LIMIT 5"""
    )

    currently_out = db.execute(
        """SELECT books.title, loans.borrowed_at
           FROM loans JOIN books ON loans.book_id = books.id
           WHERE loans.returned_at IS NULL
           ORDER BY loans.borrowed_at ASC"""
    )

    # FRONTEND: report.html -> two loops, over `most_borrowed` and `currently_out`
    return render_template("report.html", most_borrowed=most_borrowed, currently_out=currently_out)



def apology(message, code=400):
    """
    Render an error page. Called from other routes, e.g. return apology("...", 400).
    FRONTEND: apology.html should display `{{ message }}` and maybe `{{ code }}`
    """
    return render_template("apology.html", message=message, code=code), code


if __name__ == "__main__":
    app.run(debug=True)