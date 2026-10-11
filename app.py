import os
import hmac
from functools import wraps

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from better_profanity import profanity
from datetime import datetime, timedelta


#app = Flask(__name__)

#app.config["SESSION_PERMANENT"] = False
#app.config["SESSION_TYPE"] = "filesystem"
#Session(app)
#profanity.load_censor_words()
#db = SQL("sqlite:///library.db")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-solo-local")

#seguridad
PRODUCTION = os.environ.get("PRODUCTION") == "1"
if PRODUCTION and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("Falta SECRET_KEY en producción: defínela en el archivo WSGI.")

#Si no está definido, el registro queda abierto.
REGISTRATION_CODE = os.environ.get("REGISTRATION_CODE", "")

app.config["SESSION_COOKIE_SECURE"] = PRODUCTION      #la cookie  por HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True          # js no puede leerla
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"         #no se envía desde otros sitios en POST
app.config["WTF_CSRF_TIME_LIMIT"] = None              # el token dura lo que dura la sesión
csrf = CSRFProtect(app)                               # exige token CSRF en todo POST

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
        require_code=bool(REGISTRATION_CODE),
    )


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    # Cabeceras de seguridad
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.errorhandler(CSRFError)
def csrf_error(error):
    """Formulario sin token válido (sesión vencida o intento de falsificación)."""
    return apology("Tu sesión venció o el formulario no es válido. Recarga la página e inténtalo otra vez.", 400)


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

MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_MINUTES = 15


def recent_login_failures(username):
    """Cuenta los intentos fallidos de ese usuario en los últimos 15 minutos."""
    cutoff = (datetime.now() - timedelta(minutes=LOGIN_WINDOW_MINUTES)).isoformat()
    rows = db.execute(
        "SELECT COUNT(*) AS n FROM login_attempts WHERE username = ? AND attempted_at > ?",
        username, cutoff
    )
    return rows[0]["n"]


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("must provide username")
            return render_template("login.html")

        if not password:
            flash("must provide password")
            return render_template("login.html")

        attempt_name = username.strip().lower()[:100]

        # Demasiados fallos recientes: se bloquea aunque la contraseña sea correcta
        if recent_login_failures(attempt_name) >= MAX_LOGIN_FAILURES:
            flash("Demasiados intentos fallidos. Espera 15 minutos e inténtalo de nuevo.")
            return render_template("login.html"), 429

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            now = datetime.now()
            db.execute(
                "INSERT INTO login_attempts (username, attempted_at) VALUES (?, ?)",
                attempt_name, now.isoformat()
            )
            # Limpieza: borra intentos de hace más de un día
            db.execute(
                "DELETE FROM login_attempts WHERE attempted_at < ?",
                (now - timedelta(days=1)).isoformat()
            )
            flash("invalid username and/or password")
            return render_template("login.html")

        db.execute("DELETE FROM login_attempts WHERE username = ?", attempt_name)
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

    if REGISTRATION_CODE:
        given_code = request.form.get("registration_code") or ""
        if not hmac.compare_digest(given_code.encode(), REGISTRATION_CODE.encode()):
            flash("Código de registro incorrecto. Pídelo en la biblioteca.")
            return render_register()

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
    if len(password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.")
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

# Motivos permitidos para reportar un libro (clave interna -> texto visible)
REPORT_REASONS = {
    "damaged": "Libro dañado",
    "missing": "Libro perdido o no está en su lugar",
    "wrong_info": "Datos incorrectos (título, autor, etc.)",
    "other": "Otro",
}


@app.route("/report_book", methods=["POST"])
@login_required
def report_book():
    """El usuario reporta un problema con un libro; un admin lo revisa después."""

    book_id = request.form.get("book_id")
    reason = request.form.get("reason")
    details = (request.form.get("details") or "").strip()

    book = db.execute("SELECT id FROM books WHERE id = ?", book_id)
    if len(book) != 1:
        return apology("book not found", 404)
    book_id = book[0]["id"]

    if reason not in REPORT_REASONS:
        flash("Elige el motivo del reporte.")
        return redirect(f"/book/{book_id}")

    if len(details) > 500:
        flash("El detalle es muy largo (máximo 500 caracteres).")
        return redirect(f"/book/{book_id}")

    if profanity.contains_profanity(details):
        flash("El detalle contiene lenguaje inapropiado.")
        return redirect(f"/book/{book_id}")

    # Evita que el mismo usuario mande el mismo reporte varias veces mientras sigue abierto
    existing = db.execute(
        "SELECT id FROM book_reports WHERE book_id = ? AND user_id = ? AND status = 'open'",
        book_id, session["user_id"]
    )
    if existing:
        flash("Ya reportaste este libro. Un administrador lo está revisando.")
        return redirect(f"/book/{book_id}")

    db.execute(
        """INSERT INTO book_reports (book_id, user_id, reason, details, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        book_id, session["user_id"], reason, details or None, datetime.now().isoformat()
    )

    flash("Reporte enviado. Gracias por avisar.")
    return redirect(f"/book/{book_id}")

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

    return render_template("book_detail.html", book=book[0], reasons=REPORT_REASONS)




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
    open_reports = db.execute("SELECT COUNT(*) AS n FROM book_reports WHERE status = 'open'")[0]["n"]

    return render_template("admin.html", pending=pending, open_reports=open_reports)


@app.route("/admin/approve/<int:request_id>", methods=["POST"])
@login_required
@admin_required
def admin_approve(request_id):
    """Aprueba una solicitud y ejecuta la acción real (prestar o agregar libro)."""

    req = db.execute("SELECT * FROM requests WHERE id = ? AND status = 'pending'", request_id)
    if len(req) != 1:
        return apology("request not found", 404)
    req = req[0]

    now = datetime.now().isoformat()

    if req["type"] == "borrow":
        # Todo o nada: si algo falla a la mitad, no queda un libro "prestado" sin préstamo.
        db.execute("BEGIN")
        try:
            # Solo se presta si el libro SIGUE disponible (evita préstamos dobles)
            taken = db.execute(
                "UPDATE books SET status = 'borrowed' WHERE id = ? AND status = 'available'",
                req["book_id"]
            )
            if taken != 1:
                db.execute("ROLLBACK")
                db.execute(
                    "UPDATE requests SET status = 'rejected', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                    now, session["user_id"], request_id
                )
                flash("Ese libro ya no está disponible. La solicitud se rechazó automáticamente.")
                return redirect("/admin")

            db.execute(
                "INSERT INTO loans (book_id, user_id, borrowed_at) VALUES (?, ?, ?)",
                req["book_id"], req["user_id"], now
            )
            db.execute(
                "UPDATE requests SET status = 'approved', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                now, session["user_id"], request_id
            )
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

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

        db.execute("BEGIN")
        try:
            db.execute(
                """INSERT INTO books (title, author, publisher, year, isbn, language, category, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'available')""",
                title, author, publisher, year, isbn, language, category
            )
            db.execute(
                "UPDATE requests SET status = 'approved', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                now, session["user_id"], request_id
            )
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

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
                COALESCE(users.full_name, users.username) AS borrowed_by, loans.borrowed_at
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

@app.route("/admin/return/<int:book_id>", methods=["POST"])
@login_required
@admin_required
def admin_return_book(book_id):
    """Registra la devolución de un libro: cierra el préstamo activo y lo deja disponible."""

    book = db.execute("SELECT id, status FROM books WHERE id = ?", book_id)
    if len(book) != 1:
        return apology("book not found", 404)

    if book[0]["status"] == "available":
        flash("Ese libro ya está disponible.")
        return redirect("/admin/books")

    db.execute(
        "UPDATE loans SET returned_at = ? WHERE book_id = ? AND returned_at IS NULL",
        datetime.now().isoformat(), book_id
    )
    db.execute("UPDATE books SET status = 'available' WHERE id = ?", book_id)

    flash("Devolución registrada.")
    return redirect("/admin/books")


def read_book_form(form):
    """Lee y valida los campos de un libro. Devuelve (datos, mensaje_de_error)."""

    def clean(name):
        return (form.get(name) or "").strip() or None

    data = {
        "title": (form.get("title") or "").strip(),
        "author": clean("author"),
        "publisher": clean("publisher"),
        "isbn": clean("isbn"),
        "language": clean("language"),
        "category": clean("category"),
        "year": None,
    }

    year = (form.get("year") or "").strip()
    if year:
        if not year.isdigit() or not 0 <= int(year) <= 2100:
            return data, "El año debe ser un número entre 0 y 2100."
        data["year"] = int(year)

    if not data["title"]:
        return data, "El título es obligatorio."

    return data, None


@app.route("/admin/books/new", methods=["GET", "POST"])
@login_required
@admin_required
def admin_book_new():
    """El admin agrega un libro directamente al catálogo (sin solicitud)."""

    if request.method == "POST":
        data, error = read_book_form(request.form)

        if not error and data["isbn"]:
            if db.execute("SELECT id FROM books WHERE isbn = ?", data["isbn"]):
                error = "Ya existe un libro con ese ISBN."

        if error:
            flash(error)
            return render_template("admin_book_form.html", book=data, heading="Agregar libro")

        db.execute(
            """INSERT INTO books (title, author, publisher, year, isbn, language, category, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'available')""",
            data["title"], data["author"], data["publisher"], data["year"],
            data["isbn"], data["language"], data["category"]
        )
        flash("Libro agregado al catálogo.")
        return redirect("/admin/books")

    return render_template("admin_book_form.html", book={}, heading="Agregar libro")


@app.route("/admin/books/<int:book_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def admin_book_edit(book_id):
    """El admin corrige los datos de un libro. El estado no se cambia aquí."""

    book = db.execute("SELECT * FROM books WHERE id = ?", book_id)
    if len(book) != 1:
        return apology("book not found", 404)

    if request.method == "POST":
        data, error = read_book_form(request.form)

        if not error and data["isbn"]:
            if db.execute("SELECT id FROM books WHERE isbn = ? AND id != ?", data["isbn"], book_id):
                error = "Otro libro ya tiene ese ISBN."

        if error:
            flash(error)
            return render_template("admin_book_form.html", book=data, heading="Editar libro")

        db.execute(
            """UPDATE books SET title = ?, author = ?, publisher = ?, year = ?,
                                isbn = ?, language = ?, category = ?
               WHERE id = ?""",
            data["title"], data["author"], data["publisher"], data["year"],
            data["isbn"], data["language"], data["category"], book_id
        )
        flash("Libro actualizado.")
        return redirect("/admin/books")

    return render_template("admin_book_form.html", book=book[0], heading="Editar libro")


@app.route("/admin/books/<int:book_id>/delete", methods=["POST"])
@login_required
@admin_required
def admin_book_delete(book_id):
    """Elimina un libro, solo si nunca tuvo préstamos, solicitudes ni reportes."""

    if len(db.execute("SELECT id FROM books WHERE id = ?", book_id)) != 1:
        return apology("book not found", 404)

    used = (
        db.execute("SELECT id FROM loans WHERE book_id = ? LIMIT 1", book_id)
        or db.execute("SELECT id FROM requests WHERE book_id = ? LIMIT 1", book_id)
        or db.execute("SELECT id FROM book_reports WHERE book_id = ? LIMIT 1", book_id)
    )
    if used:
        flash("No se puede eliminar: el libro tiene historial de préstamos, solicitudes o reportes.")
        return redirect("/admin/books")

    try:
        db.execute("DELETE FROM books WHERE id = ?", book_id)
    except ValueError:
        flash("No se pudo eliminar el libro.")
        return redirect("/admin/books")

    flash("Libro eliminado.")
    return redirect("/admin/books")


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    """Lista de usuarios con su perfil y cuántos libros tienen prestados ahora."""

    users = db.execute(
        """SELECT users.id, users.username, users.full_name, users.turno,
                  users.grado, users.seccion, users.is_admin,
                  (SELECT COUNT(*) FROM loans
                   WHERE loans.user_id = users.id AND loans.returned_at IS NULL) AS active_loans
           FROM users
           ORDER BY users.is_admin DESC, users.grado, users.seccion, users.full_name, users.username"""
    )
    return render_template("admin_users.html", users=users, turnos=TURNOS)


@app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
@login_required
@admin_required
def admin_user_edit(user_id):
    """El admin corrige el perfil de un usuario (nombre, turno, grado, sección)."""

    user = db.execute(
        "SELECT id, username, full_name, turno, grado, seccion, is_admin FROM users WHERE id = ?",
        user_id
    )
    if len(user) != 1:
        return apology("user not found", 404)

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip() or None
        turno = request.form.get("turno") or None
        grado = request.form.get("grado") or None
        seccion = request.form.get("seccion") or None

        if (turno and turno not in TURNOS) or (grado and grado not in GRADOS) or (seccion and seccion not in SECCIONES):
            flash("Turno, grado o sección no válidos.")
            return redirect(f"/admin/users/{user_id}")

        db.execute(
            "UPDATE users SET full_name = ?, turno = ?, grado = ?, seccion = ? WHERE id = ?",
            full_name, turno, int(grado) if grado else None, seccion, user_id
        )
        flash("Perfil actualizado.")
        return redirect(f"/admin/users/{user_id}")

    return render_template(
        "admin_user_edit.html",
        user=user[0], turnos=TURNOS, grados=GRADOS, secciones=SECCIONES
    )


@app.route("/admin/users/<int:user_id>/password", methods=["POST"])
@login_required
@admin_required
def admin_user_password(user_id):
    """El admin le pone una contraseña nueva a un usuario (no hay recuperación por correo)."""

    if len(db.execute("SELECT id FROM users WHERE id = ?", user_id)) != 1:
        return apology("user not found", 404)

    new_password = request.form.get("new_password") or ""
    confirmation = request.form.get("confirmation") or ""

    if len(new_password) < 6:
        flash("La contraseña debe tener al menos 6 caracteres.")
    elif new_password != confirmation:
        flash("Las contraseñas no coinciden.")
    else:
        db.execute(
            "UPDATE users SET hash = ? WHERE id = ?",
            generate_password_hash(new_password), user_id
        )
        flash("Contraseña restablecida. Entrégasela al usuario en persona.")

    return redirect(f"/admin/users/{user_id}")

@app.route("/admin/reports")
@login_required
@admin_required
def admin_reports():
    """Lista los reportes de libros: primero los abiertos, luego los resueltos."""

    reports = db.execute(
        """SELECT book_reports.id, book_reports.reason, book_reports.details,
                  book_reports.status, book_reports.created_at, book_reports.resolved_at,
                  books.id AS book_id, books.title,
                  users.username, users.full_name, users.turno, users.grado, users.seccion
           FROM book_reports
           JOIN books ON book_reports.book_id = books.id
           JOIN users ON book_reports.user_id = users.id
           ORDER BY (book_reports.status = 'open') DESC, book_reports.created_at DESC
           LIMIT 200"""
    )
    return render_template("admin_reports.html", reports=reports, reasons=REPORT_REASONS)


@app.route("/admin/reports/resolve/<int:report_id>", methods=["POST"])
@login_required
@admin_required
def admin_resolve_report(report_id):
    """Marca un reporte como resuelto."""

    db.execute(
        "UPDATE book_reports SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE id = ? AND status = 'open'",
        datetime.now().isoformat(), session["user_id"], report_id
    )
    flash("Reporte marcado como resuelto.")
    return redirect("/admin/reports")

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
@admin_required
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