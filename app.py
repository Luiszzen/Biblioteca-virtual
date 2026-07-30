import os
from functools import wraps

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from better_profanity import profanity
from datetime import datetime

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
profanity.load_censor_words()
db = SQL("sqlite:///library.db")


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
    """Register a new user."""

    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not username:
        flash("must provide username")
        return render_template("register.html")
    if not password:
        flash("must provide password")
        return render_template("register.html")
    if password != confirmation:
        flash("passwords must match")
        return render_template("register.html")

    existing = db.execute("SELECT username FROM users WHERE username = ?", username)
    if existing:
        flash("that username is already taken")
        return render_template("register.html")

    password_hashed = generate_password_hash(password)
    db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hashed)

    new_user = db.execute("SELECT * FROM users WHERE username = ?", username)
    session["user_id"] = new_user[0]["id"]

    return redirect("/")



    """Add a new book to the catalog."""

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

        # Block offensive titles/authors before they hit the catalog
        if profanity.contains_profanity(title) or profanity.contains_profanity(author or ""):
            return apology("inappropriate content detected", 400)

        db.execute(
            """INSERT INTO books (title, author, publisher, year, isbn, language, category, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'available')""",
            title, author, publisher, year, isbn, language, category
        )

        flash("Book added!")
        return redirect("/add_book")

    # FRONTEND: add_book.html needs a form posting to /add_book with fields
    # named "title", "author", "publisher", "year", "isbn", "language", "category"
    return render_template("add_book.html")


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


@app.route("/return_book", methods=["GET", "POST"])
@login_required
def return_book():
    """Solicita devolver un libro -- queda pendiente hasta que un admin lo apruebe."""

    if request.method == "POST":
        loan_id = request.form.get("loan_id")

        if not loan_id:
            return apology("must select a loan", 400)

        loan = db.execute(
            "SELECT * FROM loans WHERE id = ? AND user_id = ? AND returned_at IS NULL",
            loan_id, session["user_id"]
        )
        if len(loan) != 1:
            return apology("active loan not found", 404)

        existing = db.execute(
            "SELECT id FROM requests WHERE type = 'return' AND loan_id = ? AND status = 'pending'",
            loan_id
        )
        if existing:
            return apology("this loan already has a pending return request", 400)

        db.execute(
            "INSERT INTO requests (type, user_id, loan_id, book_id, created_at) VALUES ('return', ?, ?, ?, ?)",
            session["user_id"], loan_id, loan[0]["book_id"], datetime.now().isoformat()
        )

        flash("Solicitud de devolución enviada. Un administrador debe aprobarla.")
        return redirect("/")

    active_loans = db.execute(
        """SELECT loans.id AS loan_id, books.title
           FROM loans JOIN books ON loans.book_id = books.id
           WHERE loans.user_id = ? AND loans.returned_at IS NULL""",
        session["user_id"]
    )
    return render_template("return.html", loans=active_loans)


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

    elif req["type"] == "return":
        db.execute(
            "UPDATE loans SET returned_at = ? WHERE id = ?",
            datetime.now().isoformat(), req["loan_id"]
        )
        db.execute("UPDATE books SET status = 'available' WHERE id = ?", req["book_id"])

    elif req["type"] == "add_book":
        db.execute(
            """INSERT INTO books (title, author, publisher, year, isbn, language, category, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'available')""",
            req["title"], req["author"], req["publisher"], req["year"],
            req["isbn"], req["language"], req["category"]
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


@app.route("/history")
@login_required
def history():
    """Show the current user's full borrow history."""

    loans = db.execute(
        """SELECT books.title, loans.borrowed_at, loans.returned_at
           FROM loans JOIN books ON loans.book_id = books.id
           WHERE loans.user_id = ?
           ORDER BY loans.borrowed_at DESC""",
        session["user_id"]
    )

    # FRONTEND: history.html -> loop over `loans`, e.g.
    #     {% for loan in loans %}
    #         <p>{{ loan.title }} - borrowed {{ loan.borrowed_at }}
    #            {% if loan.returned_at %}(returned {{ loan.returned_at }}){% endif %}</p>
    #     {% endfor %}
    return render_template("history.html", loans=loans)


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