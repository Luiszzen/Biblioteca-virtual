import os
from functools import wraps

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from better_profanity import profanity
from datetime import datetime

app = Flask(__name__)
# NOTE: removed the duplicate "app = Flask(__name__)" that used to be here.
# Having it twice threw away the session config below before any routes ran.

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
profanity.load_censor_words()

# Open (or create) the database file. This is the piece that was missing
# before: cs50.SQL was imported but never actually pointed at a file.
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


# ---------------------------------------------------------------------------
# index.html  ->  GET /
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    """
    Home page. Shows a few recently-added or available books.
    FRONTEND: loop over `books` in index.html, e.g.
        {% for book in books %}
            <p>{{ book.title }} - {{ book.author }}</p>
        {% endfor %}
    """
    books = db.execute(
        "SELECT id, title, author, status FROM books ORDER BY id DESC LIMIT 10"
    )
    return render_template("index.html", books=books)


# ---------------------------------------------------------------------------
# log_in.html  ->  GET/POST /login
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in."""

    # Forget any user_id from a previous session first, on both GET and POST
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Basic validation
        if not username:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)

        # Look up the user
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )

        # Check that the username exists and the password hash matches
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("invalid username and/or password", 403)

        # Remember which user is logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    # GET request: just show the login form
    # FRONTEND: log_in.html needs a form posting to /login with
    # fields named exactly "username" and "password"
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    return redirect("/")


# ---------------------------------------------------------------------------
# register.html  ->  GET/POST /register
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user."""

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)
        if password != confirmation:
            return apology("passwords must match", 400)

        # Hash the password -- never store it in plain text
        hash_ = generate_password_hash(password)

        try:
            new_id = db.execute(
                "INSERT INTO users (username, hash) VALUES (?, ?)",
                username, hash_
            )
        except Exception:
            # Most likely a UNIQUE constraint failure on username
            return apology("username already taken", 400)

        # Log the new user in right away
        session["user_id"] = new_id
        return redirect("/")

    # FRONTEND: register.html needs a form posting to /register with
    # fields named "username", "password", "confirmation"
    return render_template("register.html")


# ---------------------------------------------------------------------------
# add_book.html  ->  GET/POST /add_book
# ---------------------------------------------------------------------------
@app.route("/add_book", methods=["GET", "POST"])
@login_required
def add_book():
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


# ---------------------------------------------------------------------------
# search.html  ->  GET /search
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    """Search the catalog by title or author."""

    query = request.args.get("q", "")
    books = []

    if query:
        like_query = f"%{query}%"
        books = db.execute(
            "SELECT * FROM books WHERE title LIKE ? OR author LIKE ?",
            like_query, like_query
        )

    # FRONTEND: search.html needs a GET form (action="/search") with an
    # input named "q", then loop over `books` to display results, e.g.
    #     {% for book in books %}
    #         <p>{{ book.title }} - {{ book.status }}</p>
    #     {% endfor %}
    return render_template("search.html", books=books, query=query)


# ---------------------------------------------------------------------------
# borrow.html  ->  GET/POST /borrow
# ---------------------------------------------------------------------------
@app.route("/borrow", methods=["GET", "POST"])
@login_required
def borrow():
    """Borrow an available book."""

    if request.method == "POST":
        book_id = request.form.get("book_id")

        if not book_id:
            return apology("must select a book", 400)

        book = db.execute("SELECT * FROM books WHERE id = ?", book_id)
        if len(book) != 1:
            return apology("book not found", 404)
        if book[0]["status"] != "available":
            return apology("book is already borrowed", 400)

        # Record the loan and flip the book's status
        db.execute(
            "INSERT INTO loans (book_id, user_id, borrowed_at) VALUES (?, ?, ?)",
            book_id, session["user_id"], datetime.now().isoformat()
        )
        db.execute("UPDATE books SET status = 'borrowed' WHERE id = ?", book_id)

        flash("Book borrowed!")
        return redirect("/")

    # Only offer books that are actually available
    available_books = db.execute("SELECT id, title, author FROM books WHERE status = 'available'")

    # FRONTEND: borrow.html needs a form posting to /borrow with a select
    # or radio input named "book_id", populated from `available_books`
    return render_template("borrow.html", books=available_books)


# ---------------------------------------------------------------------------
# return.html  ->  GET/POST /return_book
# ---------------------------------------------------------------------------
@app.route("/return_book", methods=["GET", "POST"])
@login_required
def return_book():
    """Return a book the current user has out."""

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

        db.execute(
            "UPDATE loans SET returned_at = ? WHERE id = ?",
            datetime.now().isoformat(), loan_id
        )
        db.execute("UPDATE books SET status = 'available' WHERE id = ?", loan[0]["book_id"])

        flash("Book returned!")
        return redirect("/")

    # Only the current user's currently-out books
    active_loans = db.execute(
        """SELECT loans.id AS loan_id, books.title
           FROM loans JOIN books ON loans.book_id = books.id
           WHERE loans.user_id = ? AND loans.returned_at IS NULL""",
        session["user_id"]
    )

    # FRONTEND: return.html needs a form posting to /return_book with a
    # select/radio input named "loan_id", populated from `active_loans`
    return render_template("return.html", loans=active_loans)


# ---------------------------------------------------------------------------
# history.html  ->  GET /history
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# report.html  ->  GET /report
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# review.html  ->  GET/POST /review
# ---------------------------------------------------------------------------
@app.route("/review", methods=["GET", "POST"])
@login_required
def review():
    """Leave a text review/comment on a book."""

    if request.method == "POST":
        book_id = request.form.get("book_id")
        comment = request.form.get("comment")

        if not book_id or not comment:
            return apology("must provide a book and a comment", 400)

        # Filter profanity out of reviews rather than rejecting outright
        clean_comment = profanity.censor(comment)

        # NOTE: this needs a `reviews` table (book_id, user_id, comment, created_at)
        # that isn't in schema.sql yet -- add it if you want reviews to persist.
        db.execute(
            "INSERT INTO reviews (book_id, user_id, comment, created_at) VALUES (?, ?, ?, ?)",
            book_id, session["user_id"], clean_comment, datetime.now().isoformat()
        )

        flash("Review submitted!")
        return redirect("/review")

    books = db.execute("SELECT id, title FROM books ORDER BY title")

    # FRONTEND: review.html needs a form posting to /review with a select
    # named "book_id" (from `books`) and a textarea named "comment"
    return render_template("review.html", books=books)


# ---------------------------------------------------------------------------
# apology.html  ->  used internally by the apology() helper below, not routed
# ---------------------------------------------------------------------------
def apology(message, code=400):
    """
    Render an error page. Called from other routes, e.g. return apology("...", 400).
    FRONTEND: apology.html should display `{{ message }}` and maybe `{{ code }}`
    """
    return render_template("apology.html", message=message, code=code), code


if __name__ == "__main__":
    app.run(debug=True)