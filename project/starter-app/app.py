"""
NoteVault — a small team note-sharing web app + JSON API (term-project starter).

This is your TERM-PROJECT TARGET. It is a normal-looking app that contains several
realistic security weaknesses. Your job (see project/README.md): threat-model it,
find and document the vulnerabilities, fix them, and harden the build/release.

We do NOT list the vulnerabilities here — finding them is the assignment.

Run:  docker compose up   (then http://localhost:8080)
"""
import hashlib
import hmac
import os
import sqlite3

import jwt  # PyJWT
from flask import Flask, request, jsonify, render_template_string, redirect, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
DB = "/tmp/notevault.db"
SECRET = os.environ.get("SECRET_KEY") or os.urandom(32).hex()

# Anti-copying: every team's build is seeded with a marker derived from their own TEAM_ID, so
# any evidence a team submits (SQLi dump, IDOR response, admin-panel screenshot) that shows the
# admin's notes carries a value traceable to exactly one team — see instructor/anti-cheating.md.
TEAM_ID = os.environ.get("TEAM_ID", "unassigned")
TEAM_SALT = os.environ.get("TEAM_SALT", "notevault-anti-copy-dev-salt")


def team_marker():
    return hmac.new(TEAM_SALT.encode(), TEAM_ID.encode(), hashlib.sha256).hexdigest()[:12]


PAGE = """
<!doctype html><title>NoteVault</title>
<h1>NoteVault</h1>
{% if user %}<p>Signed in as <b>{{ user }}</b> · <a href="/logout">logout</a>
  {% if is_admin %}· <a href="/admin">admin</a>{% endif %}</p>
<form method=post action="/notes"><input name=title placeholder=title>
  <input name=body placeholder=note><button>Add note</button></form>
<h3>Your notes</h3>
<ul>
{% for note in notes %}
  <li>#{{ note.id }} <b>{{ note.title }}</b>: {{ note.body }}</li>
{% endfor %}
</ul>
<form action="/search"><input name=q placeholder="search notes"><button>Search</button></form>
{% else %}
<form method=post action="/login">user <input name=username> pass <input name=password type=password>
  <button>Login</button></form>
<form method=post action="/register">new: <input name=username> <input name=password type=password>
  <button>Register</button></form>
{% endif %}
"""


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def seed():
    con = db()
    con.executescript(
        "DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS notes;"
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);"
        "CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT, title TEXT, body TEXT);"
    )
    con.executemany("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                    [("alice", generate_password_hash("alicepw"), "user"),
                     ("admin", generate_password_hash("admin123"), "admin")])
    con.executemany("INSERT INTO notes (owner, title, body) VALUES (?,?,?)",
                    [("alice", "groceries", "milk, eggs"),
                     ("admin", "infra", "prod db password is hunter2"),
                     ("admin", "build-tag", "team=%s marker=%s" % (TEAM_ID, team_marker()))])
    con.commit()
    con.close()


def current_user():
    tok = request.cookies.get("session", "")
    if not tok:
        return None
    try:
        data = jwt.decode(tok, SECRET, algorithms=["HS256"])
        return data.get("sub")
    except Exception:
        return None


def role_of(username):
    con = db()
    r = con.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    return r["role"] if r else None


@app.route("/")
def home():
    user = current_user()
    notes = []
    if user:
        con = db()
        notes = con.execute(
            "SELECT id, title, body FROM notes WHERE owner = ?",
            (user,),
        ).fetchall()
        con.close()
    return render_template_string(PAGE, user=user, is_admin=(user and role_of(user) == "admin"),
                                  notes=notes)


@app.route("/register", methods=["POST"])
def register():
    req_json = request.get_json(silent=True) or {}
    username = request.form.get("username") or req_json.get("username")
    password = request.form.get("password") or req_json.get("password")
    role = "user"
    con = db()
    con.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
                (username, generate_password_hash(password), role))
    con.commit()
    con.close()
    return redirect("/")


@app.route("/login", methods=["POST"])
def login():
    req_json = request.get_json(silent=True) or {}
    username = request.form.get("username") or req_json.get("username")
    password = request.form.get("password") or req_json.get("password")
    con = db()
    row = con.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    con.close()
    if not row or not check_password_hash(row["password"], password or ""):
        return "login failed", 401
    tok = jwt.encode({"sub": username}, SECRET, algorithm="HS256")
    if isinstance(tok, bytes):
        tok = tok.decode("utf-8")
    resp = make_response(redirect("/"))
    resp.set_cookie("session", tok, httponly=True, secure=True, samesite="Lax")
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@app.route("/notes", methods=["POST"])
def add_note():
    user = current_user()
    if not user:
        return "auth required", 401
    title = request.form.get("title", "")
    body = request.form.get("body", "")
    con = db()
    con.execute("INSERT INTO notes (owner,title,body) VALUES (?,?,?)", (user, title, body))
    con.commit()
    con.close()
    return redirect("/")


@app.route("/api/notes/<int:nid>")
def api_note(nid):
    user = current_user()
    if not user:
        return jsonify(error="auth required"), 401
    con = db()
    r = con.execute(
        "SELECT id, owner, title, body FROM notes "
        "WHERE id = ? AND owner = ?",
        (nid, user),
    ).fetchone()
    con.close()
    return (jsonify(dict(r)) if r else (jsonify(error="not found"), 404))


@app.route("/search")
def search():
    user = current_user()
    if not user:
        return "auth required", 401
    term = request.args.get("q", "")
    con = db()
    rows = con.execute(
        "SELECT id, title, body FROM notes "
        "WHERE owner = ? AND body LIKE ?",
        (user, f"%{term}%"),
    ).fetchall()
    con.close()
    return render_template_string(
        """
        <a href="/">back</a>
        <ul>
        {% for note in notes %}
          <li>{{ note.title }}: {{ note.body }}</li>
        {% endfor %}
        </ul>
        """,
        notes=rows,
    )


@app.route("/admin")
def admin():
    user = current_user()
    if not user or role_of(user) != "admin":
        return "forbidden", 403
    con = db()
    rows = con.execute("SELECT id,username,password,role FROM users").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])


@app.route("/export")
def export():
    if not current_user():
        return "auth required", 401
    fmt = request.args.get("fmt", "txt")
    if fmt not in {"txt", "json"}:
        return "unsupported format", 400
    return "<pre>exporting notes as %s</pre>" % fmt


if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=8080, debug=False)
