from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps


app = Flask(__name__)
app.secret_key = "Erbeson-Brito-de-Souza"

def get_db():
    conn = sqlite3.connect("usuarios_db")
    conn.row_factory = sqlite3.Row
    return conn

def criar_tabela():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                senha_hash TEXT NOT NULL
            )
        """)
def login_obrigatorio(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "usuario_id" not in  session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]
        confirmar = request.form["confirmar-senha"]

        if senha != confirmar:
            flash("As senhas não são iguais.")
            return redirect.form(url_for("cadastro"))
        try:
            with get_db() as conn:
                cursor = conn.execute(
                    "INSERT INTO usuarios (email, senha_hash) VALUES (?, ?)", (email, generate_password_hash(senha)),
                )
                novo_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            flash("Esse email já está cadastrado.")
            return redirect(url_for("cadastro"))
        session["usuario_id"] = novo_id
        session["email"] = email
        return redirect(url_for("index"))
    return render_template("cadastro.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        senha = request.form["senha"]

        with get_db() as conn:
            usuario = conn.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone()
        if usuario and check_password_hash(usuario["senha_hash"], senha):
            session["usuario_id"] = usuario["id"]
            session["email"] = usuario["email"]
            return redirect(url_for("index"))
        flash("Email ou senha incorretos.")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html", email=session.get("email"))

@app.route("/logout")

def logout():
    session.clear()
    return redirect(url_for("login"))

criar_tabela()

if __name__ == "__main__":
    app.run(debug=True)