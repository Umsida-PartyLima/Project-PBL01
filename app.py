import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from itsdangerous import URLSafeTimedSerializer
import logging
from logging.handlers import RotatingFileHandler
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Gunakan kunci rahasia yang aman

# Konfigurasi session untuk keamanan
app.config['SESSION_COOKIE_SECURE'] = True  # Hanya kirim cookie di HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Batasi akses JavaScript ke cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Cegah pengiriman cookie lintas situs

# Buat serializer untuk token aman
serializer = URLSafeTimedSerializer(app.secret_key)

# Konfigurasi logging
log_handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
log_handler.setLevel(logging.INFO)
log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)
app.logger.addHandler(log_handler)

# Buat koneksi ke database SQLite
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row  # Supaya hasil query berbentuk dictionary-like
    return conn

# Buat tabel pengguna jika belum ada
def create_user_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

# Buat tabel teks yang diunggah
def create_uploaded_texts_table():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS uploaded_texts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            text_content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()
    


@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            # Menyimpan data user dan status admin di session
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]  # Simpan status admin

            flash("Login berhasil!", "success")
            # Arahkan berdasarkan status admin
            return redirect(url_for("admin_dashboard" if user["is_admin"] else "dashboard"))
        else:
            flash("Username atau password salah.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")

        if not username or not password or not email:
            flash("Semua bidang wajib diisi.", "danger")
            return redirect(url_for("register"))

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                (username, password, email)
            )
            conn.commit()
            conn.close()
            flash("Akun berhasil dibuat! Silakan login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username atau email sudah digunakan. Coba yang lain.", "danger")
            conn.close()
    return render_template("register.html")

@app.route("/admin", methods=["GET"])
def admin_dashboard():
    if "user_id" not in session or not session.get("is_admin"):  # Pastikan hanya admin yang bisa akses
        flash("Anda tidak memiliki akses ke halaman ini.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()

    # Ambil semua data pengguna
    users = conn.execute("SELECT id, username, email FROM users").fetchall()

    # Ambil semua data postingan
    posts = conn.execute("""
        SELECT 
            u.username, 
            t.text_content, 
            t.created_at 
        FROM 
            uploaded_texts t 
        JOIN 
            users u 
        ON 
            t.user_id = u.id 
        ORDER BY t.created_at DESC
    """).fetchall()

    conn.close()

    # Render data ke template HTML
    return render_template("admin_dashboard.html", users=users, posts=posts)


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:  # Periksa apakah pengguna sudah login
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("login"))

    user_id = session["user_id"]  # Ambil user ID dari session
    username = session["username"]  # Ambil username dari session

    conn = get_db_connection()

    # Proses penyimpanan teks baru
    if request.method == "POST":
        text_content = request.form.get("text_content")

        if not text_content.strip():  # Validasi teks tidak boleh kosong
            flash("Teks tidak boleh kosong!", "danger")
            return redirect(url_for("dashboard"))

        conn.execute(
            "INSERT INTO uploaded_texts (user_id, text_content) VALUES (?, ?)",
            (user_id, text_content)
        )
        conn.commit()
        flash("Teks berhasil diposting!", "success")

    # Ambil daftar teks yang sudah diposting oleh pengguna
    texts = conn.execute(
        "SELECT text_content, created_at FROM uploaded_texts WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()

    # Kirim username dan teks ke template
    return render_template("dashboard.html", username=username, texts=texts)

@app.route("/profile/<username>")
def profile(username):
    if "user_id" not in session:  # Periksa apakah pengguna sudah login
        flash("Silakan login terlebih dahulu.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        flash("Pengguna tidak ditemukan.", "danger")
        conn.close()
        return redirect(url_for("dashboard"))

    # Ambil postingan pengguna
    posts = conn.execute(
        """
        SELECT text_content, created_at 
        FROM uploaded_texts 
        WHERE user_id = ? 
        ORDER BY created_at DESC
        """,
        (user["id"],),
    ).fetchall()

    conn.close()
    return render_template("profile.html", username=user["username"], posts=posts)


@app.route("/logout")
def logout():
    if "user_id" in session:
        username = session.get("username")
        app.logger.info(f"User {username} logged out.")
    session.clear()
    flash("Anda telah logout.", "info")
    return redirect(url_for("login"))

@app.route("/generate_token/<username>")
def generate_token(username):
    # Contoh endpoint untuk membuat token aman
    token = serializer.dumps(username, salt="email-confirmation-salt")
    flash(f"Token untuk {username} dibuat: {token}", "info")
    return token

@app.route("/confirm_token/<token>")
def confirm_token(token):
    try:
        username = serializer.loads(token, salt="email-confirmation-salt", max_age=3600)
        flash(f"Token valid untuk {username}.", "success")
    except Exception as e:
        app.logger.error(f"Invalid or expired token: {str(e)}")
        flash("Token tidak valid atau sudah kedaluwarsa.", "danger")
    return redirect(url_for("login"))

if __name__ == "__main__":
    create_user_table()
    create_uploaded_texts_table()
    app.run(debug=True)
