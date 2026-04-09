"""
=============================================================
  VULNERABLE FLASK APP  --  DO NOT DEPLOY
=============================================================
"""

from flask import Flask, request, render_template_string, redirect, session
import sqlite3
import os # --- LAB 08 ADDITION: needed for uploads ---

app = Flask(__name__)
app.secret_key = "supersecret"
DB = "vuln_users.db"

# --- LAB 08 ADDITION: Insecure upload folder setup ---
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ── DB bootstrap ────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT,
            password TEXT,
            is_admin BOOLEAN DEFAULT 0 -- LAB 08 ADDITION: admin column
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT,
            phone TEXT,
            website TEXT,
            message TEXT
        )
    """)

    con.commit()
    con.close()

init_db()


# ── Base Template (CSS braces escaped) ──────────────────────
BASE = """
<!DOCTYPE html>
<html>
<head>
<title>Vulnerable App</title>
<style>
body {{ font-family: sans-serif; background:#f5f5f5; margin:0; }}

.nav {{ background:#c0392b; padding:12px 24px; color:white; }}

.nav a {{ color:white; margin-right:16px; text-decoration:none; }}

.box {{
max-width:500px;
margin:60px auto;
background:white;
padding:30px;
border-radius:8px;
box-shadow:0 2px 8px #0002;
}}

input, textarea {{
width:100%;
padding:8px;
margin:6px 0 14px;
border:1px solid #ccc;
border-radius:4px;
box-sizing:border-box;
}}

button {{
background:#c0392b;
color:white;
padding:10px 24px;
border:none;
border-radius:4px;
cursor:pointer;
width:100%;
}}

.warn {{
background:#fff3cd;
border:1px solid #ffc107;
padding:10px;
border-radius:4px;
margin-bottom:16px;
font-size:.85rem;
}}

.err {{ color:#c0392b; font-size:.85rem; }}

table {{ width:100%; border-collapse:collapse; }}

td, th {{
border:1px solid #ddd;
padding:8px;
text-align:left;
}}

th {{
background:#c0392b;
color:white;
}}
</style>
</head>

<body>

<div class="nav">
<b>⚠ VULNERABLE APP</b>
<a href="/vuln/register">Register</a>
<a href="/vuln/login">Login</a>
<a href="/vuln/contact">Contact</a>
<a href="/vuln/users">All Users</a>
<a href="/vuln/upload">Upload</a>
<a href="/vuln/admin">Admin Panel</a>
</div>

<div class="box">
{content}
</div>

</body>
</html>
"""


# ── Home ───────────────────────────────────────────────────
@app.route("/")
def home():

    content = """
    <h2>Welcome</h2>
    <p>This is a purposely vulnerable web application for security labs.</p>

    <ul>
    <li>SQL Injection demo</li>
    <li>XSS demo</li>
    <li>Plaintext password exposure</li>
    <li>No authentication controls</li>
    </ul>

    <p>Use the navigation bar to test the vulnerabilities.</p>
    """

    return render_template_string(BASE.format(content=content))


# ── Shortcuts ──────────────────────────────────────────────
@app.route("/login")
def login_shortcut():
    return redirect("/vuln/login")

@app.route("/register")
def register_shortcut():
    return redirect("/vuln/register")

@app.route("/contact")
def contact_shortcut():
    return redirect("/vuln/contact")


# ── Register ───────────────────────────────────────────────
@app.route("/vuln/register", methods=["GET","POST"])
def vuln_register():

    msg = ""

    if request.method == "POST":

        username = request.form.get("username","")
        email = request.form.get("email","")
        password = request.form.get("password","")

        con = sqlite3.connect(DB)
        cur = con.cursor()

        try:

            cur.execute(
                f"INSERT INTO users (username,email,password) VALUES ('{username}','{email}','{password}')"
            )

            con.commit()

            msg = f"<p class='err'>Registered! Password saved as: <b>{password}</b></p>"

        except Exception as e:

            msg = f"<p class='err'>DB Error: {e}</p>"

        finally:
            con.close()

    content = f"""

    <div class='warn'>⚠ VULNERABLE: SQL Injection + Plaintext Password</div>

    <h2>Register</h2>

    {msg}

    <form method="post">

    <input name="username" placeholder="Username (try admin'--)" />

    <input name="email" placeholder="Email"/>

    <input name="password" placeholder="Password"/>

    <button>Register</button>

    </form>
    """

    return render_template_string(BASE.format(content=content))


# ── Login ──────────────────────────────────────────────────
@app.route("/vuln/login", methods=["GET","POST"])
def vuln_login():

    msg = ""

    if request.method == "POST":

        username = request.form.get("username","")
        password = request.form.get("password","")

        con = sqlite3.connect(DB)
        cur = con.cursor()

        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        cur.execute(query)

        user = cur.fetchone()

        con.close()

        if user:

            session["user"] = username

            msg = f"<p style='color:green'>Logged in as {username}</p>"
            msg += f"<p class='err'>Executed Query: {query}</p>"

        else:

            msg = "<p class='err'>Invalid login</p>"

    content = f"""

    <div class='warn'>Try username: <code>' OR '1'='1'--</code></div>

    <h2>Login</h2>

    {msg}

    <form method="post">

    <input name="username" placeholder="Username"/>

    <input name="password" placeholder="Password"/>

    <button>Login</button>

    </form>
    """

    return render_template_string(BASE.format(content=content))


# ── Contact (XSS) ──────────────────────────────────────────
@app.route("/vuln/contact", methods=["GET","POST"])
def vuln_contact():

    msg = ""

    if request.method == "POST":

        name = request.form.get("name","")
        email = request.form.get("email","")
        phone = request.form.get("phone","")
        website = request.form.get("website","")
        message = request.form.get("message","")

        con = sqlite3.connect(DB)
        cur = con.cursor()

        cur.execute(
            f"INSERT INTO contacts VALUES (NULL,'{name}','{email}','{phone}','{website}','{message}')"
        )

        con.commit()
        con.close()

        msg = f"<p style='color:green'>Thanks {name}! Message: {message}</p>"

    content = f"""

    <div class='warn'>Try XSS: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></div>

    <h2>Contact</h2>

    {msg}

    <form method="post">

    <input name="name" placeholder="Name"/>

    <input name="email" placeholder="Email"/>

    <input name="phone" placeholder="Phone"/>

    <input name="website" placeholder="Website"/>

    <textarea name="message" placeholder="Message"></textarea>

    <button>Send</button>

    </form>
    """

    return render_template_string(BASE.format(content=content))


# ── Users list ─────────────────────────────────────────────
@app.route("/vuln/users")
def vuln_users():

    con = sqlite3.connect(DB)
    cur = con.cursor()

    cur.execute("SELECT id,username,email,password FROM users")

    rows = cur.fetchall()

    con.close()

    rows_html = ""

    for r in rows:
        rows_html += f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td style='color:red'>{r[3]}</td></tr>"

    content = f"""

    <div class='warn'>⚠ No authentication — anyone can view passwords</div>

    <h2>All Users</h2>

    <table>

    <tr>
    <th>ID</th>
    <th>Username</th>
    <th>Email</th>
    <th>Password</th>
    </tr>

    {rows_html}

    </table>
    """

    return render_template_string(BASE.format(content=content))

# --- LAB 08 ADDITION: Insecure File Upload (Fails Task 3) ---
@app.route("/vuln/upload", methods=["GET", "POST"])
def vuln_upload():
    msg = ""
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            # Allows path traversal and bad extensions (.exe)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
            msg = f"<p style='color:green'>File '{file.filename}' uploaded insecurely!</p>"

    content = f"""
    <div class='warn'>⚠ Vulnerable Upload — No extension checking or filename sanitization</div>
    <h2>Upload File</h2>
    {msg}
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button style="margin-top:10px">Upload Insecurely</button>
    </form>
    """
    return render_template_string(BASE.format(content=content))

# --- LAB 08 ADDITION: Unprotected Admin Route (Fails Task 5) ---
@app.route("/vuln/admin")
def vuln_admin():
    content = f"""
    <div class='warn'>⚠ Broken Access Control — Accessible without login!</div>
    <h2>Insecure Admin Panel</h2>
    <p>Welcome, unauthorized user! System secrets exposed here.</p>
    """
    return render_template_string(BASE.format(content=content))


if __name__ == "__main__":
    app.run(debug=True, port=5000)