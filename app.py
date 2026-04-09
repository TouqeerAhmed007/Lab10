"""
=============================================================
  SECURE FLASK APP  —  Lab-07 Secure Coding Practices
  NUCES Islamabad  |  Secure Software Design – Spring 2026
=============================================================
Security tasks implemented:
  Task 1 – Secure Input Handling      (WTForms + validators)
  Task 2 – Parameterized Queries      (SQLAlchemy ORM)
  Task 3 – CSRF + Session Security    (Flask-WTF CSRFProtect)
  Task 4 – Secure Error Handling      (custom 404 / 500 pages)
  Task 5 – Secure Password Storage    (flask-bcrypt hashing)
  
  LAB 08 Security tasks implemented:
  Task 1 – Security Headers           (Flask-Talisman)
  Task 2 – Rate Limiting              (Flask-Limiter)
  Task 3 – Secure File Uploads        (secure_filename)
  Task 4 – Env Secret Management      (python-dotenv)
  Task 5 – Role-Based Access Control  (Custom Decorator)
"""

import os
from functools import wraps
from flask import (
    Flask, render_template, redirect, url_for,
    flash, session, abort, request
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect

# --- LAB 08 IMPORTS ---
from dotenv import load_dotenv
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename

# Task 4: Load .env variables
load_dotenv()

# ── App factory ─────────────────────────────────────────────
app = Flask(__name__)

# ── Configuration ────────────────────────────────────────────
# Task 4: Use os.getenv
app.config["SECRET_KEY"]             = os.getenv('FLASK_SECRET_KEY', os.urandom(32)) 
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lab8_fresh_database.db"  
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Task 3 – secure cookie settings
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    WTF_CSRF_ENABLED        = True,
    WTF_CSRF_TIME_LIMIT     = 3600,
)

# Task 3: Secure Upload Config
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'txt'}
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Task 1: Talisman Security Headers
Talisman(app, content_security_policy=None, force_https=False)

# Task 2: Rate Limiter Setup
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# ── Extensions ───────────────────────────────────────────────
db     = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf   = CSRFProtect(app)

# ── Models ───────────────────────────────────────────────────
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20),  unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # Task 5: RBAC column
    is_admin = db.Column(db.Boolean, default=False)

class Contact(db.Model):
    id      = db.Column(db.Integer, primary_key=True)
    name    = db.Column(db.String(80),   nullable=False)
    email   = db.Column(db.String(120),  nullable=False)
    phone   = db.Column(db.String(20))
    website = db.Column(db.String(200))
    message = db.Column(db.Text,         nullable=False)

with app.app_context():
    db.create_all()

from forms import RegistrationForm, LoginForm, ContactForm

# ── Lab 08 Helper Functions ──────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            abort(403)
        user = User.query.get(session["user_id"])
        if not user or not user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return redirect(url_for("register"))

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing = User.query.filter_by(username=form.username.data).first()
        if existing:
            flash("Username already taken.", "danger")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        
        # Make the very first user an admin for testing
        is_first_user = User.query.count() == 0

        new_user = User(
            username = form.username.data,
            email    = form.email.data,
            password = hashed_pw,
            is_admin = is_first_user
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account created! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute") # Task 2: Rate limit login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session["user_id"]   = user.id
            session["username"]  = user.username
            session.permanent    = True
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials. Please try again.", "danger")

    return render_template("login.html", form=form)

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        entry = Contact(
            name    = form.name.data,
            email   = form.email.data,
            phone   = form.phone.data,
            website = form.website.data,
            message = form.message.data,
        )
        db.session.add(entry)
        db.session.commit()
        flash("Your message has been received. Thank you!", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", form=form)

# Task 3: Secure File Upload Route
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    if request.method == "POST":
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename) 
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded securely!', 'success')
            return redirect(url_for("dashboard"))
        else:
            flash('Invalid file type! Allowed: png, jpg, jpeg, pdf, txt', 'danger')
            
    return render_template('upload.html')

# Task 5: Role-Based Access Control Route
@app.route("/admin/dashboard")
@admin_required 
def admin_dashboard():
    return render_template('admin.html')

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ════════════════════════════════════════════════════════════
#  Custom Error Handlers
# ════════════════════════════════════════════════════════════
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

# TEMPORARILY DISABLED: So we can see real crash reports if they happen!
# @app.errorhandler(500)
# def internal_server_error(e):
#     return render_template("500.html"), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

if __name__ == "__main__":
    # SET TO TRUE: Shows you exact errors in the browser if anything breaks
    app.run(debug=True, port=5001)