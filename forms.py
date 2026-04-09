# forms.py  —  WTForms classes with full validation (Task 1)
import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import (
    DataRequired, Email, Length, Regexp, ValidationError
)

# ── Shared custom validator: block SQL keywords ──────────────
SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|OR|AND|EXEC|CAST|CHAR|DECLARE)\b",
    re.IGNORECASE
)

def no_sql_injection(form, field):
    if SQL_KEYWORDS.search(field.data):
        raise ValidationError("Input contains forbidden keywords.")

def no_html_tags(form, field):
    if re.search(r"<[^>]+>", field.data):
        raise ValidationError("HTML tags are not allowed.")


# ── Registration Form ────────────────────────────────────────
class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(min=2, max=20),
            Regexp(
                r"^[A-Za-z0-9_]+$",
                message="Username: letters, numbers, underscores only."
            ),
            no_sql_injection,
        ],
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, message="Password must be at least 8 characters."),
            Regexp(
                r"^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*])",
                message="Password needs 1 uppercase, 1 number, 1 special char.",
            ),
        ],
    )
    submit = SubmitField("Sign Up")


# ── Login Form ───────────────────────────────────────────────
class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=2, max=20), no_sql_injection],
    )
    password = PasswordField("Password", validators=[DataRequired()])
    submit   = SubmitField("Login")


# ── Contact Form ─────────────────────────────────────────────
class ContactForm(FlaskForm):
    name = StringField(
        "Your Name",
        validators=[
            DataRequired(),
            Length(max=80),
            no_html_tags,
            no_sql_injection,
        ],
    )
    email = StringField(
        "Your Email Address",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    phone = StringField(
        "Your Phone Number (optional)",
        validators=[
            Length(max=20),
            Regexp(
                r"^[\d\s\+\-\(\)]*$",
                message="Phone: digits, spaces, +, -, () only."
            ),
        ],
    )
    website = StringField(
        "Your Web Site (optional)",
        validators=[
            Length(max=200),
            Regexp(
                r"^(https?://.*)?$",
                message="Website must start with http:// or https://",
            ),
            no_sql_injection,
        ],
    )
    message = TextAreaField(
        "Message",
        validators=[
            DataRequired(),
            Length(min=10, max=1000),
            no_html_tags,
            no_sql_injection,
        ],
    )
    submit = SubmitField("Submit")
