import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from flask import Flask, redirect, render_template, url_for
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email, Length

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _mail_recipients() -> list[str]:
    raw = os.environ.get("MAIL_RECIPIENT") or os.environ.get("MAIL_RECIPIENTS")
    sender = os.environ["MAIL_SENDER"].strip()
    if not raw or not raw.strip():
        return [sender]
    recipients: list[str] = []
    for part in raw.replace(";", ",").split(","):
        addr = part.strip()
        if addr:
            recipients.append(addr)
    return recipients or [sender]


app = Flask(__name__)
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    if _env_bool("FLASK_DEBUG", False):
        _secret = "dev-only-insecure-secret"
    else:
        raise RuntimeError("SECRET_KEY is required (set a long random string).")
app.secret_key = _secret
_samesite = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax").strip()
if _samesite.lower() == "none":
    _samesite = "None"
elif _samesite.lower() == "strict":
    _samesite = "Strict"
else:
    _samesite = "Lax"
app.config["SESSION_COOKIE_SAMESITE"] = _samesite
app.config["SESSION_COOKIE_SECURE"] = _env_bool("SESSION_COOKIE_SECURE", False)
csrf = CSRFProtect(app)


def _smtp_send(subject: str, body: str, reply_to: str | None) -> None:
    host = os.environ["MAIL_SERVER"]
    port = int(os.environ.get("MAIL_PORT", "587"))
    username = os.environ["MAIL_USERNAME"]
    password = os.environ["MAIL_PASSWORD"]
    sender = os.environ["MAIL_SENDER"]
    use_tls = _env_bool("MAIL_USE_TLS", True)
    recipients = _mail_recipients()

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    if reply_to:
        msg["Reply-To"] = reply_to

    msg.set_content(body)

    # Port 465 is usually implicit TLS (SMTP_SSL); 587 typically uses STARTTLS.
    if port == 465:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, context=context) as server:
            server.login(username, password)
            server.send_message(msg)
        return

    with smtplib.SMTP(host, port) as server:
        if use_tls:
            server.starttls(context=ssl.create_default_context())
        server.login(username, password)
        server.send_message(msg)


@app.after_request
def security_headers(response):
    raw = os.environ.get("FRAME_ANCESTORS")
    ancestors = (raw or "*").strip() or "*"
    response.headers["Content-Security-Policy"] = f"frame-ancestors {ancestors}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=200)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=320)])
    message = TextAreaField("Message", validators=[DataRequired(), Length(max=20000)])


@app.get("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/", methods=["GET", "POST"])
def index():
    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data.strip()
        email = form.email.data.strip()
        message = form.message.data.strip()
        subject = "New contact form message"
        body = (
            f"Name: {name}\n"
            f"Email: {email}\n\n"
            f"{message}\n"
        )
        try:
            _smtp_send(
                subject=subject,
                body=body,
                reply_to=formataddr((name, email)) if name else email,
            )
        except Exception as exc:  # noqa: BLE001
            app.logger.exception("Failed to send mail: %s", exc)
            return render_template("index.html", form=form, error="Could not send email. Try again later."), 502
        return redirect(url_for("thanks"), code=303)

    return render_template("index.html", form=form, error=None)


@app.get("/thanks")
def thanks():
    return render_template("thanks.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
