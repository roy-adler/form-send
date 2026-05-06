import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from flask import Flask, redirect, render_template, request, session, url_for
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Optional
from werkzeug.middleware.proxy_fix import ProxyFix

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

if _env_bool("TRUST_PROXY", False):
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1,
        x_host=1,
        x_port=1,
        x_prefix=1,
    )


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


def _show_contact_heading() -> bool:
    """Hide the main 'Contact' title in iframes; keep it on direct visits to the site."""
    if request.args.get("embed", "").lower() in ("1", "true", "yes"):
        return False
    return (request.headers.get("Sec-Fetch-Dest") or "").lower() != "iframe"


def _embedded_request() -> bool:
    return not _show_contact_heading()


def _allow_host_landing_page() -> bool:
    """If False, GET / as a top-level page shows no form (iframe embeds still work)."""
    return _env_bool("ALLOW_HOST_LANDING_PAGE", True)


@app.after_request
def security_headers(response):
    raw = os.environ.get("FRAME_ANCESTORS")
    ancestors = (raw or "*").strip() or "*"
    response.headers["Content-Security-Policy"] = f"frame-ancestors {ancestors}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


class ContactForm(FlaskForm):
    name = StringField(
        "Name",
        validators=[Optional(), Length(max=200)],
        render_kw={"placeholder": "Anonymus"},
    )
    email = StringField(
        "Email",
        validators=[Optional(), Email(), Length(max=320)],
        render_kw={"placeholder": "Anonymus"},
    )
    message = TextAreaField(
        "Message",
        validators=[DataRequired(), Length(min=4, max=20000)],
        render_kw={"minlength": "4", "aria-describedby": "message-hint"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}, 200


@app.route("/", methods=["GET", "POST"])
def index():
    allow_host = _allow_host_landing_page()
    embedded = _embedded_request()

    if request.method == "GET":
        if not allow_host and not embedded:
            session.pop("form_surface", None)
            return render_template("host_landing_disabled.html"), 403
        session["form_surface"] = "embed" if embedded else "direct"

    form = ContactForm()
    if form.validate_on_submit():
        if not allow_host and session.get("form_surface") != "embed":
            return render_template("host_landing_disabled.html"), 403
        raw_name = (form.name.data or "").strip()
        raw_email = (form.email.data or "").strip()
        message = (form.message.data or "").strip()
        name = raw_name or "Anonymus"
        subject = "New contact form message"
        body = (
            f"Name: {name}\n"
            f"Email: {raw_email or '(not provided)'}\n\n"
            f"{message}\n"
        )
        try:
            reply_to = (
                formataddr((name, raw_email))
                if raw_email
                else None
            )
            _smtp_send(
                subject=subject,
                body=body,
                reply_to=reply_to,
            )
        except Exception as exc:  # noqa: BLE001
            app.logger.exception("Failed to send mail: %s", exc)
            return render_template(
                "index.html",
                form=form,
                error="Could not send email. Try again later.",
                show_contact_heading=_show_contact_heading(),
            ), 502
        return redirect(url_for("thanks"), code=303)

    return render_template(
        "index.html",
        form=form,
        error=None,
        show_contact_heading=_show_contact_heading(),
    )


@app.get("/thanks")
def thanks():
    return render_template("thanks.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
