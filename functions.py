import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import logging

load_dotenv()

# ─── Logging Setup ────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("user_auth")

# ─── JWT Config ───────────────────────────────────────────────────────────────
JWT_SECRET_KEY = secrets.token_hex(16)
TOKEN_LIFETIME_DAYS = 15          # Token 15 din valid rahega
VERIFY_CODE_MINUTES = 10          # Email verify code 10 minute mein expire

# ─── Mail Config ──────────────────────────────────────────────────────────────
MAIL_SERVER   = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT     = int(os.getenv("MAIL_PORT", 587))          # 587 = STARTTLS
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_SENDER   = os.getenv("MAIL_DEFAULT_SENDER")

# Password hashing context — ek jagah banao, baar baar nahi
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(plain: str) -> str:
    """Plain password ko hash karo."""
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Password verify karo."""
    return pwd_context.verify(plain, hashed)


def generate_token(email: str) -> str:
    """JWT token banao — 15 din valid."""
    try:
        payload = {
            "email": email,
            "exp": datetime.utcnow() + timedelta(days=TOKEN_LIFETIME_DAYS),
            "iat": datetime.utcnow(),
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
        logger.info(f"Token generated for email={email}")
        return token
    except Exception as e:
        logger.error(f"Token generation failed for email={email}: {e}")
        return None


def _send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Ek shared helper — STARTTLS use karta hai (port 587).
    SSL_WRONG_VERSION_NUMBER tab aata tha jab SMTP_SSL port 587 pe use kiya ja raha tha.
    Fix: sirf SMTP + starttls() use karo.
    """
    msg = MIMEMultipart()
    msg["From"]    = MAIL_SENDER
    msg["To"]      = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        logger.info(f"Connecting to SMTP {MAIL_SERVER}:{MAIL_PORT} for {to_email}")
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.ehlo()
        server.starttls()          # <-- SSL ka sahi tarika port 587 ke liye
        server.ehlo()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_SENDER, to_email, msg.as_string())
        server.quit()
        logger.info(f"Email sent successfully to {to_email} | subject='{subject}'")
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error(f"SMTP auth failed — check MAIL_USERNAME/MAIL_PASSWORD")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error sending to {to_email}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email to {to_email}: {e}")
        return False


def send_recovery_email(email: str, code: str) -> bool:
    subject = "Password Recovery Code"
    body = (
        f"Your password recovery code is: {code}\n\n"
        f"This code is valid for {VERIFY_CODE_MINUTES} minutes.\n"
        "If you did not request this, please ignore this email."
    )
    return _send_email(email, subject, body)


def send_verify_email_code(email: str, code: str) -> bool:
    subject = "Email Verification Code"
    body = (
        f"Your email verification code is: {code}\n\n"
        f"This code is valid for {VERIFY_CODE_MINUTES} minutes.\n"
        "If you did not request this, please ignore this email."
    )
    return _send_email(email, subject, body)


def generate_recovery_code() -> str:
    """4-digit numeric code."""
    return "".join(random.choices(string.digits, k=4))
