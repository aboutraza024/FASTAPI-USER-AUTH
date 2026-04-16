import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import timedelta
import secrets
load_dotenv()


JWT_SECRET_KEY = secrets.token_hex(16)
JWT_EXPIRATION_DELTA = timedelta(minutes=60)  

MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_PORT = os.getenv("MAIL_PORT")
MAIL_USE_SSL = os.getenv("MAIL_USE_SSL")
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER")

def generate_token(email: str) -> str:
    try:
        payload = {
            "email": email,
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")
    except Exception as e:
        return False

def send_recovery_email(email: str, code: str):
    subject = 'Password Recovery Code'
    body = f'Your recovery code is: {code}'

    # Create message
    msg = MIMEMultipart()
    msg['From'] = MAIL_DEFAULT_SENDER
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to SMTP server
        server = smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT) if MAIL_USE_SSL else smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        server.connect(MAIL_SERVER, MAIL_PORT)
        server.ehlo()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        
        # Send email
        server.sendmail(MAIL_DEFAULT_SENDER, email, msg.as_string())
        
        # Close connection
        server.quit()
        
        print(f"Email sent to {email} with recovery code.")
        return "success"
    except Exception as e:
        print(f"Error sending email: {e}")

def send_verify_email_code(email: str, code: str):
    subject = "Email verify Code"
    body = f"Your verify code is: {code}"

    msg = MIMEMultipart()
    msg["From"] = MAIL_DEFAULT_SENDER
    msg["To"] = email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", MAIL_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()

        server.login(MAIL_USERNAME, MAIL_PASSWORD)

        server.sendmail(MAIL_DEFAULT_SENDER, email, msg.as_string())

        server.quit()

        print(f"Email sent to {email}")
        return "success"

    except Exception as e:
        print("Error sending email:", e)
        return None

def generate_recovery_code() -> str:
    return ''.join(random.choices(string.digits, k=4))