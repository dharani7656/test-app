import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv


load_dotenv()
def send_phishing_alert_email(user_email, subject, sender):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = os.getenv("SENDER_EMAIL") 
    smtp_password = os.getenv("APP_PASSWORD")  # 🔑 Replace with your App Password

    msg = MIMEMultipart()
    msg['From'] = smtp_user
    msg['To'] = user_email
    msg['Subject'] = "⚠️ Phishing Email Alert!"

    body = f"""
    ⚠️ Phishing Email Detected!

    📨 Subject: {subject}
    🧑‍💻 From: {sender}

    Please be cautious and avoid clicking on any suspicious links.

    Stay Safe,
    Your Security Team
    """

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, user_email, msg.as_string())
        server.quit()
        print(f"✅ Alert email sent to {user_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
