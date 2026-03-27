import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
load_dotenv()
def send_email_alert(ip, score, level):
    sender_email = os.getenv("EMAIL_USER")
    app_password = os.getenv("EMAIL_PASS")
    receiver_email = os.getenv("ALERT_EMAIL")

    subject = f"🚨 Security Alert for {ip}"

    body = f"""
    ALERT!

    Target: {ip}
    Risk Score: {score}
    Risk Level: {level}

    Immediate action required.
    """

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        return True

    except Exception as e:
        print("Email error:", e)
        return False