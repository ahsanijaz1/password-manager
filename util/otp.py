import smtplib
import ssl
import random
import os
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(receiver_email, otp):
    subject = "Your Password Manager OTP Code"
    body = f"Your OTP code is: {otp}"

    em = EmailMessage()
    em['From'] = EMAIL_ADDRESS
    em['To'] = receiver_email
    em['Subject'] = subject
    em.set_content(body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(em)

    print("OTP sent to your email!")
