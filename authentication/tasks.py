from celery import shared_task
from django.core.mail import EmailMultiAlternatives, send_mail
from django.conf import settings
from twilio.rest import Client

@shared_task
def send_verification_email_task(email, subject, html_message):
    msg = EmailMultiAlternatives(subject, '', settings.DEFAULT_FROM_EMAIL, [email])
    msg.attach_alternative(html_message, "text/html")
    msg.send()
    return "Verification email sent"

@shared_task
def send_password_reset_email_task(subject, message, recipient_list):
    send_mail(subject, message, settings.EMAIL_HOST_USER, recipient_list)
    return "Password reset email sent"

@shared_task
def send_otp_sms_task(phone_number, otp):
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message = client.messages.create(
        body=f"Your OTP for login is: {otp}. It is valid for 5 minutes.",
        from_=settings.TWILIO_PHONE_NUMBER,
        to=f"+{phone_number}"
    )
    return message.sid
