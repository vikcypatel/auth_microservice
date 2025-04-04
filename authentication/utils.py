from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from authentication.tasks import send_verification_email_task, send_otp_sms_task, send_password_reset_email_task
import six

class CustomTokenGenerator(PasswordResetTokenGenerator):
    """Custom token generator that does not require last_login."""

    def _make_hash_value(self, user, timestamp):
        return six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_verified)

custom_token_generator = CustomTokenGenerator()


def send_verification_email(email, subject, message):
    send_verification_email_task.delay(email, subject, message)
    return {"status": "success", "message": "Email sent successfully!"}


def send_otp_sms(phone_number, otp):
    send_otp_sms_task.delay(phone_number, otp)
    return {"status": "success", "message": "OTP sent successfully!"}


def send_password_reset_email(user):
    uidb64 = urlsafe_base64_encode(force_bytes(f"t-{user.pk}"))
    token = custom_token_generator.make_token(user)
    reset_link = f"http://localhost:3000/reset-password/{uidb64}/{token}/"
    subject = "Password Reset Request"
    message = f"Hi {user.first_name},\n\nClick the link below to reset your password:\n{reset_link}"
    send_password_reset_email_task.delay(subject, message, [user.email])
