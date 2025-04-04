import random
import uuid
from datetime import timedelta
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.timezone import now


class UserManager(BaseUserManager):
    """Custom manager for User model with email as the unique identifier."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # Hashes the password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('staff', 'Staff'),
        ('customer', 'Customer'),
    ]
    email = models.EmailField(unique=True)
    phone_number = models.BigIntegerField(unique=True)
    password = models.CharField(max_length=255)  # Ensure proper hashing
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='customer')
    # Email Verification
    verification_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False, null=True)

    # OTP Authentication
    otp = models.CharField(max_length=6, null=True, blank=True)
    otp_expiry = models.DateTimeField(null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    # Permissions
    groups = models.ManyToManyField(
        "auth.Group", related_name="custom_users", blank=True
    )

    # Remove username field (if email is the primary identifier)
    username = None

    # Define authentication field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'phone_number']

    objects = UserManager()  # Use custom manager

    def __str__(self):
        return self.email

    def generate_otp(self):
        """Generate a 6-digit OTP with 5-minute expiry."""
        self.otp = str(random.randint(100000, 999999))
        self.otp_expiry = now() + timedelta(minutes=5)
        self.save()

    def is_otp_valid(self, entered_otp):
        """Check if OTP is correct and not expired."""
        return self.otp == entered_otp and self.otp_expiry and now() < self.otp_expiry

    def clear_otp(self):
        """Clear OTP after successful verification."""
        self.otp = None
        self.otp_expiry = None
        self.save()
    def check_password(self, raw_password):
        """Check if the entered password matches the stored hash."""
        return check_password(raw_password, self.password)

