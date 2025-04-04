from django.urls import reverse
from django.contrib.auth.models import Group
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .models import User

from unittest.mock import patch

from .utils import custom_token_generator


class UserAuthTests(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.test_email = "test@example.com"
        self.test_password = "securePassword123"
        self.phone_number = "9999999999"
        self.country_code = "+91"
        self.user = User.objects.create_user(
            email=self.test_email,
            password=self.test_password,
            phone_number=self.phone_number,
            first_name="John",
            last_name="Doe",
            is_verified=True
        )

    def test_register_user_success(self):
        url = reverse("register")
        Group.objects.get_or_create(name="customer")  # Ensure group exists

        data = {
            "email": "newuser@example.com",
            "password": "newpass123",
            "first_name": "New",
            "last_name": "User",
            "phone_number": "8888888888",
            "role": "customer"
        }

        with patch("authentication.views.send_verification_email") as mock_send_email:
            mock_send_email.return_value = True
            response = self.client.post(url, data, format="json")
            self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_login_user_success(self):
        url = reverse("login")
        data = {
            "email": self.test_email,
            "password": self.test_password,
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access_token", response.data)

    def test_login_unverified_user(self):
        self.user.is_verified = False
        self.user.save()
        url = reverse("login")
        data = {"email": self.test_email, "password": self.test_password}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_request_otp_success(self):
        url = reverse("request-otp")
        with patch("authentication.views.send_otp_sms") as mock_sms:
            mock_sms.return_value = True
            response = self.client.post(url, {"phone_number": self.phone_number, "contry_code": self.country_code})
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_verify_otp_success(self):
        self.user.generate_otp()
        self.user.save()
        url = reverse("verify-otp")
        response = self.client.post(url, {"phone_number": self.phone_number, "otp": self.user.otp})
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_request_success(self):
        url = reverse("password-reset")
        with patch("authentication.views.send_password_reset_email") as mock_reset_email:
            mock_reset_email.return_value = True
            response = self.client.post(url, {"email": self.test_email})
            self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_password_reset_confirm_success(self):
        token = custom_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(f"user-{self.user.pk}"))
        url = reverse("password-reset-confirm", kwargs={"uidb64": uidb64, "token": token})
        data = {"password": "newsecurepass123"}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_profile_update(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("user-profile-update")
        response = self.client.put(url, {"first_name": "Updated"})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["data"]["first_name"], "Updated")

    def test_admin_dashboard(self):
        # Create and assign admin group
        group, _ = Group.objects.get_or_create(name="admin")
        self.user.groups.add(group)
        self.user.role = "admin"
        self.user.save()
        self.client.force_authenticate(user=self.user)
        url = reverse("admin-dashboard")
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_dashboard_permission(self):
        self.client.force_authenticate(user=self.user)
        url = reverse("user-dashboard")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
