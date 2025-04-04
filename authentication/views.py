import os
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import IsAuthenticated
from authentication.utils import send_otp_sms, send_password_reset_email, custom_token_generator
from django.shortcuts import get_object_or_404
from dotenv import load_dotenv
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import Group
from .utils import send_verification_email
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from .models import User
from .serializers import UserRegistrationSerializer, UserProfileUpdateSerializer
from .permission import IsAdmin
from django.contrib.auth.decorators import login_required, permission_required
from rest_framework.permissions import IsAuthenticated

# Create your views here.

load_dotenv()


@api_view(['POST'])
def register(request):
    serializer = UserRegistrationSerializer(data=request.data)
    host_url = os.getenv('HOST_URL')

    if serializer.is_valid():
        role = serializer.validated_data.get("role", "customer")  # default to 'customer'

        # for restrict create admin user
        # if role == "admin":
        #     return Response({"error": "Cannot register as admin."}, status=status.HTTP_403_FORBIDDEN)

        user = serializer.save()

        try:
            # Assign role group (optional)
            try:
                group = Group.objects.get(name=role)
                user.groups.add(group)
            except Group.DoesNotExist:
                pass  # If group isn't set up, silently continue

            # Send verification email
            subject = "Verify Your Email"
            verification_url = f"{host_url}/verify-email/{user.verification_token}/"
            message = f"""
                <h2>Welcome, {user.first_name}!</h2>
                <p>Thank you for registering. Click the link below to verify your email:</p>
                <a href="{verification_url}">Verify Email</a>
            """

            email_status = send_verification_email(user.email, subject, message)

            return Response(
                {
                    "message": "User registered successfully! Check your email for verification.",
                    "email_status": email_status,
                    "role": role
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            user.delete()  # Rollback if email fails
            return Response({'message': str(e)}, status=status.HTTP_406_NOT_ACCEPTABLE)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def verify_user(request, token):
    user = get_object_or_404(User, verification_token=token)
    if user.is_verified:
        return Response({"message": "Email is already verified!"}, status=status.HTTP_200_OK)

    user.is_verified = True
    user.save()

    return Response({"message": "Email verification successful!"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def login(request):
    email = request.data.get("email")
    password = request.data.get("password")

    # Validate input
    if not email or not password:
        return Response({"error": "Email and password are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

    # Check if password is correct
    if not user.check_password(password):
        return Response({"error": "Invalid email or password."}, status=status.HTTP_401_UNAUTHORIZED)

    # Check if user is verified
    if not user.is_verified:
        return Response({"error": "Please verify your email before logging in."}, status=status.HTTP_403_FORBIDDEN)

    # OTP is correct - clear it
    user.otp = None
    user.otp_expiry = None
    user.is_verified = True
    user.save()

    # Generate JWT tokens
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    return Response(
        {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": str(refresh),
            "user": {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "phone_number": user.phone_number,
            },
        },
        status=status.HTTP_200_OK,
    )

# step 2

@api_view(['POST'])
def request_otp(request):
    """Step 1: Validate phone number, then send OTP."""
    phone_number = request.data.get("phone_number")
    contry_code = request.data.get("contry_code")

    if not phone_number:
        return Response({"error": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(phone_number=phone_number)
    except User.DoesNotExist:
        return Response({"error": "Phone number not registered."}, status=status.HTTP_404_NOT_FOUND)

    # Generate OTP
    user.generate_otp()

    # Send OTP via SMS
    try:
        send_otp_sms(f"{contry_code}{phone_number}", user.otp)
    except Exception as e:
        return Response({"error": f"Failed to send OTP: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({"message": "OTP sent successfully to your phone number."}, status=status.HTTP_200_OK)


@api_view(['POST'])
def verify_otp(request):
    """Step 2: Verify OTP and log in the user."""
    phone_number = request.data.get("phone_number")
    otp = request.data.get("otp")

    if not phone_number or not otp:
        return Response({"error": "Phone number and OTP are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(phone_number=phone_number)
    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

    # Check if OTP is valid
    if not user.is_otp_valid(otp):
        return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

    # Clear OTP after successful login
    user.clear_otp()

    # Generate JWT token
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)

    return Response(
        {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": str(refresh),
            "user": {
                "id": user.id,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone_number": user.phone_number,
            },
        },
        status=status.HTTP_200_OK,
    )



@api_view(["POST"])
def password_reset(request):
    """Handle password reset request and send email with reset link"""


    user = User.objects.get(email=request.data.get("email"))
    if user:
        # Send password reset email
        send_password_reset_email(user)
        return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)

    return Response({"error": "Invalid email."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def password_reset_confirm(request, uidb64, token):
    """Verify the token and update the user's password"""
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid.split('-')[1])

        if not custom_token_generator.check_token(user, token):  # Use custom token generator
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        # Update the password
        new_password = request.data.get("password")

        if new_password:
            user.password = make_password(str(new_password))
            user.save()

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Please Enter Valid password."}, status=status.HTTP_400_BAD_REQUEST)
    except (User.DoesNotExist, ValueError, TypeError):
        return Response({"error": "Invalid reset request."}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["PUT"])
@permission_classes([IsAuthenticated])  # Ensure only authenticated users can update
def user_profile_update(request):
    user = request.user  # Get logged-in user

    serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)  # Allow partial updates
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Profile updated successfully", "data": serializer.data}, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])
def admin_dashboard(request):
    return Response({"message": "Welcome, Admin!"})



@api_view(['GET'])
@login_required
def user_dashboard(request):
    return Response({"message": "Welcome, User!"})
