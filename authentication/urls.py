from django.urls import path
from .views import register, login, password_reset, verify_user, request_otp, verify_otp, password_reset_confirm, \
    user_profile_update, admin_dashboard,user_dashboard

urlpatterns =[
    path('register/',register,name="register"),
    path('verify-email/<uuid:token>/', verify_user, name='verify-email'),
    path('login/',login,name="login"),
    path("request-otp/", request_otp, name="request-otp"),
    path("verify-otp/", verify_otp, name="verify-otp"),
    path('password-reset/',password_reset,name="password-reset"),
    path("password-reset/<uidb64>/<token>/", password_reset_confirm,name="password-reset-confirm"),
    path("profile/update/", user_profile_update, name="user-profile-update"),
    path("admin-dashboard/", admin_dashboard, name="admin-dashboard"),
    path("user-dashboard/", user_dashboard, name="user-dashboard"),
]
