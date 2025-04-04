from rest_framework import permissions

class IsAdmin(permissions.BasePermission):
    """Custom permission to allow only admins to access."""

    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == "admin"
