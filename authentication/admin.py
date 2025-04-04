from django.contrib import admin
from authentication.models import User

# Register your models here.
@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'last_name', 'is_verified')  # Fields shown in list view
    list_filter = ('is_verified',)  # Filter sidebar in Django Admin

