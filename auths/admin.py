from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Role  


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('email', 'username', 'is_verified',
                    'role', 'is_active', 'is_staff')
    list_filter = ('is_verified', 'role', 'is_active', 'is_staff')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {
         'fields': ('username', 'first_name', 'last_name', 'phone_number', 'address')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff',
         'is_superuser','is_verified', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'role', 'is_active', 'is_staff')}
         ),
    )
    search_fields = ('email', 'username', 'phone_number')
    ordering = ('email',)
    filter_horizontal = ('groups', 'user_permissions')


# Registering CustomUser model with CustomUserAdmin
admin.site.register(CustomUser, CustomUserAdmin)