from django.contrib import admin
from .models import User, UserRoles, ActivationToken, Profiles, Staff, Vendor


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'first_name', 'last_name',
                    'is_active', 'is_staff', 'is_superuser')
    list_filter = ('is_active', 'is_staff', 'is_superuser')
    search_fields = ('email', 'first_name', 'last_name')


@admin.register(UserRoles)
class UserRolesAdmin(admin.ModelAdmin):
    list_display = ('user', 'user_type')
    list_filter = ('user_type',)
    search_fields = ('user__first_name', 'user__last_name', 'user__email')


@admin.register(ActivationToken)
class ActivationTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at', 'expires_at')
    search_fields = ('user__first_name', 'user__last_name',
                     'user__email', 'token')


@admin.register(Profiles)
class ProfilesAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone_number', 'address', 'gender')
    search_fields = ('user__first_name', 'user__last_name',
                     'user__email', 'phone_number')


@admin.register(Staff)
class StaffAdmin(admin.ModelAdmin):
    list_display = ('user', 'emp_id', 'designation', 'exp_level')
    search_fields = ('user__first_name', 'user__last_name',
                     'user__email', 'emp_id')


@admin.register(Vendor)
class VendorAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'id', 'phone', 'shop_type', 'ratings')
    search_fields = ('name', 'id', 'phone', 'user__first_name',
                     'user__last_name', 'user__email')
    list_filter = ('shop_type', 'ratings')
