from datetime import timedelta
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
import uuid
from users.managers import CustomUserManager
import random
import string


class User(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=40)
    last_name = models.CharField(max_length=40)
    email = models.EmailField(unique=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    # Used for OTP Verification, initially False.
    is_active = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.first_name + " " + self.last_name


class UserRoles(models.Model):
    user_roles = [
        ('customer', 'customer'),
        ('vendor', 'vendor'),
        ('admin', 'admin'),
        ('owner', 'owner')
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    user_type = models.CharField(
        max_length=25, choices=user_roles, default='customer')

    def __str__(self):
        return self.user.first_name + " " + self.user.last_name


class ActivationToken(models.Model):
    TOKEN_TYPES = (
        ('activation', 'Activation'),
        ('password_reset', 'Password Reset'),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    token_type = models.CharField(
        max_length=20, choices=TOKEN_TYPES)

    def save(self, *args, **kwargs):
        if not self.pk:
            if self.token_type == 'activation':
                self.expires_at = timezone.now() + timedelta(hours=1)
            elif self.token_type == 'password_reset':
                self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)


class Profiles(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(
        max_length=40, blank=True, null=True, unique=True)
    address = models.TextField(blank=True, null=True)
    gender = models.CharField(max_length=10, blank=True, null=True)
    profile_picture = models.ImageField(
        upload_to='profile_pictures/', blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)


class Staff(models.Model):
    emp_id = models.CharField(max_length=7, primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    designation = models.CharField(max_length=100)
    exp_level = models.IntegerField(default=0)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def save(self, *args, **kwargs):
        if not self.emp_id:
            last_staff = Staff.objects.order_by('-emp_id').first()
            if last_staff:
                last_id = int(last_staff.emp_id[4:])
                new_id = f'MVES{str(last_id + 1).zfill(3)}'
            else:
                new_id = 'MVES001'
            self.emp_id = new_id

        super().save(*args, **kwargs)


class Vendor(models.Model):
    id = models.CharField(
        max_length=9, unique=True, blank=True, primary_key=True)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=40)
    email = models.EmailField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    shop_type = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    gstin_number = models.CharField(max_length=50, blank=True, null=True)
    business_license = models.CharField(max_length=255, blank=True, null=True)
    website_url = models.URLField(blank=True, null=True)
    ratings = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = self.generate_vendor_id()
        super().save(*args, **kwargs)

    def generate_vendor_id(self):
        base_id = ''.join(e for e in self.name if e.isalnum()).upper()
        if len(base_id) < 3:
            base_id = base_id.ljust(3, 'X')
        else:
            base_id = base_id[:3]

        random_part = ''.join(random.choices(base_id + string.digits, k=6))
        unique_id = base_id + random_part

        while Vendor.objects.filter(id=unique_id).exists():
            random_part = ''.join(random.choices(base_id + string.digits, k=6))
            unique_id = base_id + random_part

        return unique_id
