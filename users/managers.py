from django.contrib.auth.models import UserManager
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.core.exceptions import ValidationError as DjangoValidationError


class CustomUserManager(UserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        try:
            validate_email(email)
        except DjangoValidationError:
            raise ValueError("You have not provided a valid e-mail address")

        if email.split('@')[1].lower() != 'gmail.com':
            raise ValueError("Only gmail.com email addresses are allowed")

        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra_fields)

        # Validate password
        try:
            validate_password(password, user)
        except ValidationError as e:
            raise ValueError(e.messages)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self._create_user(email, password, **extra_fields)
