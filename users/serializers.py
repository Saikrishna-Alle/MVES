from .models import Profiles, User, UserRoles
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.html import strip_tags
from django.utils.encoding import force_bytes
from .models import ActivationToken, Staff, Vendor
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import gettext_lazy as _

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        try:
            user = User.objects.create_user(**validated_data)
        except ValueError as e:
            raise serializers.ValidationError({'password': e.args[0]})

        existing_token = ActivationToken.objects.filter(
            user=user, token_type='activation').first()

        if existing_token:
            existing_token.delete()

        token = ActivationToken.objects.create(
            user=user, token_type='activation')

        self.send_activation_email(user, token.token)

        return user

    def send_activation_email(self, user, token):
        subject = 'Activate Your Account'
        from_email = 'no-reply@mves.com'
        to_email = user.email
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = f'http://localhost:8000/fetch/activate/{uid}/{token}/'
        context = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'activation_link': activation_link
        }

        # Render HTML template into a string
        html_message = render_to_string(
            'Emails/Registration_OTP_Mail.html', context)

        # Optionally, you can also strip the HTML tags for a plain text alternative
        plain_message = strip_tags(html_message)

        # Send mail with both HTML and plain text content
        send_mail(subject, plain_message, from_email, [
                  to_email], html_message=html_message, fail_silently=False)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except ObjectDoesNotExist:
            raise serializers.ValidationError(
                _("User with this email does not exist."))
        return value

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])

        # Delete any existing password reset tokens for the user
        ActivationToken.objects.filter(
            user=user, token_type='password_reset').delete()

        # Create a new password reset token
        token = ActivationToken.objects.create(
            user=user,
            token_type='password_reset'
        )

        self.send_reset_password_email(user, token)
        return token

    def send_reset_password_email(self, user, token):
        subject = "Password Reset"
        from_email = "no-reply@example.com"
        to_email = user.email
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://localhost:8000/build/resetpassword/{uid}/{token.token}/"

        context = {
            "reset_link": reset_link,
        }

        # Render HTML template into a string
        html_message = render_to_string(
            'emails/Password_Reset_Mail.html', context)

        # Send mail with both HTML and plain text content
        send_mail(subject, None, from_email, [
                  to_email], html_message=html_message)


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True, required=True)
    confirm_new_password = serializers.CharField(
        write_only=True, required=True)

    def validate(self, data):
        validate_password(data['new_password'])
        return data


# user_type = serializers.CharField(source='get_user_type_display', read_only=True)
class UserRolesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRoles
        fields = '__all__'


class ProfilesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profiles
        fields = '__all__'


class StaffSerializer(serializers.ModelSerializer):
    class Meta:
        model = Staff
        fields = '__all__'


class VendorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vendor
        fields = '__all__'


class UserSerializer(serializers.ModelSerializer):
    # user_type = serializers.CharField(source='get_user_type_display', read_only=True)
    userroles = UserRolesSerializer(read_only=True)
    profiles = ProfilesSerializer(read_only=True)
    staff = StaffSerializer(read_only=True)
    vendors = VendorSerializer(many=True, read_only=True)

    class Meta:
        model = User
        exclude = ('groups', 'user_permissions', 'password')
