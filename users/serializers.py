from rest_framework import serializers
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .models import User, ActivationToken, UserRoles
from .utils import send_activation_email
from rest_framework.authtoken.models import Token


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    user_type = serializers.ChoiceField(choices=UserRoles.ROLES)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name',
                  'password', 'user_type']

    def _has_permission_to_register(self, user_role, user_type):
        if not user_role:
            return False

        if user_type == 'vendor' and user_role.user_type in ['admin', 'owner']:
            return True
        if user_type == 'admin' and user_role.user_type == 'owner':
            return True
        if user_type == 'owner' and user_role.user_type == 'owner':
            return True
        return False

    def create(self, validated_data):
        user_role = self.context['request'].user.userroles if self.context['request'].user.is_authenticated else None
        user_type = self.initial_data['user_type']

        if user_type != 'customer' and not self._has_permission_to_register(user_role, user_type):
            raise serializers.ValidationError(
                "You do not have permission to register this user type.")

        user = User.objects.create(
            email=validated_data['email'],
            password=make_password(validated_data['password']),
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            is_active=False,
        )

        UserRoles.objects.create(user=user, user_type=user_type)

        existing_token = ActivationToken.objects.filter(
            user=user, token_type='activation').first()

        if existing_token:
            existing_token.delete()

        token = ActivationToken.objects.create(
            user=user, token_type='activation')

        send_activation_email(user, token.token, 'activate-user',
                              'Emails/Registration_OTP_Mail.html', "Activate Your Account")

        return user


class ActivationSerializer(serializers.Serializer):
    token = serializers.UUIDField()

    def validate(self, data):
        try:
            activation_token = ActivationToken.objects.get(
                token=data['token'], token_type='activation')
        except ActivationToken.DoesNotExist:
            raise serializers.ValidationError("Invalid activation token.")

        if activation_token.is_expired():
            raise serializers.ValidationError("Activation token has expired.")

        return data

    def activate_user(self, token):
        activation_token = ActivationToken.objects.get(token=token)
        user = activation_token.user
        user.is_active = True
        user.save()
        activation_token.delete()


class ResendActivationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        email = data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User with this email does not exist.")

        if user.is_active:
            raise serializers.ValidationError(
                "This account is already activated.")

        data['user'] = user
        return data

    def save(self, **kwargs):
        user = self.validated_data['user']
        ActivationToken.objects.filter(
            user=user, token_type='activation').delete()

        token = ActivationToken.objects.create(
            user=user, token_type='activation')

        send_activation_email(user, token.token, 'activate-user',
                              'Emails/Registration_OTP_Mail.html', "Activate Your Account")
        return {'message': 'Activation email sent!'}


class DeactivateUserSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()

    def _has_permission_to_deactivate(self, user_role, target_user_type):
        if not user_role:
            return False

        if target_user_type == 'customer' and user_role.user_type in ['admin', 'owner']:
            return True
        if target_user_type == 'vendor' and user_role.user_type in ['admin', 'owner']:
            return True
        if target_user_type == 'admin' and user_role.user_type == 'owner':
            return True
        if target_user_type == 'owner' and user_role.user_type == 'owner':
            return True
        return False

    def validate(self, data):
        user_id = data['user_id']
        request_user = self.context['request'].user

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User with this ID does not exist.")

        if not user.is_active:
            raise serializers.ValidationError(
                "This account is already deactivated.")
        if request_user != user:
            user_role = request_user.userroles if request_user.is_authenticated else None
            if not self._has_permission_to_deactivate(user_role, user.userroles.user_type):
                raise serializers.ValidationError(
                    "You do not have permission to deactivate this user.")

        return data

    def save(self):
        user_id = self.validated_data['user_id']
        user = User.objects.get(id=user_id)
        user.is_active = False
        user.save()


class DeleteUserSerializer(serializers.Serializer):
    user_id = serializers.UUIDField()

    def validate(self, data):
        user_id = data['user_id']
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                "User with this ID does not exist.")

        if not self.context['request'].user.is_superuser:
            raise serializers.ValidationError(
                "Only the owner can delete accounts.")

        return data

    def save(self):
        user_id = self.validated_data['user_id']
        user = User.objects.get(id=user_id)
        user.delete()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data['email']
        password = data['password']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.check_password(password):
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("This account is not activated.")

        return data

    def save(self):
        email = self.validated_data['email']
        user = User.objects.get(email=email)
        token, created = Token.objects.get_or_create(user=user)
        if not created and token.created < timezone.now() - timezone.timedelta(days=1):
            token.delete()
            token = Token.objects.create(user=user)
            token.expires = timezone.now() + timezone.timedelta(days=1)
            token.save()
        return user, token.key


class LogoutSerializer(serializers.Serializer):
    def save(self):
        user = self.context['request'].user
        Token.objects.filter(user=user).delete()


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context['request'].user
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError(
                {'old_password': _('Old password is not correct')})
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError(
                {'confirm_password': _('New passwords must match')})
        return data

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                _('User with this email does not exist.'))
        return value

    def save(self):
        user = User.objects.get(email=self.validated_data['email'])
        ActivationToken.objects.filter(
            user=user, token_type='password_reset').delete()

        token = ActivationToken.objects.create(
            user=user, token_type='password_reset')

        send_activation_email(user, token.token, 'reset-password',
                              'Emails/Password_Reset_Mail.html', "Reset Your Password")
        return {'message': 'Activation email sent!'}


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(
        write_only=True, style={'input_type': 'password'})

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def save(self, **kwargs):
        token = self.context['token']
        try:
            activation_token = ActivationToken.objects.get(
                token=token, token_type='password_reset')
        except ActivationToken.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired token.")

        user = activation_token.user
        user.set_password(self.validated_data['new_password'])
        user.save()
        activation_token.delete()
        return user
