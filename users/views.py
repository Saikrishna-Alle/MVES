# Standard library imports
import json
import logging

# Django imports
from django.contrib.auth import authenticate, get_user_model, update_session_auth_hash
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

# Third-party imports
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

# Local application imports
from users.models import ActivationToken, Profiles, User, UserRoles
from users.serializers import (
    ChangePasswordSerializer,
    ForgotPasswordSerializer,
    NProfilesSerializer,
    NUserSerializer,
    ResetPasswordSerializer,
    UserRegistrationSerializer
)

User = get_user_model()
logger = logging.getLogger(__name__)


def validate_user_role(user_role):
    if user_role not in ['customer', 'vendor', 'admin', 'owner']:
        raise ValueError("Provide valid user role")


class PostView(APIView):

    def post(self, request, action, uidb64=None, token=None, pk=None):
        try:
            if action == 'registration':
                return self.registration(request)
            elif action == 'login':
                return self.user_login(request)
            elif action == 'logout':
                return self.user_logout(request)
            elif action == 'changepassword':
                return self.change_password(request)
            elif action == 'forgetpassword':
                return self.forget_password(request)
            elif action == 'resetpassword':
                return self.reset_password(request, uidb64, token)
            elif action == 'profiles':
                return self.create_profile(request)
            else:
                return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in PostView post method: {str(e)}")
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def registration(self, request):
        user_type = request.data.get('user_type')
        try:
            validate_user_role(user_type)
        except ValueError as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        if user_type == 'customer':
            return self._register_user(request, user_type)

        if not request.user.is_authenticated:
            return Response({'message': "Authentication required for this action."}, status=status.HTTP_403_FORBIDDEN)

        user_role = UserRoles.objects.get(user_id=request.user.id)
        if not self._has_permission_to_register(user_role.user_type, user_type):
            return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        return self._register_user(request, user_type)

    def _register_user(self, request, user_type):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            UserRoles.objects.create(user=user, user_type=user_type)
            return Response({"detail": f"{request.data.get('first_name')} registered. Check your email for the activation link."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _has_permission_to_register(self, user_role, user_type):
        if user_type == 'vendor' and user_role in ['admin', 'owner']:
            return True
        if user_type == 'admin' and user_role == 'owner':
            return True
        if user_type == 'owner' and user_role == 'owner':
            return True
        return False

    def user_login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = User.objects.filter(email=email).first()

        if user and not user.is_active:
            return Response({'message': 'Your account is inactive. Please check your email for the activation link.'}, status=status.HTTP_403_FORBIDDEN)

        user = authenticate(email=email, password=password)
        if user:
            token, created = Token.objects.get_or_create(user=user)
            if not created and token.created < timezone.now() - timezone.timedelta(days=1):
                token.delete()
                token = Token.objects.create(user=user)
                token.save()
            user_type = UserRoles.objects.get(user_id=user.id).user_type
            return Response({'token': token.key, 'id': user.id, 'email': email, 'firstname': user.first_name, 'lastname': user.last_name, 'user_type': user_type}, status=status.HTTP_200_OK)

        return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    def user_logout(self, request):
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({'message': 'User is not logged in.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in user_logout method: {str(e)}")
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @permission_classes([IsAuthenticated])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({"message": "Invalid old password."}, status=status.HTTP_400_BAD_REQUEST)
            if request.data.get("new_password") != request.data.get("confirm_new_password"):
                return Response({"message": "New passwords must match."}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            update_session_auth_hash(request, user)
            return Response({"detail": "Password has been changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def forget_password(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def reset_password(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            token_instance = ActivationToken.objects.get(
                user=user, token=token, token_type='password_reset')

            if token_instance.expires_at < timezone.now():
                return Response({"detail": "Password reset link has expired."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                if request.data.get("new_password") != request.data.get("confirm_new_password"):
                    return Response({"message": "New passwords must match."}, status=status.HTTP_400_BAD_REQUEST)
                user.set_password(serializer.validated_data['new_password'])
                user.save()
                token_instance.delete()
                return Response({"detail": "Password reset successfully."}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except (User.DoesNotExist, ActivationToken.DoesNotExist) as e:
            logger.error(f"Error in reset_password method: {str(e)}")
            return Response({"detail": "Invalid reset password link."}, status=status.HTTP_400_BAD_REQUEST)

    @permission_classes([IsAuthenticated])
    def create_profile(self, request):
        user_id = request.user.id
        user_role = UserRoles.objects.get(user_id=user_id)

        request_user_id = request.data.get('user', user_id)
        if Profiles.objects.filter(user_id=request_user_id).exists():
            return Response({"detail": "Profile already exists for this user."}, status=status.HTTP_400_BAD_REQUEST)

        if user_role.user_type == 'customer' and request_user_id != user_id:
            return Response({"detail": "You're not authorized to create profiles for other users."}, status=status.HTTP_403_FORBIDDEN)

        serializer = NProfilesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetView(APIView):

    def get(self, request, action, uidb64=None, token=None, pk=None):
        try:
            if action == 'activate':
                return self.activate_account(request, uidb64, token)
            elif action == 'users':
                return self.get_user(request, pk)
            elif action == 'profiles':
                return self.get_profile(request, pk)
            else:
                return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in GetView get method: {str(e)}")
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def activate_account(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            activation_token = ActivationToken.objects.get(
                user=user, token=token, token_type='account_activation')

            if activation_token.expires_at < timezone.now():
                return Response({"detail": "Activation link has expired."}, status=status.HTTP_400_BAD_REQUEST)

            user.is_active = True
            user.save()
            activation_token.delete()
            return Response({"message": "Account activated successfully."}, status=status.HTTP_200_OK)
        except (User.DoesNotExist, ActivationToken.DoesNotExist) as e:
            logger.error(f"Error in activate_account method: {str(e)}")
            return Response({"detail": "Invalid activation link."}, status=status.HTTP_400_BAD_REQUEST)

    @permission_classes([IsAuthenticated])
    def get_user(self, request, pk):
        user_role = UserRoles.objects.get(user_id=request.user.id)

        if user_role.user_type not in ['admin', 'owner'] and request.user.id != pk:
            return Response({'message': 'You do not have permission to view other users.'}, status=status.HTTP_403_FORBIDDEN)

        user = get_object_or_404(User, pk=pk)
        user_serializer = NUserSerializer(user)
        return Response(user_serializer.data, status=status.HTTP_200_OK)

    @permission_classes([IsAuthenticated])
    def get_profile(self, request, pk):
        profile = get_object_or_404(Profiles, pk=pk)
        profile_serializer = NProfilesSerializer(profile)
        return Response(profile_serializer.data, status=status.HTTP_200_OK)


class PatchView(APIView):

    @permission_classes([IsAuthenticated])
    def patch(self, request, action, pk=None):
        try:
            if action == 'users':
                return self.update_user(request, pk)
            else:
                return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in PatchView patch method: {str(e)}")
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update_user(self, request, pk):
        user_role = UserRoles.objects.get(user_id=request.user.id)
        target_user = get_object_or_404(User, pk=pk)
        target_user_role = UserRoles.objects.get(user_id=target_user.id)

        if request.user.id != pk and user_role.user_type not in ['admin', 'owner']:
            return Response({'message': 'You do not have permission to update other users.'}, status=status.HTTP_403_FORBIDDEN)

        if target_user_role.user_type in ['admin', 'owner'] and user_role.user_type != 'owner':
            return Response({'message': 'You do not have permission to update admin or owner users.'}, status=status.HTTP_403_FORBIDDEN)

        restricted_fields = ['user_type',
                             'is_active', 'is_staff', 'is_superuser']
        for field in restricted_fields:
            if field in request.data and user_role.user_type != 'owner':
                return Response({'message': f'You do not have permission to update {field}.'}, status=status.HTTP_403_FORBIDDEN)

        serializer = NUserSerializer(
            target_user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TerminateView(APIView):

    @permission_classes([IsAuthenticated])
    def delete(self, request, action, pk=None):
        try:
            if action == 'users':
                return self.delete_user(request, pk)
            else:
                return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in TerminateView delete method: {str(e)}")
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete_user(self, request, pk):
        user_role = UserRoles.objects.get(user_id=request.user.id)
        target_user = get_object_or_404(User, pk=pk)
        target_user_role = UserRoles.objects.get(user_id=target_user.id)

        if user_role.user_type not in ['admin', 'owner']:
            return Response({'message': 'You do not have permission to delete other users.'}, status=status.HTTP_403_FORBIDDEN)

        if target_user_role.user_type in ['admin', 'owner'] and user_role.user_type != 'owner':
            return Response({'message': 'You do not have permission to delete admin or owner users.'}, status=status.HTTP_403_FORBIDDEN)

        target_user.delete()
        return Response({"message": "User deleted successfully."}, status=status.HTTP_200_OK)
