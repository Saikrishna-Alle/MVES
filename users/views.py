# Standard library imports
import json

# Django imports
from django.contrib.auth import authenticate, get_user_model, update_session_auth_hash
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.http import JsonResponse
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


class PostView(APIView):
    def post(self, request, action, uidb64=None, token=None, pk=None):
        if action == 'registration':
            return self.Registration(request)
        elif action == 'login':
            return self.user_login(request)
        elif action == 'logout':
            return self.user_logout(request)
        elif action == 'changepassword':
            return self.changepassword(request)
        elif action == 'forgetpassword':
            return self.forgetpassword(request)
        elif action == 'resetpassword':
            return self.resetpassword(request, uidb64, token)
        elif action == 'profiles':
            return self.profiles(request)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def Registration(self, request):
        try:
            user_type = request.data.get('user_type')
            if user_type not in ['customer', 'vendor', 'admin', 'owner']:
                return Response({'message': 'Provide valid user role'}, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response({'message': 'Provide valid user role'}, status=status.HTTP_400_BAD_REQUEST)

        if user_type == 'customer':
            serializer = UserRegistrationSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                UserRoles.objects.create(user=user, user_type=user_type)
                return Response({"detail": f"{request.data.get('first_name')} registered. Check your email for the activation link."}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_id = request.user.id
            user_role = UserRoles.objects.get(user_id=user_id)
        except UserRoles.DoesNotExist:
            return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if user_type == 'vendor' and user_role.user_type in ['admin', 'owner']:
            pass
        elif user_type == 'admin' and user_role.user_type == 'owner':
            pass
        elif user_type == 'owner' and user_role.user_type == 'owner':
            pass
        else:
            return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            UserRoles.objects.create(user=user, user_type=user_type)
            return Response({"detail": f"{request.data.get('first_name')} registered. Check your email for the activation link."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def user_login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = None
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                return Response({
                    'message': 'Your account is inactive. Please check your email for the activation link.'
                }, status=status.HTTP_403_FORBIDDEN)
        except ObjectDoesNotExist:
            pass
        if user:
            user = authenticate(email=email, password=password)

            if user is not None:
                token, created = Token.objects.get_or_create(user=user)
                if not created and token.created < timezone.now() - timezone.timedelta(days=1):
                    token.delete()
                    token = Token.objects.create(user=user)
                    token.expires = timezone.now() + timezone.timedelta(days=1)
                    token.save()
                user_type = get_object_or_404(UserRoles, user_id=user.id)
                return Response({'token': token.key, 'id': user.id, 'email': email, 'firstname': user.first_name, 'lastname': user.last_name, 'user_type': user_type.user_type}, status=status.HTTP_200_OK)
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    def user_logout(self, request):
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({'message': 'User is not logged in.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @ permission_classes([IsAuthenticated])
    def changepassword(self, request):
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            user = request.user

            if not user.check_password(serializer.validated_data['old_password']):
                return Response({"message": "Inavalid old Password."}, status=status.HTTP_400_BAD_REQUEST)

            if request.data.get("new_password") != request.data.get("confirm_new_password"):
                return Response({"message": "New passwords must match."}, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(serializer.validated_data['new_password'])
            user.save()

            update_session_auth_hash(request, user)

            return Response({"detail": "Password has been changed successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def forgetpassword(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.save()
            return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def resetpassword(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            token_instance = ActivationToken.objects.get(
                user=user, token=token, token_type='password_reset')

            if token_instance.expires_at < timezone.now():
                return Response({"detail": "Password reset link has expired."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ResetPasswordSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            if request.data.get("new_password") != request.data.get("confirm_new_password"):
                return Response({"message": "New passwords must match."}, status=status.HTTP_400_BAD_REQUEST)

            # Update user's password
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            token_instance.delete()

            return Response({"detail": "Password reset successfully."}, status=status.HTTP_200_OK)

        except (User.DoesNotExist, ActivationToken.DoesNotExist) as e:
            return Response({"detail": "Invalid reset password link."}, status=status.HTTP_400_BAD_REQUEST)

    @permission_classes([IsAuthenticated])
    def profiles(self, request):
        try:
            user_id = request.user.id
            user_role = UserRoles.objects.get(user_id=user_id)
        except UserRoles.DoesNotExist:
            return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        request_user_id = request.data.get('user', user_id)

        # Check if the profile already exists
        if Profiles.objects.filter(user_id=request_user_id).exists():
            return Response({"detail": "Profile for this user already exists."}, status=status.HTTP_400_BAD_REQUEST)

        # If the user is creating a profile for someone else, check permissions
        if request_user_id != user_id:
            try:
                target_user_role = UserRoles.objects.get(
                    user_id=request_user_id)
            except UserRoles.DoesNotExist:
                return Response({'message': "Target user does not have a role."}, status=status.HTTP_403_FORBIDDEN)

            if user_role.user_type == 'admin' and target_user_role.user_type == 'owner':
                return Response({'message': "Admin cannot create profiles for owners."}, status=status.HTTP_403_FORBIDDEN)
            elif user_role.user_type not in ['admin', 'owner']:
                return Response({"message": "You are not allowed to create profiles for other users."}, status=status.HTTP_403_FORBIDDEN)

        # Validate and create the profile
        serializer = NProfilesSerializer(data=request.data)
        if serializer.is_valid():
            if request_user_id == user_id or user_role.user_type in ['admin', 'owner']:
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response({"message": "You are not allowed to create profiles for other users."}, status=status.HTTP_403_FORBIDDEN)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetView(APIView):
    serializer_class = NUserSerializer

    def get(self, request, action, uidb64=None, token=None, pk=None):
        if action == 'activate':
            return self.Activation(request, uidb64, token)
        if action == 'users':
            return self.users(request, pk)
        elif action == 'profiles':
            return self.profiles(request, pk)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def Activation(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            token_instance = ActivationToken.objects.get(
                user=user, token=token, token_type='activation')

            if token_instance.expires_at < timezone.now():
                return Response({"detail": "Activation link expired."}, status=status.HTTP_400_BAD_REQUEST)

            user.is_active = True
            user.save()
            token_instance.delete()
            return Response({"detail": "Account activated successfully."}, status=status.HTTP_200_OK)
        except (User.DoesNotExist, ActivationToken.DoesNotExist):
            return Response({"detail": "Invalid activation link."}, status=status.HTTP_400_BAD_REQUEST)

    @ permission_classes([IsAuthenticated])
    def users(self, request, pk=None):
        try:
            user_id = request.user.id
            user_role = UserRoles.objects.get(user_id=user_id)
        except UserRoles.DoesNotExist:
            return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)

        if user_role.user_type not in ['customer', 'vendor', 'admin', 'owner']:
            return Response({'message': 'Provide valid user role'}, status=status.HTTP_400_BAD_REQUEST)
        if pk:
            try:
                pk_instance = User.objects.get(id=pk)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            if request.user.email == pk_instance.email or user_role.user_type in ['admin', 'owner']:
                user = User.objects.select_related(
                    'userroles', 'profiles', 'staff').prefetch_related('vendors').get(pk=pk)
                serializer = self.serializer_class(user)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)
        else:
            if user_role.user_type in ['admin', 'owner']:
                users = User.objects.select_related(
                    'userroles', 'profiles', 'staff').prefetch_related('vendors').all()
                serializer = self.serializer_class(users, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({'message': "You're not authorized to perform this action."}, status=status.HTTP_403_FORBIDDEN)

    def profiles(self, request, pk=None):
        if pk:
            profile = get_object_or_404(Profiles, pk=pk)
            serializer = NProfilesSerializer(profile)
        else:
            profiles = Profiles.objects.all()
            serializer = NProfilesSerializer(profiles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PatchView(APIView):
    def patch(self, request, action, pk=None):
        if action == 'users':
            return self.users(request, pk)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    @ permission_classes([IsAuthenticated])
    def users(self, request, pk=None):
        try:
            user_role = UserRoles.objects.get(user=request.user)
        except UserRoles.DoesNotExist:
            return Response({'message': "User roles not found for the specified user."}, status=status.HTTP_404_NOT_FOUND)

        try:
            pk_instance = get_object_or_404(User, id=pk)
            pk_role_instance = UserRoles.objects.get(user=pk_instance)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except UserRoles.DoesNotExist:
            return Response({'message': "User roles not found for the specified user."}, status=status.HTTP_404_NOT_FOUND)

        if user_role.user_type not in ['customer', 'vendor', 'admin', 'owner']:
            return Response({'message': 'Provide valid user role'}, status=status.HTTP_400_BAD_REQUEST)

        if request.user.email != pk_instance.email and user_role.user_type not in ['admin', 'owner']:
            return JsonResponse({"detail": "You do not have permission to update other users' details."}, status=status.HTTP_403_FORBIDDEN)

        data = request.data

        # List of fields that only the owner can update
        owner_only_fields = ['user_type',
                             'is_active', 'is_staff', 'is_superuser']
        user_fields = ['first_name', 'last_name']

        for user_field in user_fields:
            if user_field in data:
                setattr(pk_instance, user_field, data[user_field])

        if user_role.user_type == 'owner':
            for owner_only_field in owner_only_fields:
                if owner_only_field in data:
                    if owner_only_field == 'user_type':
                        setattr(pk_role_instance, owner_only_field,
                                data[owner_only_field])
                    else:
                        setattr(pk_instance, owner_only_field,
                                data[owner_only_field])

        pk_instance.save()
        pk_role_instance.save()

        response_data = {
            'id': pk_instance.id,
            'first_name': pk_instance.first_name,
            'last_name': pk_instance.last_name,
            'email': pk_instance.email,
            'user_type': pk_role_instance.user_type,
            'is_active': pk_instance.is_active,
            'is_staff': pk_instance.is_staff,
            'is_superuser': pk_instance.is_superuser,
        }
        return JsonResponse(response_data, status=status.HTTP_200_OK)


class TerminateView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, action, pk=None):
        if action == 'users':
            return self.users(request, pk)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def users(self, request, pk=None):
        try:
            user_role = UserRoles.objects.get(user=request.user)
        except UserRoles.DoesNotExist:
            return Response({'message': "User roles not found for the specified user."}, status=status.HTTP_404_NOT_FOUND)

        try:
            pk_instance = get_object_or_404(User, id=pk)
            pk_role_instance = UserRoles.objects.get(user=pk_instance)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except UserRoles.DoesNotExist:
            return Response({'message': "User roles not found for the specified user."}, status=status.HTTP_404_NOT_FOUND)

        if user_role.user_type not in ['customer', 'vendor', 'admin', 'owner']:
            return Response({'message': 'Provide valid user role'}, status=status.HTTP_400_BAD_REQUEST)

        if request.user.email != pk_instance.email and user_role.user_type not in ['admin', 'owner']:
            return JsonResponse({"detail": "You do not have permission to delete other users' details."}, status=status.HTTP_403_FORBIDDEN)

        if pk_role_instance.user_type in ['admin', 'owner'] and user_role.user_type != 'owner':
            return JsonResponse({"detail": "You do not have permission to delete admin or owner details."}, status=status.HTTP_403_FORBIDDEN)

        # If the checks pass, delete the user
        pk_instance.delete()
        return Response({'message': 'User deleted successfully.'}, status=status.HTTP_200_OK)
