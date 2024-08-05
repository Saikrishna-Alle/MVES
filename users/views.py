from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import (RegisterSerializer, ActivationSerializer, ResendActivationEmailSerializer,
                          DeactivateUserSerializer, DeleteUserSerializer, LoginSerializer, LogoutSerializer)

from django.shortcuts import get_object_or_404
from .models import ActivationToken, User
from .utils import send_activation_email


class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Registration successful. Please check your email for the activation link."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivateAccountView(APIView):
    def get(self, request, token):
        serializer = ActivationSerializer(data={'token': token})
        if serializer.is_valid():
            serializer.activate_user(token)
            return Response({'message': 'Account activated successfully!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendActivationEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        user = get_object_or_404(User, email=email)
        try:
            token = ActivationToken.objects.get(
                user=user, token_type='activation')
            if token.is_expired():
                token.delete()
                token = ActivationToken.objects.create(
                    user=user, token_type='activation')
        except ActivationToken.DoesNotExist:
            token = ActivationToken.objects.create(
                user=user, token_type='activation')
        send_activation_email(user, token.token)
        return Response({'message': 'Activation email sent!'}, status=status.HTTP_200_OK)


class DeactivateUserView(APIView):
    def post(self, request):
        serializer = DeactivateUserSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User deactivated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteUserView(APIView):
    def post(self, request):
        serializer = DeleteUserSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User deleted successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user, token = serializer.save()
            return Response({"message": "Login Succesfull.", "token": token, "fullName": f'{user.first_name} {user.last_name}', "email": user.email}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
        serializer = LogoutSerializer(
            data=request.data, context={'request': request})
        serializer.save()
        return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)
