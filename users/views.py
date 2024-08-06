from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import (RegisterSerializer, ActivationSerializer, ResendActivationEmailSerializer,
                          DeactivateUserSerializer, DeleteUserSerializer, LoginSerializer, LogoutSerializer)


class CompleteAuthView(APIView):
    def post(self, request, action, token=None, *args, **kwargs):
        if action == "register":
            return self.register(request)
        elif action == 'login':
            return self.login(request)
        elif action == 'logout':
            return self.logout(request)
        elif action == 'resend-activation-email':
            return self.resend_activation_email(request)
        elif action == 'deactivate-user':
            return self.deactivate_user(request, token)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, action, token=None, *args, **kwargs):
        if action == "activate-user":
            return self.activate_user(request, token)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, action, token=None, *args, **kwargs):
        if action == 'delete-user':
            return self.delete_user(request, token)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def register(self, request):
        serializer = RegisterSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Registration successful. Please check your email for the activation link."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user, token = serializer.save()
            return Response({"message": "Login Successful.", "token": token, "fullName": f'{user.first_name} {user.last_name}', "email": user.email}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @permission_classes([IsAuthenticated])
    def logout(self, request):
        serializer = LogoutSerializer(
            data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Logout successful."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @permission_classes([IsAuthenticated])
    def delete_user(self, request, token):
        data = {'user_id': token}
        serializer = DeleteUserSerializer(
            data=data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User deleted successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def resend_activation_email(self, request):
        serializer = ResendActivationEmailSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Activation email sent!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @permission_classes([IsAuthenticated])
    def deactivate_user(self, request, token):
        serializer = DeactivateUserSerializer(
            data={'user_id': token}, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User deactivated successfully!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def activate_user(self, request, token):
        serializer = ActivationSerializer(data={'token': token})
        if serializer.is_valid():
            serializer.activate_user(token)
            return Response({'message': 'Account activated successfully!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
