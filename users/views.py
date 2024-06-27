from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from .models import ActivationToken
from .serializers import UserRegistrationSerializer
from django.utils import timezone
from django.conf import settings
from users.models import UserRoles
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authtoken.models import Token
from django.utils import timezone
from django.shortcuts import get_object_or_404, redirect

User = get_user_model()


class PostView(APIView):
    def post(self, request, action):
        if action == 'registration':
            return self.Registration(request)
        elif action == 'login':
            return self.user_login(request)
        elif action == 'logout':
            return self.user_logout(request)
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
                return Response({'token': token.key, 'email': email, 'firstname': user.first_name, 'lastname': user.last_name, 'user_type': user_type.user_type}, status=status.HTTP_200_OK)
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    def user_logout(self, request):
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({'message': 'User is not logged in.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetView(APIView):
    def get(self, request, action, uidb64=None, token=None):
        if action == 'activate':
            return self.Activation(request, uidb64, token)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def Activation(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            token_instance = ActivationToken.objects.get(
                user=user, token=token)

            if token_instance.expires_at < timezone.now():
                return Response({"detail": "Activation link expired."}, status=status.HTTP_400_BAD_REQUEST)

            user.is_active = True
            user.save()
            token_instance.delete()
            return Response({"detail": "Account activated successfully."}, status=status.HTTP_200_OK)
        except (User.DoesNotExist, ActivationToken.DoesNotExist):
            return Response({"detail": "Invalid activation link."}, status=status.HTTP_400_BAD_REQUEST)
