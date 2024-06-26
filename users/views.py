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

User = get_user_model()


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "User registered. Check your email for the activation link."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivateAccountView(APIView):
    def get(self, request, uidb64, token):
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
