from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .models import ActivationToken
import uuid

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

        token = ActivationToken.objects.create(user=user)

        self.send_activation_email(user, token.token)

        return user

    def send_activation_email(self, user, token):
        subject = 'Activate Your Account'
        from_email = 'from@example.com'
        to_email = user.email
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = f'http://localhost:8000/api/activate/{uid}/{token}/'
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
