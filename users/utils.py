import uuid
from datetime import timedelta
from django.utils import timezone
from django.template.loader import render_to_string
from .models import ActivationToken
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.html import strip_tags
from django.core.mail import send_mail


def send_activation_email(user, token):
    subject = 'Activate Your Account'
    from_email = 'no-reply@mves.com'
    to_email = user.email
    activation_link = f'http://localhost:8000/activate/{token}/'
    context = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'activation_link': activation_link
    }
    html_message = render_to_string(
        'Emails/Registration_OTP_Mail.html', context)
    plain_message = strip_tags(html_message)
    send_mail(subject, plain_message, from_email, [
              to_email], html_message=html_message, fail_silently=False)
