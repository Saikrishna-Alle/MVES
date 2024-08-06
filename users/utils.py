from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import send_mail


def send_activation_email(user, token, purpose, template, subject):
    from_email = 'no-reply@mves.com'
    to_email = user.email
    activation_link = f'http://localhost:8000/auth/{purpose}/{token}/'
    context = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'link': activation_link
    }
    html_message = render_to_string(
        template, context)
    plain_message = strip_tags(html_message)
    send_mail(subject, plain_message, from_email, [
              to_email], html_message=html_message, fail_silently=False)
