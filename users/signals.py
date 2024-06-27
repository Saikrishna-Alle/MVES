# users/signals.py

from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from users.models import UserRoles


@receiver(post_migrate)
def create_owner(sender, **kwargs):
    User = get_user_model()

    # Check if the owner already exists to avoid duplicates
    if not User.objects.filter(email='krishna@gmail.com').exists():
        owner_user = User.objects.create_superuser(
            email='krishna@gmail.com',
            first_name='sri',
            last_name='Krishna',
            password='241420S@i6'
        )
        owner_user.is_active = True
        owner_user.save()

        # Assign the owner role
        UserRoles.objects.create(user=owner_user, user_type='owner')
