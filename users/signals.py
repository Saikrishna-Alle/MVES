# users/signals.py

from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from users.models import UserRoles


@receiver(post_migrate)
def create_owner(sender, **kwargs):
    User = get_user_model()

    # Check if the owner already exists to avoid duplicates
    if not UserRoles.objects.filter(user_type='owner').exists():
        owner_user = User.objects.create_superuser(
            email='owner@gmail.com',
            first_name='Owner',
            last_name='Owner',
            password='241420S@i6'
        )
        owner_user.is_active = True
        owner_user.is_superuser = True
        owner_user.save()

        # Assign the owner role
        UserRoles.objects.create(user=owner_user, user_type='owner')

    if not UserRoles.objects.filter(user_type='admin').exists():
        owner_user = User.objects.create_superuser(
            email='admin@gmail.com',
            first_name='Admin',
            last_name='Admin',
            password='241420S@i6'
        )
        owner_user.is_active = True
        owner_user.save()

        # Assign the owner role
        UserRoles.objects.create(user=owner_user, user_type='admin')

    if not UserRoles.objects.filter(user_type='vendor').exists():
        owner_user = User.objects.create_superuser(
            email='vendor@gmail.com',
            first_name='Vendor',
            last_name='Vendor',
            password='241420S@i6'
        )
        owner_user.is_active = True
        owner_user.save()

        # Assign the owner role
        UserRoles.objects.create(user=owner_user, user_type='vendor')

    if not UserRoles.objects.filter(user_type='customer').exists():
        owner_user = User.objects.create_superuser(
            email='customer@gmail.com',
            first_name='Customer',
            last_name='Customer',
            password='241420S@i6'
        )
        owner_user.is_active = True
        owner_user.save()

        # Assign the owner role
        UserRoles.objects.create(user=owner_user, user_type='customer')
