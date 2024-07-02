# create_dummy_data.py

import random
import string
from datetime import timedelta
from django.utils import timezone
from django.core.management.base import BaseCommand, CommandError
from faker import Faker
from users.models import User, UserRoles, ActivationToken, Profiles, Staff, Vendor
from django.contrib.auth import get_user_model
from users.managers import CustomUserManager
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password

User = get_user_model()
fake = Faker()


class Command(BaseCommand):
    help = 'Creates dummy data for testing purposes using Faker'

    def add_arguments(self, parser):
        parser.add_argument('num_records', type=int,
                            help='Number of dummy records to create')

    def handle(self, *args, **kwargs):
        num_records = kwargs['num_records']
        self.stdout.write(f'Creating {num_records} dummy records...')

        for _ in range(num_records):
            # Create a user with Faker data
            user = User.objects.create_user(
                email=fake.email(),
                first_name=fake.first_name(),
                last_name=fake.last_name(),
                password='241420S@i6'  # You can generate a random password if needed
            )

            # Activate the user
            user.is_active = True
            user.is_staff = True
            user.save()

            # Create user roles
            user_type = random.choice(['customer', 'vendor', 'admin', 'owner'])
            UserRoles.objects.create(user=user, user_type=user_type)

            # Create profile with Faker data
            Profiles.objects.create(
                user=user,
                phone_number=fake.phone_number(),
                address=fake.address(),
                gender=random.choice(['Male', 'Female'])
            )

            # Create staff with Faker data
            Staff.objects.create(
                user=user,
                designation=fake.job(),
                exp_level=random.randint(1, 10)
            )

            # Create vendor with Faker data
            Vendor.objects.create(
                user=user,
                name=fake.company(),
                phone=fake.phone_number(),
                email=fake.email(),
                address=fake.address(),
                shop_type=random.choice(['Online', 'Physical']),
                ratings=random.uniform(1.0, 5.0)
            )

        self.stdout.write(self.style.SUCCESS(
            f'{num_records} dummy records created successfully.'))
