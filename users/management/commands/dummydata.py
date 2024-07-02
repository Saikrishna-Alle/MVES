# users/management/commands/dummydata.py

from django.core.management.base import BaseCommand
from users.management.files.create_dummy_data import Command as CreateDummyDataCommand


class Command(BaseCommand):
    help = 'Creates and activates dummy data for testing using Faker'

    def add_arguments(self, parser):
        parser.add_argument('num_records', type=int,
                            help='Number of dummy records to create')

    def handle(self, *args, **kwargs):
        num_records = kwargs['num_records']
        create_dummy_data_command = CreateDummyDataCommand()
        create_dummy_data_command.handle(num_records=num_records)
        self.stdout.write(self.style.SUCCESS(
            f'{num_records} dummy records creation and activation complete.'))
