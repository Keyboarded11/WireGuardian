from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django_otp.plugins.otp_totp.models import TOTPDevice
from panel.models import Audit


class Command(BaseCommand):
    help = 'Local console recovery only; invalidates ALL sessions.'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, username, **options):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise CommandError('Utilisateur inconnu')
        TOTPDevice.objects.filter(user=user).delete()
        Session.objects.all().delete()
        Audit.objects.create(actor='console locale', action='Réinitialisation 2FA', detail=username)
        self.stdout.write('2FA réinitialisée et sessions invalidées. Changez aussi le mot de passe si nécessaire.')
