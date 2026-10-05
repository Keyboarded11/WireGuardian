from django.conf import settings
from .policy import policy
from pathlib import Path

APP_VERSION = (Path(__file__).resolve().parent.parent / 'VERSION').read_text().strip()


def site(request):
    return {'installation': policy(), 'development': settings.DEV, 'app_version': APP_VERSION, 'language_options': settings.LANGUAGES}
