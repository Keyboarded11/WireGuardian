"""Installer localisation is available before Django or dependencies are installed."""
import gettext
from pathlib import Path

LANGUAGES = ('fr', 'en', 'de', 'es', 'it')
_catalog = gettext.NullTranslations()
_language = 'fr'


def select_language(code=None):
    global _catalog, _language
    if code is None:
        print('WireGuardian — Français [fr] · English [en] · Deutsch [de] · Español [es] · Italiano [it]')
        code = input('Language / Langue [fr]: ').strip().lower() or 'fr'
    if code not in LANGUAGES:
        raise ValueError('Choose fr, en, de, es or it.')
    _catalog = gettext.translation('django', localedir=Path(__file__).resolve().parent.parent / 'locale', languages=[code])
    _language = code
    return code


def language_code():
    return _language


def _(message):
    return _catalog.gettext(message)
