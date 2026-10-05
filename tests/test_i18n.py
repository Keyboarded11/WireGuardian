import gettext
import io
import json
from pathlib import Path
import re
import sys
import time
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase, SimpleTestCase, Client, override_settings
from django.utils.translation import override, gettext as _

from deploy.compile_translations import load_catalog, source_messages
from panel.forms import PeerForm, EndpointForm
from panel.models import Audit, Peer, Configuration

ROOT = Path(__file__).resolve().parent.parent
LANGUAGES = ['fr', 'en', 'de', 'es', 'it']
PASSWORD = 'A-local-test-password-9324!'


class CatalogTests(SimpleTestCase):
    def test_all_marked_messages_have_four_complete_translations(self):
        catalog = load_catalog()
        self.assertFalse(source_messages() - catalog.keys())
        for source, values in catalog.items():
            self.assertEqual(len(values), 4, source)
            for value in values:
                self.assertTrue(value.strip(), source)
                self.assertEqual(set(re.findall(r'\{value\d+\}', source)), set(re.findall(r'\{value\d+\}', value)), source)

    def test_compiled_catalogs_match_editable_sources(self):
        catalog = load_catalog()
        for language in LANGUAGES:
            translations = gettext.translation('django', localedir=ROOT / 'locale', languages=[language])
            for source, values in catalog.items():
                expected = source if language == 'fr' else values[LANGUAGES.index(language) - 1]
                self.assertEqual(translations.gettext(source), expected)

    def test_lazy_form_labels_follow_each_request_language(self):
        expected = ['Nom de l’appareil', 'Device name', 'Gerätename', 'Nombre del dispositivo', 'Nome dispositivo']
        for language, label in zip(LANGUAGES, expected):
            with override(language):
                self.assertEqual(str(PeerForm().fields['name'].label), label)
                form = EndpointForm({'endpoint': 'invalid;command'})
                self.assertFalse(form.is_valid())
                self.assertIn(_('Indiquez une adresse IPv4 ou un nom DNS valide.'), form.errors['endpoint'])

    def test_brand_has_vector_assets_and_no_old_monogram(self):
        import xml.etree.ElementTree as ET
        for name in ('wireguardian-mark.svg', 'wireguardian-mark-light.svg', 'wireguardian-logo.svg'):
            root = ET.parse(ROOT / 'static/brand' / name).getroot()
            self.assertEqual(root.tag, '{http://www.w3.org/2000/svg}svg')
            self.assertFalse(root.findall('.//{http://www.w3.org/2000/svg}image'))
        for path in (ROOT / 'templates').glob('*.html'):
            source = path.read_text(encoding='utf-8')
            self.assertNotIn('>K.<', source)
            self.assertNotIn('brand-symbol', source)
            self.assertNotIn('WIREGUARD MANAGER', source)

    def test_installer_questions_are_localised_without_django(self):
        # Import the actual installer; only its pure questionnaire runs, never install().
        sys.path.insert(0, str(ROOT / 'deploy'))
        try:
            from deploy import install
            from cli_language import select_language
            expected = ['Nom du premier administrateur', 'First administrator’s username', 'Benutzername des ersten Administrators', 'Nombre del primer administrador', 'Nome del primo amministratore']
            for language, expected_prompt in zip(LANGUAGES, expected):
                select_language(language)
                prompts = []
                answers = iter(['192.168.8.10', 'ens18', '192.168.8.0/24', '192.168.8.0/24', '10.80.0.0/24', '10.80.0.1', '51820', '22', 'vpn.example.org', '9.9.9.9', 'admin', 'y', '', 'y', 'INSTALLER'])
                def answer(prompt):
                    prompts.append(prompt)
                    return next(answers)
                with patch.object(install, 'detected_network', return_value=('', '', '')), patch('builtins.input', side_effect=answer), patch('getpass.getpass', return_value=PASSWORD), patch('sys.stdout', new=io.StringIO()):
                    policy, username, password, automatic, release = install.questionnaire()
                self.assertIn(expected_prompt, '\n'.join(prompts))
                self.assertEqual(policy['vpn_network'], '10.80.0.0/24')
                self.assertEqual(username, 'admin')
                self.assertTrue(automatic)
                self.assertEqual(password, PASSWORD)
            select_language('fr')
        finally:
            sys.path.pop(0)


class LanguageRequestTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('test-admin', password=PASSWORD, is_staff=True)
        Configuration.objects.create(pk=1, endpoint='vpn.example.org')

    def authenticated(self):
        self.client.force_login(self.user)
        session = self.client.session
        session['verified_at'] = time.time()
        session['password_at'] = time.time()
        session.save()

    def test_login_browser_language_and_errors_in_five_languages(self):
        expected = ['Identifiants incorrects.', 'Incorrect credentials.', 'Falsche Zugangsdaten.', 'Credenciales incorrectas.', 'Credenziali errate.']
        for language, error in zip(LANGUAGES, expected):
            response = self.client.post('/connexion/', {'username': 'missing-' + language, 'password': 'bad'}, HTTP_ACCEPT_LANGUAGE=language)
            self.assertContains(response, error)
            self.assertContains(response, f'lang="{language}"')
            self.assertContains(response, 'WireGuardian')
            self.assertEqual(response.headers['Content-Language'], language)

    def test_switch_persists_without_discarding_session(self):
        self.authenticated()
        original = self.client.session.session_key
        response = self.client.post('/language/', {'language': 'de', 'next': '/appareils/?q=test'})
        self.assertRedirects(response, '/appareils/?q=test', fetch_redirect_response=False)
        self.assertEqual(response.cookies[settings.LANGUAGE_COOKIE_NAME].value, 'de')
        self.assertEqual(self.client.session.session_key, original)
        page = self.client.get('/appareils/', HTTP_ACCEPT_LANGUAGE='es')
        self.assertContains(page, 'Geräte')
        self.assertEqual(page.headers['Content-Language'], 'de')

    def test_language_endpoint_rejects_open_redirect_and_invalid_language(self):
        response = self.client.post('/language/', {'language': 'it', 'next': 'https://attacker.example/'})
        self.assertEqual(response.url, '/')
        response = self.client.post('/language/', {'language': 'xx', 'next': '/'})
        self.assertNotIn(settings.LANGUAGE_COOKIE_NAME, response.cookies)

    def test_language_change_remains_csrf_protected(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/language/', {'language': 'de'}).status_code, 403)

    @override_settings(LANGUAGE_COOKIE_SECURE=True)
    def test_language_cookie_security(self):
        cookie = self.client.post('/language/', {'language': 'en'}) .cookies[settings.LANGUAGE_COOKIE_NAME]
        self.assertTrue(cookie['secure'])
        self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'], 'Lax')

    def test_authenticated_pages_and_stored_actions_in_five_languages(self):
        self.authenticated()
        Audit.objects.create(actor='test-admin', action='Appareil créé', detail='Bureau français <script>')
        expected = ['Appareil créé', 'Device created', 'Gerät erstellt', 'Dispositivo creado', 'Dispositivo creato']
        for language, action in zip(LANGUAGES, expected):
            self.client.cookies[settings.LANGUAGE_COOKIE_NAME] = language
            for url in ['/', '/appareils/', '/appareils/ajouter/', '/reseau/', '/utilisateurs/', '/utilisateurs/ajouter/', '/securite/', '/journal/', '/maintenance/']:
                with self.subTest(language=language, url=url):
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 200)
                    self.assertContains(response, f'lang="{language}"')
                    self.assertNotContains(response, 'brand-symbol')
                    if url == '/journal/':
                        self.assertContains(response, action)
                        self.assertContains(response, 'Bureau français &lt;script&gt;')
        self.assertEqual(Audit.objects.get().action, 'Appareil créé')
