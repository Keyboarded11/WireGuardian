import base64
import copy
import time
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from django.contrib.auth.models import User
from django.test import Client, TestCase, SimpleTestCase
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice

from deploy.backup_crypto import encrypt, decrypt
from deploy.core import validate_policy, validate_peers, firewall, wg_config
from panel.agent_client import AgentUnavailable
from panel.models import Configuration, Peer, Audit

PASSWORD = 'Long-test-password-7391!'
PUBLIC = base64.b64encode(bytes(range(32))).decode()
POLICY = {'admin_address': '172.20.1.10', 'admin_networks': ['172.20.1.0/24'], 'lan_networks': ['172.20.1.0/24'], 'vpn_network': '10.90.0.0/24', 'vpn_address': '10.90.0.1', 'port': 59999, 'ssh_port': 2222, 'endpoint': 'vpn.example.org', 'dns': '9.9.9.9', 'interface': 'ens18', 'full_tunnel': False}


class AccessTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user('admin', password=PASSWORD, is_staff=True)
        self.reader = User.objects.create_user('reader', password=PASSWORD)
        Configuration.objects.create(pk=1, endpoint='vpn.example.org')

    def authenticate(self, user=None):
        self.client.force_login(user or self.admin)
        session = self.client.session
        session['verified_at'] = time.time()
        session['password_at'] = time.time()
        session.save()

    def test_user_options_are_scoped_to_account(self):
        self.authenticate(self.reader)
        self.assertContains(self.client.get('/utilisateurs/'), 'reader')
        self.assertEqual(self.client.get(f'/utilisateurs/{self.admin.pk}/options/').status_code, 403)
        self.assertEqual(self.client.post(f'/utilisateurs/{self.admin.pk}/options/', {'new_password1': PASSWORD, 'new_password2': PASSWORD}).status_code, 403)
        self.assertContains(self.client.get(f'/utilisateurs/{self.reader.pk}/options/'), 'reader')

    def test_admin_password_reset_requires_actor_password(self):
        self.authenticate()
        url = f'/utilisateurs/{self.reader.pk}/options/'
        new = 'A-different-password-92841!'
        data = {'new_password1': new, 'new_password2': new}
        self.assertEqual(self.client.post(url, data).status_code, 403)
        data['actor_password'] = PASSWORD
        self.assertRedirects(self.client.post(url, data), url, fetch_redirect_response=False)
        self.reader.refresh_from_db()
        self.assertTrue(self.reader.check_password(new))
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password(PASSWORD))

    def test_admin_mfa_reset_revokes_target_sessions_only(self):
        from django.contrib.sessions.models import Session
        TOTPDevice.objects.create(user=self.reader, confirmed=True)
        other = Client()
        other.force_login(self.reader)
        session_key = other.session.session_key
        self.authenticate()
        url = f'/utilisateurs/{self.reader.pk}/options/'
        self.assertEqual(self.client.post(url, {'action': 'reset_2fa', 'actor_password': 'wrong'}).status_code, 403)
        self.assertTrue(TOTPDevice.objects.filter(user=self.reader).exists())
        self.assertRedirects(self.client.post(url, {'action': 'reset_2fa', 'actor_password': PASSWORD}), url, fetch_redirect_response=False)
        self.assertFalse(TOTPDevice.objects.filter(user=self.reader).exists())
        self.assertFalse(Session.objects.filter(session_key=session_key).exists())
        self.assertEqual(self.client.get('/utilisateurs/').status_code, 200)

    def test_self_mfa_reset_cannot_bypass_token(self):
        self.authenticate()
        TOTPDevice.objects.create(user=self.admin, confirmed=True)
        self.assertEqual(self.client.post(f'/utilisateurs/{self.admin.pk}/options/', {'action': 'reset_2fa', 'actor_password': PASSWORD}).status_code, 403)
        self.assertTrue(TOTPDevice.objects.filter(user=self.admin).exists())

    def test_user_menu_replaces_security_menu(self):
        self.authenticate()
        page = self.client.get('/utilisateurs/')
        self.assertContains(page, f'/utilisateurs/{self.admin.pk}/options/')
        self.assertNotContains(page, 'href="/securite/"')

    @patch('panel.views.agent_client.call', return_value={'ok': True, 'public_key': PUBLIC})
    def test_create_is_immediate_and_replay_keeps_address(self, call):
        self.authenticate()
        self.client.post('/appareils/ajouter/', {'name':'Stable client'})
        peer = Peer.objects.get()
        original = (peer.pk, peer.address, peer.public_key)
        self.assertEqual(Configuration.objects.get(pk=1).revision, Configuration.objects.get(pk=1).applied_revision)
        self.assertTrue(any(c.args[0] == 'sync' for c in call.call_args_list))
        self.client.post('/appareils/ajouter/', {'name':'Stable client'})
        self.assertEqual(Peer.objects.count(), 1)
        peer.refresh_from_db()
        self.assertEqual((peer.pk,peer.address,peer.public_key),original)

    @patch('panel.views.agent_client.call', return_value={'ok': True, 'public_key': PUBLIC})
    def test_limit_and_failed_sync_leave_no_new_client(self, call):
        self.authenticate()
        self.client.post('/appareils/limite/', {'max_clients':1})
        self.client.post('/appareils/ajouter/', {'name':'First'})
        self.client.post('/appareils/ajouter/', {'name':'Second'})
        self.assertEqual(Peer.objects.count(),1)
        call.side_effect = AgentUnavailable('offline')
        peer = Peer.objects.get()
        self.client.post(f'/appareils/{peer.pk}/', {'action':'delete'})
        self.assertTrue(Peer.objects.filter(pk=peer.pk).exists())

    def test_anonymous_cannot_read_dashboard_or_profiles(self):
        for url in ['/', '/appareils/', '/maintenance/', '/reseau/', '/journal/']:
            self.assertRedirects(self.client.get(url), '/connexion/', fetch_redirect_response=False)

    def test_password_login_without_otp_is_supported(self):
        response = self.client.post('/connexion/', {'username': 'admin', 'password': PASSWORD})
        self.assertRedirects(response, '/', fetch_redirect_response=False)
        self.assertIn('verified_at', self.client.session)

    def test_enabled_otp_cannot_be_bypassed(self):
        TOTPDevice.objects.create(user=self.admin, confirmed=True)
        response = self.client.post('/connexion/', {'username': 'admin', 'password': PASSWORD})
        self.assertRedirects(response, '/verification/', fetch_redirect_response=False)
        self.assertRedirects(self.client.get('/'), '/verification/', fetch_redirect_response=False)

    def test_otp_valid_once_only(self):
        device = TOTPDevice.objects.create(user=self.admin, confirmed=True)
        self.client.post('/connexion/', {'username': 'admin', 'password': PASSWORD})
        code = f'{totp(device.bin_key):06d}'
        self.assertRedirects(self.client.post('/verification/', {'token': code}), '/', fetch_redirect_response=False)
        self.client.post('/deconnexion/')
        self.client.post('/connexion/', {'username': 'admin', 'password': PASSWORD})
        self.assertContains(self.client.post('/verification/', {'token': code}), 'déjà utilisé')
        self.assertNotIn('verified_at', self.client.session)

    def test_opt_in_otp_enrolment_and_no_cleartext_password(self):
        self.authenticate()
        self.client.post('/securite/activer/', {'password': PASSWORD})
        self.assertNotIn(PASSWORD, str(dict(self.client.session)))
        self.client.get('/verification/')
        device = TOTPDevice.objects.get(user=self.admin)
        self.assertFalse(device.confirmed)
        response = self.client.post('/verification/', {'token': f'{totp(device.bin_key):06d}'})
        self.assertRedirects(response, '/', fetch_redirect_response=False)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)

    def test_otp_enrolment_invalidates_old_sessions(self):
        other = Client()
        other.post('/connexion/', {'username': 'admin', 'password': PASSWORD})
        self.authenticate()
        self.client.post('/securite/activer/', {'password': PASSWORD})
        self.client.get('/verification/')
        device = TOTPDevice.objects.get(user=self.admin)
        self.client.post('/verification/', {'token': f'{totp(device.bin_key):06d}'})
        self.assertRedirects(other.get('/'), '/connexion/', fetch_redirect_response=False)

    def test_enrolment_qr_renders_without_optional_image_libraries(self):
        self.authenticate()
        self.client.post('/securite/activer/', {'password': PASSWORD})
        self.client.get('/verification/')
        response = self.client.get('/verification/qr/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'image/svg+xml')
        self.assertIn(b'<svg', response.content)

    def test_reader_cannot_mutate_or_see_admin_pages(self):
        self.authenticate(self.reader)
        for url in ['/appareils/ajouter/', '/utilisateurs/ajouter/', '/maintenance/', '/reseau/', '/journal/']:
            self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(self.client.post('/appliquer/').status_code, 403)

    def test_csrf_blocks_mutations(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.admin)
        self.assertEqual(client.post('/appliquer/').status_code, 403)

    def test_persistent_account_throttle(self):
        for _ in range(8):
            self.client.post('/connexion/', {'username': 'admin', 'password': 'incorrect'})
        self.assertEqual(self.client.post('/connexion/', {'username': 'admin', 'password': PASSWORD}).status_code, 429)

    @patch('panel.views.agent_client.call', side_effect=AgentUnavailable('Service absent'))
    def test_agent_absence_does_not_show_fake_success(self, call):
        self.authenticate()
        self.assertContains(self.client.get('/'), 'Télémétrie indisponible')
        self.client.post('/appliquer/')
        configuration = Configuration.objects.get(pk=1)
        self.assertEqual(configuration.applied_revision, 0)
        self.assertFalse(Audit.objects.filter(action='Configuration WireGuard appliquée').exists())

    @patch('panel.views.policy', return_value=POLICY)
    @patch('panel.views.available_addresses', return_value=iter(['10.90.0.2']))
    @patch('panel.views.agent_client.call', return_value={'ok': True, 'public_key': PUBLIC})
    def test_new_full_profile_is_one_time_and_uses_installation(self, call, addresses, policy):
        self.authenticate()
        response = self.client.post('/appareils/ajouter/', {'name': 'Laptop', 'internet': 'on'})
        self.assertContains(response, '0.0.0.0/0, ::/0')
        self.assertContains(response, ':59999')
        self.assertContains(response, 'DNS = 9.9.9.9')
        self.assertContains(response, 'PrivateKey = ')
        peer = Peer.objects.get()
        self.assertEqual(peer.address, '10.90.0.2')
        self.assertNotIn('private', ' '.join(f.name for f in Peer._meta.fields))
        self.assertNotContains(self.client.get(f'/appareils/{peer.pk}/profil/'), 'PrivateKey = ')

    @patch('panel.views.policy', return_value=POLICY)
    @patch('panel.views.available_addresses', return_value=iter(['10.90.0.2']))
    @patch('panel.views.agent_client.call', return_value={'ok': True, 'public_key': PUBLIC})
    def test_split_profile_does_not_capture_internet_or_dns(self, call, addresses, policy):
        self.authenticate()
        response = self.client.post('/appareils/ajouter/', {'name': 'Mobile'})
        self.assertContains(response, '172.20.1.0/24, 10.90.0.1/32')
        self.assertNotContains(response, '0.0.0.0/0')
        self.assertNotContains(response, 'DNS = ')

    @patch('panel.views.agent_client.call', return_value={'ok': True})
    def test_apply_sends_only_enabled_public_records(self, call):
        self.authenticate()
        Peer.objects.create(name='Laptop', public_key=PUBLIC, address='10.90.0.2', internet=True)
        self.client.post('/appliquer/')
        call.assert_called_once_with('sync', peers=[{'public_key': PUBLIC, 'address': '10.90.0.2', 'internet': True}])

    def test_destructive_get_not_allowed(self):
        self.authenticate()
        self.assertEqual(self.client.get('/appliquer/').status_code, 405)
        self.assertEqual(self.client.get('/deconnexion/').status_code, 405)

    def test_safety_headers(self):
        response = self.client.get('/connexion/')
        self.assertIn("frame-ancestors 'none'", response['Content-Security-Policy'])
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')

    def test_deactivated_account_loses_session(self):
        self.authenticate(self.reader)
        self.reader.is_active = False
        self.reader.save()
        self.assertRedirects(self.client.get('/'), '/connexion/', fetch_redirect_response=False)

    def test_maintenance_requires_password_even_for_logged_admin(self):
        self.authenticate()
        self.assertEqual(self.client.post('/maintenance/action/', {'operation': 'update_system', 'password': 'bad'}).status_code, 403)

    @patch('panel.views.agent_client.call', return_value={'ok': True})
    def test_backup_job_does_not_log_encryption_password(self, call):
        self.authenticate()
        phrase = 'my-backup-secret-98761'
        self.client.post('/maintenance/action/', {'operation': 'backup', 'password': PASSWORD, 'backup_password': phrase, 'backup_confirmation': phrase})
        call.assert_called_once_with('backup', password=phrase)
        self.assertNotIn(phrase, str(list(Audit.objects.values())))

    @patch('panel.views.agent_client.call', return_value={'ok': True, 'job': {'state': 'idle'}})
    def test_all_admin_templates_render(self, call):
        self.authenticate()
        for url in ['/', '/appareils/', '/appareils/ajouter/', '/utilisateurs/', '/utilisateurs/ajouter/', '/reseau/', '/journal/', '/securite/', '/maintenance/']:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)


class PolicyTests(SimpleTestCase):
    def test_different_installation_is_accepted(self):
        self.assertEqual(validate_policy(copy.deepcopy(POLICY)), POLICY)

    def test_reject_overlap(self):
        p = {**POLICY, 'lan_networks': ['10.90.0.0/16']}
        with self.assertRaises(ValueError):
            validate_policy(p)

    def test_reject_command_injection_interface(self):
        with self.assertRaises(ValueError):
            validate_policy({**POLICY, 'interface': 'eth0;reboot'})

    def test_reject_outside_peer(self):
        with self.assertRaises(ValueError):
            validate_peers([{'public_key': PUBLIC, 'address': '172.20.10.2', 'internet': False}], POLICY)

    def test_reject_malicious_key(self):
        with self.assertRaises(ValueError):
            validate_peers([{'public_key': 'x\nPostUp = bad', 'address': '10.90.0.2', 'internet': False}], POLICY)

    def test_duplicate_peers_rejected(self):
        peer = {'public_key': PUBLIC, 'address': '10.90.0.2', 'internet': False}
        with self.assertRaises(ValueError):
            validate_peers([peer, peer], POLICY)

    def test_rendered_rules_drop_revoked_tunnel_before_established(self):
        text = firewall(POLICY, [])
        self.assertLess(text.index('iifname "wg0" drop'), text.index('ct state established,related accept'))
        self.assertIn('policy drop', text)
        self.assertNotIn('flush ruleset', text)

    def test_server_peer_allowed_ips_remain_single_ip_for_full_tunnel(self):
        peer = {'public_key': PUBLIC, 'address': '10.90.0.2', 'internet': True}
        result = wg_config(POLICY, [peer], PUBLIC)
        self.assertIn('AllowedIPs = 10.90.0.2/32', result)
        self.assertNotIn('0.0.0.0/0', result)


class BackupTests(SimpleTestCase):
    def test_backup_roundtrip_and_wrong_password(self):
        payload = b'private-key-and-configuration'
        encrypted = encrypt(payload, PASSWORD)
        self.assertNotIn(payload, encrypted)
        self.assertEqual(decrypt(encrypted, PASSWORD), payload)
        with self.assertRaises(InvalidTag):
            decrypt(encrypted, 'wrong-password')

    def test_backup_tampering_rejected(self):
        encrypted = encrypt(b'sensitive', PASSWORD)
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 1])
        with self.assertRaises(InvalidTag):
            decrypt(tampered, PASSWORD)
