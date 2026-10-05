"""Installer checks without changing packages, networking or the local machine."""
import importlib
import io
import json
import sys
from pathlib import Path
from unittest.mock import patch
from django.test import SimpleTestCase, override_settings

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'deploy'))
installer = importlib.import_module('deploy.install')
sys.path.pop(0)


class InstallerTests(SimpleTestCase):
    def test_detection_uses_target_host_only(self):
        replies = [json.dumps([{'dev': 'enp7s0'}]).encode(), json.dumps([{'addr_info': [{'scope': 'global', 'local': '172.24.6.12', 'prefixlen': 24}]}]).encode()]
        with patch.object(installer.subprocess, 'check_output', side_effect=replies):
            self.assertEqual(installer.detected_network(), ('enp7s0', '172.24.6.12', '172.24.6.0/24'))

    def test_failed_detection_has_no_personal_fallback(self):
        with patch.object(installer.subprocess, 'check_output', side_effect=OSError):
            self.assertEqual(installer.detected_network(), ('', '', ''))

    def test_invalid_input_reprompts(self):
        with patch('builtins.input', side_effect=['65536', '51821']), patch('sys.stdout', new=io.StringIO()):
            self.assertEqual(installer.ask_valid('UDP', validator=installer.port_number), 51821)

    def test_vpn_must_be_private_and_bounded(self):
        for value in ('0.0.0.0/0', '203.0.113.0/24', '10.0.0.0/8', '10.2.0.1/24', '::/0'):
            with self.assertRaises(ValueError):
                installer.vpn_network(value)
        self.assertEqual(installer.vpn_network('172.25.90.0/24'), '172.25.90.0/24')

    def test_unrestricted_admin_network_rejected(self):
        with self.assertRaises(ValueError):
            installer.networks('0.0.0.0/0')

    def test_policy_required_outside_development(self):
        from panel.policy import policy
        with patch.dict('os.environ', {}, clear=True):
            with self.assertRaises(RuntimeError):
                policy()

    def test_questionnaire_uses_explicit_account_and_hides_password(self):
        from cli_language import select_language
        select_language('fr')
        answers = ['172.24.6.12','enp7s0','172.24.6.0/24','172.24.6.0/24','172.25.90.0/24','','51821','2222','vpn.example.net','','chosen-operator','n','','y','INSTALLER']
        prompts=[]
        def answer(prompt):
            prompts.append(prompt)
            return answers.pop(0)
        output=io.StringIO()
        with patch.object(installer, 'detected_network', return_value=('', '', '')), patch('builtins.input', side_effect=answer), patch('getpass.getpass', return_value='An-installer-test-password-7401!'), patch('sys.stdout', new=output):
            p,user,password,auto,release=installer.questionnaire()
        self.assertEqual(user, 'chosen-operator')
        self.assertFalse(auto)
        self.assertEqual(p['vpn_address'], '172.25.90.1')
        self.assertEqual(p['ssh_port'], 2222)
        self.assertNotIn(password, output.getvalue())
        self.assertTrue(any('Nom du premier administrateur :' in prompt for prompt in prompts))
        self.assertFalse(any('[admin]' in prompt for prompt in prompts))
