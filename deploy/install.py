#!/usr/bin/env python3
"""Debian >=12 / antiX with Python >=3.11, dedicated-server interactive installer."""
import argparse
import base64
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import ssl
import time
import urllib.request

from core import validate_policy, firewall
from cli_language import _, select_language, language_code

PACKAGES = ['python3', 'python3-venv', 'wireguard-tools', 'iproute2', 'nftables', 'nginx', 'openssl', 'ca-certificates', 'unattended-upgrades', 'openssh-server', 'cron', 'kmod', 'logrotate']
APP = Path('/opt/keyboarded')
ROOT = Path('/etc/keyboarded')
DATA = Path('/var/lib/keyboarded')
STATE = Path('/var/lib/keyboarded-agent')


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def ask(label, default='', secret=False):
    while True:
        answer = (getpass.getpass if secret else input)(f'{label}' + (f' [{default}]' if default else '') + ' : ').strip() or default
        if answer:
            return answer


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
    path.chmod(mode)


def ask_valid(label, default='', validator=lambda value: value):
    while True:
        value = ask(label, default)
        try:
            return validator(value)
        except (ValueError, TypeError):
            print(_('Saisie invalide. Vérifiez le format et recommencez.'))


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError('Unusable address')
    return str(address)


def networks(value):
    result = [str(ipaddress.IPv4Network(n.strip(), strict=True)) for n in value.split(',')]
    if any(ipaddress.ip_network(n).prefixlen == 0 for n in result):
        raise ValueError('An unrestricted network is not allowed')
    if not 1 <= len(result) <= 16:
        raise ValueError('Network count')
    return result


def vpn_network(value):
    subnet = ipaddress.IPv4Network(value, strict=True)
    private = any(subnet.subnet_of(ipaddress.IPv4Network(n)) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    if not private or not 22 <= subnet.prefixlen <= 29:
        raise ValueError('Private VPN subnet /22 to /29 required')
    return str(subnet)


def port_number(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('Port range')
    return port


def detected_network():
    try:
        routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'default']))
        interface = routes[0]['dev']
        addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'address', 'show', 'dev', interface]))
        address = next(a for item in addresses for a in item['addr_info'] if a['scope'] == 'global')
        return interface, address['local'], str(ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}").network)
    except (OSError, ValueError, KeyError, IndexError, StopIteration, subprocess.CalledProcessError):
        return '', '', ''


def questionnaire():
    print(_('\nWireGuardian · Keyboarded\nAssistant d’installation — serveur Debian dédié\n'))
    print(_('Les adresses sont des exemples : indiquez celles de VOTRE réseau.\nUtilisez la console Proxmox/locale pour éviter une coupure SSH.\n'))
    p = {}
    interface, address, lan = detected_network()
    print(_('1/4 — Réseau : les suggestions proviennent uniquement de ce serveur.'))
    p['admin_address'] = ask_valid(_('Adresse IPv4 fixe déjà configurée sur ce serveur'), address, ipv4)
    p['interface'] = ask(_('Interface réseau de sortie (ip -br link)'), interface)
    p['lan_networks'] = ask_valid(_('Réseaux LAN accessibles, séparés par des virgules'), lan, networks)
    p['admin_networks'] = ask_valid(_('Réseaux autorisés à administrer HTTPS et SSH'), ','.join(p['lan_networks']), networks)
    def vpn_choice(value):
        candidate = vpn_network(value)
        if any(ipaddress.ip_network(candidate).overlaps(ipaddress.ip_network(n)) for n in p['lan_networks'] + p['admin_networks']):
            raise ValueError('Overlapping networks')
        return candidate
    p['vpn_network'] = ask_valid(_('Sous-réseau VPN, distinct de tous les LAN'), validator=vpn_choice)
    p['vpn_address'] = ask(_('Adresse du serveur dans ce VPN'), str(next(ipaddress.ip_network(p['vpn_network']).hosts())))
    p['port'] = ask_valid(_('Port WireGuard UDP'), '51820', port_number)
    p['ssh_port'] = ask_valid(_('Port SSH ACTUEL à préserver'), os.environ.get('SSH_CONNECTION', '').split()[-1] if os.environ.get('SSH_CONNECTION') else '22', port_number)
    p['endpoint'] = ask(_('Nom DNS public ou IPv4 publique (modifiable ensuite)'))
    dns = input(_('DNS IPv4 des profils (vide = conserver le DNS client) : ')).strip()
    p['dns'] = dns
    p['full_tunnel'] = False
    p['lan_networks'] = [n.strip() for n in p['lan_networks']]
    p['admin_networks'] = [n.strip() for n in p['admin_networks']]
    validate_policy(p)
    print(_('2/4 — Compte : aucun identifiant ni mot de passe prédéfini.'))
    username = ask(_('Nom du premier administrateur'))
    if not re.fullmatch(r'[a-zA-Z0-9_@.+-]{1,150}', username):
        raise ValueError(_('Nom utilisateur invalide'))
    while True:
        password = ask(_('Mot de passe administrateur (14 caractères minimum)'), secret=True)
        if len(password) >= 14 and password == ask(_('Confirmez le mot de passe'), secret=True):
            break
        print(_('Mot de passe trop court ou confirmation différente'))
    print(_('\nHTTPS : un certificat local sera créé. Importez-le comme certificat de confiance\nou remplacez-le par un certificat de votre PKI. Aucun port HTTP public nécessaire.'))
    print(_('3/4 — Maintenance : correctifs Debian et publications signées.'))
    auto = ask(_('Activer les mises à jour de sécurité Debian automatiques ? y/n'), 'y') == 'y'
    manifest = input(_('URL HTTPS du manifeste de mises à jour applicatives signées (vide si pas encore publié) : ')).strip()
    signing_key = input(_('Clé publique Ed25519 Base64 de l’éditeur : ')).strip() if manifest else ''
    if manifest and (not manifest.startswith('https://') or len(base64.b64decode(signing_key, validate=True)) != 32):
        raise ValueError(_('Source de mises à jour ou clé invalide'))
    print(_('4/4 — Vérifiez : IP fixe ou réservation DHCP, accès console et serveur dédié.'))
    if ask(_('Ces prérequis sont-ils assurés ? y/n'), 'n') != 'y':
        raise SystemExit(_('Installation annulée.'))
    print(_('\nRÉCAPITULATIF\n') + json.dumps(p, indent=2, ensure_ascii=False))
    print(_('\nInstallation des dépendances, création des services, HTTPS privé et pare-feu.\nLes entrées non autorisées et le transfert hors VPN seront bloqués.\nAucune modification de l’adresse IP du serveur ni de la configuration SSH.\nAucun redémarrage automatique. L’inscription 2FA sera facultative dans la dashboard.'))
    if input(_('Tapez INSTALLER pour appliquer : ')) != 'INSTALLER':
        raise SystemExit(_('Installation annulée.'))
    return p, username, password, auto, {'manifest_url': manifest, 'public_key': signing_key}


def service_script(name, command, user):
    return f'''#!/bin/sh
### BEGIN INIT INFO
# Provides: {name}
# Required-Start: $network $remote_fs
# Required-Stop: $network $remote_fs
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Keyboarded service
### END INIT INFO
set -eu
case "${{1:-}}" in
 start) start-stop-daemon --start --quiet --background --make-pidfile --pidfile /run/{name}.pid --chuid {user} --startas /bin/sh -- -c 'exec {command} >>/var/log/keyboarded/{name}.log 2>&1' ;;
 stop) start-stop-daemon --stop --quiet --retry TERM/20/KILL/5 --pidfile /run/{name}.pid --remove-pidfile || true ;;
 restart) "$0" stop; "$0" start ;;
 status) test -f /run/{name}.pid && kill -0 "$(cat /run/{name}.pid)" ;;
 *) echo 'Usage: start|stop|restart|status'; exit 2 ;;
esac
'''


def preflight(p):
    """Abort before package/service mutations on an unsupported or occupied host."""
    import pwd
    import grp
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'debian' or release.get('VERSION_ID', '').strip('"') not in ('12', '13'):
        raise ValueError('This release supports Debian 12 and 13 only')
    if not Path('/run/systemd/system').is_dir():
        raise ValueError('Debian with systemd required for this release')
    for path in (APP, ROOT, DATA, STATE, Path('/usr/sbin/policy-rc.d'), Path('/etc/nginx/sites-available/keyboarded'), Path('/etc/systemd/system/keyboarded-web.service'), Path('/etc/systemd/system/keyboarded-agent.service')):
        if path.exists() or path.is_symlink():
            raise ValueError(f'Existing installation component: {path}')
    for lookup in (pwd.getpwnam, grp.getgrnam):
        try:
            lookup('wireguardian-svc')
        except KeyError:
            pass
        else:
            raise ValueError('The dedicated service account/group already exists')
    if shutil.disk_usage('/').free < 2 * 1024**3:
        raise ValueError('At least 2 GiB of free disk space required')
    routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
    vpn = ipaddress.ip_network(p['vpn_network'])
    for route in routes:
        destination = route.get('dst', 'default')
        if destination == 'default':
            continue
        if vpn.overlaps(ipaddress.ip_network(destination, strict=False)):
            raise ValueError('VPN subnet overlaps an existing route')
    listeners = subprocess.check_output(['ss', '-H', '-lun', 'sport', '=', ':' + str(p['port'])], text=True)
    if listeners.strip():
        raise ValueError('The requested WireGuard UDP port is already occupied')
    if shutil.which('nft') and subprocess.check_output(['nft', 'list', 'ruleset'], text=True).strip():
        raise ValueError('Existing firewall rules: use a dedicated server with reviewed networking')
    effective = subprocess.check_output(['/usr/sbin/sshd', '-T'], text=True)
    if f"port {p['ssh_port']}" not in effective.splitlines():
        raise ValueError('SSH port does not match the current SSH server configuration')


def install(p, username, password, automatic, release):
    os.umask(0o022)
    init_name = Path('/proc/1/comm').read_text().strip()
    if not Path('/run/systemd/system').exists() and not Path('/run/runit').exists() and init_name not in ('init', 'runit'):
        raise ValueError(_('Init {value0} non pris en charge : systemd, SysV ou runit requis.').format(value0=init_name))
    if APP.exists() or ROOT.exists():
        raise ValueError(_('Installation existante détectée. Aucun écrasement : utilisez la maintenance ou la restauration.'))
    # Refuse competing tunnel; preserve unrelated services rather than reconfiguring them.
    if Path('/etc/wireguard/wg0.conf').exists() or subprocess.run(['ip', 'link', 'show', 'wg0'], capture_output=True).returncode == 0:
        raise ValueError(_('wg0 existe déjà. Serveur dédié requis.'))
    addresses = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show', 'dev', p['interface']]))
    if not any(a.get('local') == p['admin_address'] for item in addresses for a in item.get('addr_info', [])):
        raise ValueError(_('Adresse d’administration absente de l’interface choisie. Configurez une IP fixe avant installation.'))
    ssh_client = os.environ.get('SSH_CONNECTION', '').split()
    if ssh_client and not any(ipaddress.ip_address(ssh_client[0]) in ipaddress.ip_network(n) for n in p['admin_networks']):
        raise ValueError(_('Votre connexion SSH actuelle serait bloquée. Corrigez les réseaux autorisés ou utilisez la console.'))
    if subprocess.run(['sh', '-c', 'ss -ltnH sport = :443 | test -z "$(cat)"'], capture_output=True).returncode:
        raise ValueError(_('Le port HTTPS 443 est déjà occupé. Serveur dédié requis.'))
    preflight(p)
    run(['apt-get', 'update'])
    # Do not let newly installed services listen before private HTTPS is configured.
    guard = Path('/usr/sbin/policy-rc.d')
    if guard.exists():
        raise ValueError('Existing policy-rc.d: inspect service-start policy before installation')
    write(guard, '#!/bin/sh\nexit 101\n', 0o755)
    try:
        run(['apt-get', 'install', '-y', '--no-install-recommends', *PACKAGES], env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    finally:
        guard.unlink()
    subprocess.run(['modprobe', 'wireguard'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(['useradd', '--system', '--user-group', '--home-dir', str(DATA), '--shell', '/usr/sbin/nologin', 'wireguardian-svc'])
    source = Path(__file__).resolve().parent.parent
    APP.mkdir(mode=0o755)
    for name in ('app', 'panel', 'deploy', 'templates', 'static', 'locale', 'manage.py', 'requirements.lock', 'VERSION', 'RELEASE_SEQUENCE', 'LICENSE'):
        item = source / name
        if item.is_dir():
            shutil.copytree(item, APP / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        else:
            shutil.copy2(item, APP / name)
    ROOT.mkdir(mode=0o750)
    DATA.mkdir(mode=0o700)
    STATE.mkdir(mode=0o700)
    Path('/var/log/keyboarded').mkdir(mode=0o750)
    run(['chown', 'root:wireguardian-svc', str(ROOT)])
    run(['chown', 'wireguardian-svc:wireguardian-svc', str(DATA)])
    run(['chown', 'root:wireguardian-svc', '/var/log/keyboarded'])
    write(Path('/var/log/keyboarded/keyboarded-web.log'), '', 0o600)
    run(['chown', 'wireguardian-svc:wireguardian-svc', '/var/log/keyboarded/keyboarded-web.log'])
    write(ROOT / 'policy.json', json.dumps(p, indent=2), 0o640)
    write(ROOT / 'release.json', json.dumps(release), 0o600)
    write(STATE / 'peers.json', '[]')
    run(['nft', '-c', '-f', '-'], input=firewall(p, []), text=True)
    write(ROOT / 'firewall.nft', firewall(p, []))
    nft_config = Path('/etc/nftables.conf')
    if nft_config.exists():
        shutil.copy2(nft_config, ROOT / 'nftables.before-install.conf')
    # Dedicated server install: preserve existing file, append only our table include.
    with nft_config.open('a') as stream:
        stream.write('\ninclude "/etc/keyboarded/firewall.nft"\n')
    private = subprocess.check_output(['/usr/bin/wg', 'genkey'], text=True).strip()
    write(ROOT / 'wireguard.key', private + '\n')
    env = {'APP_LANGUAGE': language_code(), 'DJANGO_SECRET_KEY': secrets.token_urlsafe(64), 'ALLOWED_HOSTS': p['admin_address'] + ',' + p['vpn_address'], 'DATABASE_PATH': str(DATA / 'database.sqlite3'), 'KEYBOARDED_POLICY': str(ROOT / 'policy.json')}
    write(ROOT / 'web.env', json.dumps(env), 0o640)
    run(['chown', 'root:wireguardian-svc', str(ROOT / 'policy.json'), str(ROOT / 'web.env')])
    run(['python3', '-m', 'venv', str(APP / '.venv')])
    python = str(APP / '.venv/bin/python')
    run([python, '-m', 'pip', 'install', '--only-binary=:all:', '--require-hashes', '-r', str(APP / 'requirements.lock')])
    run([python, str(APP / 'deploy/run_web.py'), '--migrate'])
    run([python, str(APP / 'manage.py'), 'collectstatic', '--noinput'], env={**os.environ, **env})
    create = 'import django; django.setup(); from django.contrib.auth.models import User; from django.contrib.auth.password_validation import validate_password; import json,sys; d=json.load(sys.stdin); u=User(username=d["username"]); validate_password(d["password"],u); User.objects.create_superuser(d["username"],password=d["password"])'
    run(['runuser', '-u', 'wireguardian-svc', '--', python, '-c', create], cwd=APP, input=json.dumps({'username': username, 'password': password}), text=True, env={**os.environ, **env, 'DJANGO_SETTINGS_MODULE': 'app.settings'})
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-days', '365', '-nodes', '-keyout', str(ROOT / 'tls.key'), '-out', str(ROOT / 'tls.crt'), '-subj', '/CN=WireGuardian', '-addext', f'subjectAltName=IP:{p["admin_address"]},IP:{p["vpn_address"]}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    allow = '\n'.join('    allow ' + n + ';' for n in p['admin_networks'] + [p['vpn_network']])
    nginx = f'''server {{
    listen 443 ssl;
    server_name _;
    ssl_certificate /etc/keyboarded/tls.crt;
    ssl_certificate_key /etc/keyboarded/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
{allow}
    deny all;
    client_max_body_size 32k;
    location / {{
        proxy_pass http://127.0.0.1:9080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 65s;
    }}
}}
'''
    write(Path('/etc/nginx/sites-available/keyboarded'), nginx, 0o644)
    default = Path('/etc/nginx/sites-enabled/default')
    if default.is_symlink():
        default.unlink()
    Path('/etc/nginx/sites-enabled/keyboarded').symlink_to('/etc/nginx/sites-available/keyboarded')
    write(Path('/etc/sysctl.d/70-keyboarded.conf'), 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.default.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv4.conf.default.accept_source_route=0\n', 0o644)
    run(['sysctl', '-p', '/etc/sysctl.d/70-keyboarded.conf'], stdout=subprocess.DEVNULL)
    write(Path('/etc/apt/apt.conf.d/52keyboarded'), 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "' + ('1' if automatic else '0') + '";\nUnattended-Upgrade::Automatic-Reboot "false";\n', 0o644)
    write(Path('/etc/cron.d/keyboarded'), '17 3 * * * wireguardian-svc cd /opt/keyboarded && /opt/keyboarded/.venv/bin/python deploy/expire_sessions.py\n', 0o644)
    write(Path('/etc/logrotate.d/keyboarded'), '/var/log/keyboarded/*.log {\n weekly\n rotate 8\n compress\n missingok\n notifempty\n copytruncate\n}\n', 0o644)
    for name, command, user in [('keyboarded-agent', f'{python} {APP}/deploy/agent.py', 'root'), ('keyboarded-web', f'{python} {APP}/deploy/run_web.py', 'wireguardian-svc')]:
        write(Path('/etc/init.d') / name, service_script(name, command, user), 0o755)
        if Path('/run/systemd/system').exists():
            hardening = 'NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths=/var/lib/keyboarded\n' if user != 'root' else ''
            unit = f'[Unit]\nDescription={name}\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nUser={user}\nExecStart={command}\nRestart=on-failure\nRestartSec=3\nUMask=0077\n{hardening}[Install]\nWantedBy=multi-user.target\n'
            write(Path('/etc/systemd/system') / (name + '.service'), unit, 0o644)
        elif Path('/run/runit').exists() or 'runit' in Path('/proc/1/comm').read_text():
            active = Path('/etc/service')
            if not active.is_dir():
                raise ValueError(_('Runit détecté mais /etc/service est absent. Configuration manuelle requise.'))
            command_prefix = '' if user == 'root' else '/usr/bin/chpst -u wireguardian-svc:wireguardian-svc '
            script = f'#!/bin/sh\nexec 2>&1\nexec {command_prefix}{command} >>/var/log/keyboarded/{name}.log 2>&1\n'
            write(Path('/etc/sv') / name / 'run', script, 0o755)
            (active / name).symlink_to(Path('/etc/sv') / name)
            # service(8) implementations vary across antiX releases; keep an explicit bridge.
            write(Path('/etc/init.d') / name, f'#!/bin/sh\nexec /usr/bin/sv "$1" /etc/service/{name}\n', 0o755)
        else:
            run(['update-rc.d', name, 'defaults'])
    if Path('/run/systemd/system').exists():
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', 'nftables'])
        run(['systemctl', 'enable', '--now', 'keyboarded-agent', 'keyboarded-web'])
    else:
        run(['update-rc.d', 'nftables', 'defaults'])
        run(['service', 'keyboarded-agent', 'start'])
        run(['service', 'keyboarded-web', 'start'])
    run(['nginx', '-t'])
    run(['systemctl', 'enable', '--now', 'cron', 'apt-daily.timer', 'apt-daily-upgrade.timer'])
    run(['systemctl', 'enable', 'nginx'])
    run(['service', 'nginx', 'restart'])
    context = ssl.create_default_context(cafile=str(ROOT / 'tls.crt'))
    for attempt in range(15):
        try:
            run(['/usr/bin/wg', 'show', 'wg0', 'public-key'], stdout=subprocess.DEVNULL)
            with urllib.request.urlopen(f'https://{p["admin_address"]}/connexion/', context=context, timeout=3) as response:
                if response.status == 200:
                    break
        except (OSError, subprocess.CalledProcessError):
            time.sleep(1)
    else:
        raise ValueError(_('Les services ne répondent pas. Inspectez /var/log/keyboarded et les services depuis la console.'))
    print(_('\nInstallation terminée : https://{value0}\nImportez /etc/keyboarded/tls.crt sur vos postes d’administration.\nRedirigez uniquement UDP {value1} sur votre routeur.\nVérifiez un redémarrage et un client VPN avant mise en service.\n').format(value0=p['admin_address'], value1=p['port']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Installation interactive de WireGuardian sur Debian dédié')
    parser.add_argument('--questionnaire-only', action='store_true', help='Afficher les questions sans installer')
    parser.add_argument('--language', choices=('fr', 'en', 'de', 'es', 'it'), help='Installer language')
    args = parser.parse_args()
    select_language(args.language)
    if sys.version_info < (3, 11):
        raise SystemExit(_('Python >=3.11 requis : Debian 12/13 ou antiX sur une base correspondante.'))
    if not args.questionnaire_only and (os.name != 'posix' or os.geteuid() != 0):
        raise SystemExit(_('Installation à lancer en root sur Debian/antiX.'))
    try:
        if not args.questionnaire_only:
            import fcntl
            installation_lock = open('/run/wireguardian-install.lock', 'w')
            fcntl.flock(installation_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        values = questionnaire()
        if not args.questionnaire_only:
            install(*values)
    except KeyboardInterrupt:
        raise SystemExit('\nInstallation interrupted. Inspect the current state before retrying.')
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(_('Installation arrêtée : {value0}. Consultez la console ; aucun nettoyage destructif automatique.').format(value0=exc))
