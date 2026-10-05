#!/usr/bin/env python3
"""Console migration for parameters that can sever administration connectivity."""
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time

from agent import ROOT, STATE, atomic, boot
from core import validate_policy


def main():
    if os.geteuid() != 0:
        raise SystemExit('Console root requise.')
    old = json.loads((ROOT / 'policy.json').read_text())
    new = old.copy()
    print('Migration réseau depuis la console locale. Les profils clients devront être mis à jour.')
    labels = {'admin_address': 'IPv4 fixe de cette machine', 'admin_networks': 'Réseaux autorisés pour HTTPS/SSH', 'lan_networks': 'Réseaux LAN', 'vpn_network': 'Sous-réseau VPN', 'vpn_address': 'IPv4 du serveur VPN', 'interface': 'Interface de sortie', 'port': 'Port UDP WireGuard', 'ssh_port': 'Port SSH existant', 'endpoint': 'DNS/IP public', 'dns': 'DNS IPv4 des clients'}
    for key, label in labels.items():
        default = ','.join(old[key]) if isinstance(old[key], list) else str(old[key])
        answer = input(f'{label} [{default}] : ').strip() or default
        new[key] = [x.strip() for x in answer.split(',')] if isinstance(old[key], list) else int(answer) if type(old[key]) is int else answer
    validate_policy(new)
    addresses = json.loads(subprocess.check_output(['ip', '-j', 'address', 'show', 'dev', new['interface']]))
    if not any(a.get('local') == new['admin_address'] for item in addresses for a in item.get('addr_info', [])):
        raise ValueError('Configurez d’abord cette adresse sur l’interface système.')
    print(json.dumps(new, indent=2))
    if input('Tapez MIGRER (interruption du VPN et HTTPS) : ') != 'MIGRER':
        return
    snapshot = STATE / ('before-network-' + str(int(time.time())))
    snapshot.mkdir(mode=0o700)
    files = [ROOT / 'policy.json', ROOT / 'web.env', ROOT / 'tls.key', ROOT / 'tls.crt', STATE / 'peers.json', Path('/etc/nginx/sites-available/keyboarded'), Path('/var/lib/keyboarded/database.sqlite3')]
    subprocess.run(['service', 'keyboarded-web', 'stop'], check=True)
    subprocess.run(['service', 'keyboarded-agent', 'stop'], check=True)
    for path in files:
        shutil.copy2(path, snapshot / path.name)
    try:
        db = sqlite3.connect('/var/lib/keyboarded/database.sqlite3')
        peers = db.execute('SELECT id, public_key, enabled, internet FROM panel_peer ORDER BY id').fetchall()
        addresses = iter(str(ip) for ip in ipaddress.ip_network(new['vpn_network']).hosts() if str(ip) != new['vpn_address'])
        assignment = [(row, next(addresses)) for row in peers]
        # Temporary unique values inside one transaction avoid collisions on prefix changes.
        with db:
            for index, (row, ip) in enumerate(assignment):
                db.execute('UPDATE panel_peer SET address=? WHERE id=?', (f'pending-{index}', row[0]))
            for row, ip in assignment:
                db.execute('UPDATE panel_peer SET address=? WHERE id=?', (ip, row[0]))
            db.execute('UPDATE panel_configuration SET endpoint=?, revision=revision+1, applied_revision=revision+1', (new['endpoint'],))
            db.execute('DELETE FROM django_session')
        db.close()
        atomic(STATE / 'peers.json', json.dumps([{'public_key': row[1], 'address': ip, 'internet': bool(row[3])} for row, ip in assignment if row[2]]))
        atomic(ROOT / 'policy.json', json.dumps(new, indent=2), 0o640)
        env = json.loads((ROOT / 'web.env').read_text())
        env['ALLOWED_HOSTS'] = new['admin_address'] + ',' + new['vpn_address']
        atomic(ROOT / 'web.env', json.dumps(env), 0o640)
        shutil.chown(ROOT / 'policy.json', group='wireguardian-svc')
        shutil.chown(ROOT / 'web.env', group='wireguardian-svc')
        nginx = Path('/etc/nginx/sites-available/keyboarded')
        lines = [line for line in nginx.read_text().splitlines() if not line.strip().startswith('allow ')]
        text = '\n'.join(lines).replace('    deny all;', '\n'.join('    allow ' + n + ';' for n in new['admin_networks'] + [new['vpn_network']]) + '\n    deny all;')
        nginx.write_text(text)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-days', '365', '-nodes', '-keyout', str(ROOT / 'tls.key'), '-out', str(ROOT / 'tls.crt'), '-subj', '/CN=Keyboarded WireGuard', '-addext', f'subjectAltName=IP:{new["admin_address"]},IP:{new["vpn_address"]}'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['nginx', '-t'], check=True)
        subprocess.run(['ip', 'address', 'flush', 'dev', 'wg0'], check=True)
        boot()
        subprocess.run(['service', 'nginx', 'reload'], check=True)
    except Exception:
        for path in files:
            shutil.copy2(snapshot / path.name, path)
        subprocess.run(['ip', 'address', 'flush', 'dev', 'wg0'], check=False)
        boot()
        raise
    finally:
        subprocess.run(['service', 'keyboarded-agent', 'start'], check=True)
        subprocess.run(['service', 'keyboarded-web', 'start'], check=True)
    print('Migration terminée. Réimportez le certificat HTTPS et mettez à jour Address/AllowedIPs/Endpoint sur chaque client.')


if __name__ == '__main__':
    main()
