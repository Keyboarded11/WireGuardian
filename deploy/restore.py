#!/usr/bin/env python3
"""Restore a downloaded encrypted backup from the server console."""
import getpass
import io
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile

from maintenance import decrypt, BACKUP_FILES
from agent import ROOT, STATE, atomic, boot
from core import validate_policy, validate_peers


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit('Usage (root) : /opt/keyboarded/.venv/bin/python deploy/restore.py archive.kwg')
    archive = Path(sys.argv[1])
    if archive.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('Archive trop volumineuse')
    clear = decrypt(archive.read_bytes(), getpass.getpass('Phrase de sauvegarde : '))
    with tarfile.open(fileobj=io.BytesIO(clear), mode='r:gz') as tar:
        members = tar.getmembers()
        if {item.name for item in members} != set(BACKUP_FILES) or len(members) != len(BACKUP_FILES) or any(not item.isfile() or item.size > 128 * 1024 * 1024 for item in members):
            raise ValueError('Contenu de sauvegarde invalide')
        content = {item.name: tar.extractfile(item).read() for item in members}
    p = validate_policy(json.loads(content['policy.json']))
    validate_peers(json.loads(content['peers.json']), p)
    current = json.loads((ROOT / 'policy.json').read_text())
    # Avoid silently restoring host-specific addresses / a secret path from another server.
    if any(p[k] != current[k] for k in ('admin_address', 'admin_networks', 'vpn_network', 'vpn_address', 'interface', 'ssh_port')):
        raise ValueError('La topologie de la sauvegarde diffère. Reconfigurez d’abord ce serveur depuis sa console.')
    print('Cette restauration remplace comptes, 2FA, clés et appareils. Toutes les sessions seront invalidées.')
    if input('Tapez RESTAURER : ') != 'RESTAURER':
        return
    account = pwd.getpwnam('wireguardian-svc')
    with tempfile.TemporaryDirectory(dir=STATE) as directory:
        stage = Path(directory)
        for name, data in content.items():
            (stage / name).write_bytes(data)
        database = sqlite3.connect(stage / 'database.sqlite3')
        if database.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Base de données endommagée')
        database.execute('DELETE FROM django_session')
        database.commit()
        database.close()
        subprocess.run(['service', 'keyboarded-web', 'stop'], check=True)
        subprocess.run(['service', 'keyboarded-agent', 'stop'], check=True)
        targets = {name: (Path('/var/lib/keyboarded/database.sqlite3') if name == 'database.sqlite3' else (STATE if name == 'peers.json' else ROOT) / name) for name in BACKUP_FILES}
        # Keep an on-server rollback snapshot; no deletion of the previous installation.
        previous = STATE / 'before-restore'
        if previous.exists():
            subprocess.run(['service', 'keyboarded-agent', 'start'], check=False)
            subprocess.run(['service', 'keyboarded-web', 'start'], check=False)
            raise ValueError('Une restauration précédente est conservée. Archivez before-restore avant de recommencer.')
        previous.mkdir(mode=0o700)
        for name, target in targets.items():
            shutil.copy2(target, previous / name)
        try:
            # Preserve local environment paths; only restore the application secret.
            old_env = json.loads((ROOT / 'web.env').read_text())
            saved_env = json.loads(content['web.env'])
            old_env['DJANGO_SECRET_KEY'] = saved_env['DJANGO_SECRET_KEY']
            (stage / 'web.env').write_text(json.dumps(old_env))
            for name, target in targets.items():
                shutil.copyfile(stage / name, target)
                os.chmod(target, 0o640 if name in ('policy.json', 'web.env') else 0o600)
                os.chown(target, account.pw_uid if name == 'database.sqlite3' else 0, account.pw_gid if name in ('database.sqlite3', 'policy.json', 'web.env') else 0)
            subprocess.run(['/opt/keyboarded/.venv/bin/python', '/opt/keyboarded/deploy/run_web.py', '--migrate'], check=True)
            boot()
        except Exception:
            for name, target in targets.items():
                shutil.copy2(previous / name, target)
            raise
        finally:
            subprocess.run(['service', 'keyboarded-agent', 'start'], check=True)
            subprocess.run(['service', 'keyboarded-web', 'start'], check=True)
    print('Configuration restaurée. Vérifiez les connexions VPN et reconnectez-vous à la dashboard.')


if __name__ == '__main__':
    main()
