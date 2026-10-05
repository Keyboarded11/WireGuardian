#!/usr/bin/env python3
"""Privileged maintenance jobs. Sources and signing key are root configured."""
import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from agent import atomic, ROOT, STATE
from backup_crypto import encrypt, decrypt

APP = Path('/opt/keyboarded')
DATA = Path('/var/lib/keyboarded')
BACKUP_FILES = ['database.sqlite3', 'policy.json', 'web.env', 'wireguard.key', 'peers.json']


def backup(password):
    if not 14 <= len(password) <= 1024:
        raise ValueError('Backup password must contain at least 14 characters')
    with tempfile.TemporaryDirectory(dir=STATE) as temporary:
        folder = Path(temporary)
        source = sqlite3.connect(f'file:{DATA / "database.sqlite3"}?mode=ro', uri=True)
        destination = sqlite3.connect(folder / 'database.sqlite3')
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        for name in BACKUP_FILES[1:]:
            shutil.copy2((STATE if name == 'peers.json' else ROOT) / name, folder / name)
        memory = io.BytesIO()
        with tarfile.open(fileobj=memory, mode='w:gz') as archive:
            for name in BACKUP_FILES:
                archive.add(folder / name, arcname=name)
        if memory.tell() > 48 * 1024 * 1024:
            raise ValueError('Backup exceeds dashboard limit; archive from console')
        encrypted = encrypt(memory.getvalue(), password)
        target = STATE / 'backup.kwg'
        descriptor, name = tempfile.mkstemp(dir=STATE)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(encrypted)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, target)


def fetch(url, maximum):
    if not url.startswith('https://'):
        raise ValueError('HTTPS release URLs required')
    with urllib.request.urlopen(url, timeout=30) as response:
        if not response.url.startswith('https://'):
            raise ValueError('Insecure redirect')
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError('Release exceeds size limit')
    return data


def update_app():
    # Trust is established at installation, never from dashboard input.
    previous = Path('/opt/keyboarded.previous')
    if previous.is_symlink():
        raise ValueError('Unexpected previous-release symlink')
    release = json.loads((ROOT / 'release.json').read_text())
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(release['public_key'], validate=True))
    manifest_bytes = fetch(release['manifest_url'], 16384)
    signature = fetch(release['manifest_url'] + '.sig', 1024)
    key.verify(base64.b64decode(signature, validate=True), manifest_bytes)
    manifest = json.loads(manifest_bytes)
    current = int((APP / 'RELEASE_SEQUENCE').read_text())
    if type(manifest['sequence']) is not int or manifest['sequence'] <= current:
        raise ValueError('Release is not newer than installed version')
    bundle = fetch(manifest['url'], 32 * 1024 * 1024)
    if hashlib.sha256(bundle).hexdigest() != manifest['sha256']:
        raise ValueError('Release checksum mismatch')
    stage = Path(tempfile.mkdtemp(prefix='keyboarded-release-', dir='/opt'))
    try:
        with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
            if sum(info.file_size for info in archive.infolist()) > 128 * 1024 * 1024:
                raise ValueError('Expanded release too large')
            for info in archive.infolist():
                parts = Path(info.filename).parts
                if not parts or Path(info.filename).is_absolute() or '..' in parts or '\\' in info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError('Unsafe release entry')
            archive.extractall(stage)
        if int((stage / 'RELEASE_SEQUENCE').read_text()) != manifest['sequence']:
            raise ValueError('Release sequence mismatch')
        subprocess.run(['/usr/bin/python3', '-m', 'venv', str(stage / '.venv')], check=True)
        subprocess.run([str(stage / '.venv/bin/pip'), 'install', '--require-hashes', '-r', str(stage / 'requirements.lock')], check=True)
        subprocess.run([str(stage / '.venv/bin/python'), '-m', 'compileall', '-q', str(stage)], check=True)
        # Worker uses umask 077 for secrets; release code must remain readable by
        # the unprivileged web service. Never follow venv interpreter symlinks.
        stage.chmod(0o755)
        for path in stage.rglob('*'):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        if previous.exists():
            shutil.rmtree(previous)
        # Release transaction: stop web, snapshot DB, migrate, rollback code + DB on failure.
        subprocess.run(['/usr/sbin/service', 'keyboarded-web', 'stop'], check=True)
        database = DATA / 'database.sqlite3'
        shutil.copy2(database, STATE / 'pre-update.sqlite3')
        APP.rename(previous)
        stage.rename(APP)
        try:
            subprocess.run([str(APP / '.venv/bin/python'), str(APP / 'deploy/run_web.py'), '--migrate'], check=True)
            env = {**os.environ, **json.loads((ROOT / 'web.env').read_text())}
            subprocess.run([str(APP / '.venv/bin/python'), str(APP / 'manage.py'), 'collectstatic', '--noinput'], env=env, check=True)
            subprocess.run(['/usr/sbin/service', 'keyboarded-agent', 'restart'], check=True)
            subprocess.run(['/usr/sbin/service', 'keyboarded-web', 'start'], check=True)
            for attempt in range(15):
                try:
                    request = urllib.request.Request('http://127.0.0.1:9080/connexion/', headers={'Host': env['ALLOWED_HOSTS'].split(',')[0], 'X-Forwarded-Proto': 'https'})
                    with urllib.request.urlopen(request, timeout=2) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(1)
            else:
                raise ValueError('New web service did not become healthy')
        except Exception:
            subprocess.run(['/usr/sbin/service', 'keyboarded-web', 'stop'], check=False)
            APP.rename(stage)
            previous.rename(APP)
            shutil.copy2(STATE / 'pre-update.sqlite3', database)
            subprocess.run(['/usr/sbin/service', 'keyboarded-agent', 'restart'], check=False)
            subprocess.run(['/usr/sbin/service', 'keyboarded-web', 'start'], check=False)
            raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    os.umask(0o077)
    operation = sys.argv[1]
    with open(STATE / 'maintenance.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        started = time.time()
        def report(state, message):
            atomic(STATE / 'maintenance.json', json.dumps({'state': state, 'operation': operation, 'message': message, 'started': started, 'finished': time.time() if state != 'running' else None, 'reboot_required': Path('/var/run/reboot-required').exists()}))
        report('running', 'Opération en cours')
        try:
            if operation == 'backup':
                backup(sys.stdin.readline().rstrip('\n'))
            elif operation == 'update_system':
                env = {**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'a'}
                with open(STATE / 'apt.log', 'a') as log:
                    subprocess.run(['/usr/bin/apt-get', 'update'], check=True, stdout=log, stderr=log, env=env, timeout=900)
                    subprocess.run(['/usr/bin/apt-get', '-y', '-o', 'Dpkg::Options::=--force-confold', 'upgrade'], check=True, stdout=log, stderr=log, env=env, timeout=3600)
            elif operation == 'update_app':
                update_app()
            else:
                raise ValueError('Unsupported job')
            report('complete', 'Opération terminée. Vérifiez les services après une mise à jour.')
        except Exception as exc:
            # Error type is useful without exposing URLs, subprocess input or secrets.
            report('failed', f'Échec de l’opération ({type(exc).__name__}). Consultez la console et les journaux de maintenance.')


if __name__ == '__main__':
    main()
