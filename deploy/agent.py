#!/usr/bin/env python3
"""Root-owned, local socket agent. Never accepts paths, commands or private keys."""
import base64
import grp
import json
import logging
import os
from pathlib import Path
import pwd
import socket
import struct
import subprocess
import tempfile

from core import validate_policy, validate_peers, wg_config, firewall

ROOT = Path('/etc/keyboarded')
STATE = Path('/var/lib/keyboarded-agent')
SOCKET = Path('/run/keyboarded/agent.sock')


def run(args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True, check=True, timeout=20).stdout


def atomic(path, text, mode=0o600):
    descriptor, name = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def policy():
    return validate_policy(json.loads((ROOT / 'policy.json').read_text()))


def saved_peers():
    path = STATE / 'peers.json'
    return json.loads(path.read_text()) if path.exists() else []


def apply_firewall(p, peers):
    exists = subprocess.run(['/usr/sbin/nft', 'list', 'table', 'inet', 'keyboarded'], capture_output=True).returncode == 0
    rules = ('delete table inet keyboarded\n' if exists else '') + firewall(p, peers)
    run(['/usr/sbin/nft', '-c', '-f', '-'], rules)
    run(['/usr/sbin/nft', '-f', '-'], rules)
    atomic(ROOT / 'firewall.nft', firewall(p, peers))


def sync(p, peers):
    validate_peers(peers, p)
    private = (ROOT / 'wireguard.key').read_text().strip()
    new_config = wg_config(p, peers, private)
    old_peers = saved_peers()
    path = STATE / 'sync.conf'
    try:
        # ACL is applied first to close revoked egress immediately.
        apply_firewall(p, peers)
        atomic(path, new_config)
        run(['/usr/bin/wg', 'syncconf', 'wg0', str(path)])
        atomic(STATE / 'peers.json', json.dumps(peers))
    except Exception:
        apply_firewall(p, old_peers)
        atomic(path, wg_config(p, old_peers, private))
        run(['/usr/bin/wg', 'syncconf', 'wg0', str(path)])
        raise


def boot():
    p = policy()
    if subprocess.run(['/usr/sbin/ip', 'link', 'show', 'wg0'], capture_output=True).returncode:
        run(['/usr/sbin/ip', 'link', 'add', 'wg0', 'type', 'wireguard'])
    prefix = p['vpn_network'].split('/')[1]
    run(['/usr/sbin/ip', 'address', 'replace', p['vpn_address'] + '/' + prefix, 'dev', 'wg0'])
    sync(p, saved_peers())
    run(['/usr/sbin/ip', 'link', 'set', 'wg0', 'up'])


def status():
    lines = run(['/usr/bin/wg', 'show', 'wg0', 'dump']).strip().splitlines()
    header = lines[0].split('\t')
    peers = {}
    for line in lines[1:]:
        values = line.split('\t')
        peers[values[0]] = {'handshake': int(values[4]), 'rx': int(values[5]), 'tx': int(values[6])}
    return {'ok': True, 'public_key': header[1], 'port': int(header[2]), 'peers': peers}


def dispatch(data):
    operation = data.get('operation')
    if operation == 'status' and set(data) == {'operation'}:
        return status()
    if operation == 'sync' and set(data) == {'operation', 'peers'}:
        sync(policy(), data['peers'])
        return {'ok': True}
    if operation == 'maintenance_status' and set(data) == {'operation'}:
        file = STATE / 'maintenance.json'
        return {'ok': True, 'job': json.loads(file.read_text()) if file.exists() else {'state': 'idle'}}
    if (operation in ('update_system', 'update_app') and set(data) == {'operation'}) or (operation == 'backup' and set(data) == {'operation', 'password'}):
        # Worker holds an exclusive flock; dashboard cannot launch arbitrary commands.
        if operation == 'backup' and (not isinstance(data['password'], str) or not 14 <= len(data['password']) <= 1024 or '\n' in data['password']):
            raise ValueError('Invalid backup password')
        child = subprocess.Popen(['/opt/keyboarded/.venv/bin/python', '/opt/keyboarded/deploy/maintenance.py', operation], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        child.stdin.write((data.get('password', '') + '\n').encode())
        child.stdin.close()
        return {'ok': True}
    if operation == 'download_backup' and set(data) == {'operation'}:
        path = STATE / 'backup.kwg'
        if not path.exists() or path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('No backup available or archive too large')
        return {'ok': True, 'archive': base64.b64encode(path.read_bytes()).decode()}
    if operation == 'configure' and set(data) == {'operation', 'policy'}:
        old = policy()
        new = validate_policy(data['policy'])
        # Server address and VPN prefix changes require migration of every client.
        if any(new[k] != old[k] for k in ('vpn_network', 'vpn_address', 'admin_address', 'admin_networks', 'ssh_port')):
            raise ValueError('Address migration requires console reconfiguration')
        run(['/usr/sbin/ip', 'link', 'show', 'dev', new['interface']])
        validate_peers(saved_peers(), new)
        try:
            sync(new, saved_peers())
            atomic(ROOT / 'policy.json', json.dumps(new, indent=2), 0o640)
            os.chown(ROOT / 'policy.json', 0, grp.getgrnam('wireguardian-svc').gr_gid)
        except Exception:
            sync(old, saved_peers())
            raise
        return {'ok': True}
    raise ValueError('Unsupported operation')


def main():
    os.umask(0o077)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    SOCKET.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(SOCKET.parent, 0, grp.getgrnam('wireguardian-svc').gr_gid)
    os.chmod(SOCKET.parent, 0o750)
    SOCKET.unlink(missing_ok=True)
    boot()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(SOCKET))
        os.chown(SOCKET, 0, grp.getgrnam('wireguardian-svc').gr_gid)
        os.chmod(SOCKET, 0o660)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                try:
                    _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if uid != pwd.getpwnam('wireguardian-svc').pw_uid:
                        raise ValueError('Unauthorized Unix peer')
                    body = b''
                    while not body.endswith(b'\n'):
                        part = connection.recv(4096)
                        if not part or len(body) + len(part) > 262144:
                            raise ValueError('Invalid message')
                        body += part
                    result = dispatch(json.loads(body))
                except Exception:
                    logging.error('Agent operation failed; no request body or secret logged')
                    result = {'ok': False}
                try:
                    connection.sendall(json.dumps(result).encode() + b'\n')
                except OSError:
                    pass


if __name__ == '__main__':
    main()
