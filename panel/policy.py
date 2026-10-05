import ipaddress
import json
import os
from pathlib import Path

DEFAULTS = {
    'admin_address': '127.0.0.1', 'lan_networks': ['198.18.0.0/24'],
    'vpn_network': '198.19.0.0/24', 'vpn_address': '198.19.0.1',
    'port': 51820, 'endpoint': '', 'full_tunnel': False, 'dns': '',
}


def policy():
    path = os.environ.get('KEYBOARDED_POLICY')
    if path:
        return json.loads(Path(path).read_text())
    if os.environ.get('KEYBOARDED_DEV') != '1':
        raise RuntimeError('Installation policy required in production')
    return DEFAULTS.copy()


def client_routes():
    p = policy()
    return ['0.0.0.0/0'] if p['full_tunnel'] else p['lan_networks'] + [p['vpn_address'] + '/32']


def available_addresses():
    p = policy()
    return (str(ip) for ip in ipaddress.ip_network(p['vpn_network']).hosts() if str(ip) != p['vpn_address'])
