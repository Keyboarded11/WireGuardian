"""Validated policy and deterministic firewall/config rendering; no shell input."""
import base64
import ipaddress
import re


def network(value):
    result = ipaddress.ip_network(value, strict=True)
    if result.version != 4:
        raise ValueError('IPv4 networks required; IPv6 is blocked inside the tunnel.')
    return result


def validate_policy(p):
    required = {'admin_address', 'admin_networks', 'lan_networks', 'vpn_network', 'vpn_address', 'port', 'endpoint', 'dns', 'interface', 'ssh_port'}
    if not required.issubset(p):
        raise ValueError('Incomplete installation policy')
    if ipaddress.ip_address(p['admin_address']).version != 4:
        raise ValueError('IPv4 administration address required')
    vpn = network(p['vpn_network'])
    if not 22 <= vpn.prefixlen <= 29:
        raise ValueError('VPN subnet must be /22 to /29')
    if ipaddress.ip_address(p['vpn_address']) not in list(vpn.hosts()):
        raise ValueError('Invalid VPN server address')
    for field in ('lan_networks', 'admin_networks'):
        if not isinstance(p[field], list) or not 1 <= len(p[field]) <= 16:
            raise ValueError('Provide 1 to 16 networks')
        for item in p[field]:
            subnet = network(item)
            if subnet.prefixlen == 0 or subnet.is_multicast or subnet.is_loopback:
                raise ValueError('Unrestricted or unusable network is not allowed')
            if vpn.overlaps(subnet):
                raise ValueError('VPN and LAN networks overlap')
    if not any(ipaddress.ip_address(p['admin_address']) in network(n) for n in p['admin_networks']):
        raise ValueError('Administration address must be inside an administration network')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', p['interface']):
        raise ValueError('Invalid interface name')
    if not all(type(p[k]) is int and 1 <= p[k] <= 65535 for k in ('port', 'ssh_port')):
        raise ValueError('Invalid port')
    endpoint = p['endpoint']
    if not isinstance(endpoint, str) or len(endpoint) > 253 or (endpoint and any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part) for part in endpoint.split('.'))):
        raise ValueError('Invalid public endpoint')
    if p.get('dns'):
        if ipaddress.ip_address(p['dns']).version != 4:
            raise ValueError('IPv4 DNS required')
    return p


def validate_peers(peers, p):
    if not isinstance(peers, list) or len(peers) > 1021:
        raise ValueError('Invalid peer list')
    keys, addresses = set(), set()
    net = network(p['vpn_network'])
    for peer in peers:
        if set(peer) != {'public_key', 'address', 'internet'} or type(peer['internet']) is not bool:
            raise ValueError('Invalid peer fields')
        key = peer['public_key']
        raw = base64.b64decode(key, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode() != key or not any(raw):
            raise ValueError('Invalid WireGuard public key')
        address = ipaddress.ip_address(peer['address'])
        if address not in net or str(address) in (p['vpn_address'], str(net.network_address), str(net.broadcast_address)):
            raise ValueError('Peer outside allowed VPN subnet')
        if key in keys or str(address) in addresses:
            raise ValueError('Duplicate peer')
        keys.add(key)
        addresses.add(str(address))
    return peers


def wg_config(p, peers, private_key):
    validate_policy(p)
    validate_peers(peers, p)
    text = f'[Interface]\nPrivateKey = {private_key}\nListenPort = {p["port"]}\n'
    for peer in peers:
        text += f'\n[Peer]\nPublicKey = {peer["public_key"]}\nAllowedIPs = {peer["address"]}/32\n'
    return text


def firewall(p, peers):
    validate_policy(p)
    validate_peers(peers, p)
    admin = ', '.join(p['admin_networks'])
    lans = ', '.join(p['lan_networks'])
    full = ', '.join(peer['address'] for peer in peers if peer['internet'])
    all_peers = ', '.join(peer['address'] for peer in peers)
    clients_elements = f'elements = {{ {all_peers} }};' if all_peers else ''
    full_elements = f'elements = {{ {full} }};' if full else ''
    # Check WireGuard input/forward BEFORE established-state accepts: revocation is immediate.
    return f'''table inet keyboarded {{
 set clients {{ type ipv4_addr; {clients_elements} }}
 set full_tunnel {{ type ipv4_addr; {full_elements} }}
 chain input {{ type filter hook input priority -10; policy drop;
  iifname "lo" accept
  iifname "wg0" ip saddr @clients tcp dport 443 accept
  iifname "wg0" ip saddr @clients icmp type echo-request accept
  iifname "wg0" drop
  ct state established,related accept
  ct state invalid drop
  ip saddr {{ {admin} }} tcp dport {{ 443, {p['ssh_port']} }} accept
  udp dport {p['port']} accept
  ip protocol icmp accept
 }}
 chain forward {{ type filter hook forward priority -10; policy drop;
  iifname "wg0" oifname "wg0" drop
  iifname "wg0" ip saddr @clients ip daddr {{ {lans} }} accept
  iifname "wg0" ip saddr @full_tunnel meta nfproto ipv4 accept
  iifname "wg0" drop
  oifname "wg0" ip daddr @clients ip saddr {{ {lans} }} ct state established,related accept
  oifname "wg0" ip daddr @full_tunnel ct state established,related accept
 }}
 chain nat {{ type nat hook postrouting priority srcnat; policy accept;
  ip saddr {p['vpn_network']} oifname "{p['interface']}" masquerade
 }}
}}
'''
