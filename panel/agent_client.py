from django.utils.translation import gettext as _, gettext_noop as N
import json
import socket
from django.conf import settings


class AgentUnavailable(Exception):
    pass


def call(operation, **payload):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(30)
            client.connect(settings.AGENT_SOCKET)
            client.sendall(json.dumps({'operation': operation, **payload}).encode() + b'\n')
            data = b''
            while not data.endswith(b'\n'):
                part = client.recv(8192)
                if not part or len(data) > (90 * 1024 * 1024 if operation == 'download_backup' else 262144):
                    raise ValueError('Invalid agent response')
                data += part
            result = json.loads(data)
            if not result.get('ok'):
                raise ValueError('Agent refused operation')
            return result
    except (OSError, ValueError, AttributeError) as exc:
        raise AgentUnavailable(_('Service WireGuard indisponible ou opération refusée. Consultez les journaux système.')) from exc
