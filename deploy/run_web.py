#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

root = Path('/opt/keyboarded')
os.chdir(root)
sys.path.insert(0, str(root))
os.environ.update(json.loads(Path('/etc/keyboarded/web.env').read_text()))
os.environ['DJANGO_SETTINGS_MODULE'] = 'app.settings'
if '--migrate' in sys.argv:
    import pwd
    account = pwd.getpwnam('wireguardian-svc')
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    import django
    django.setup()
    from django.core.management import call_command
    call_command('migrate', interactive=False)
else:
    from waitress import serve
    from app.wsgi import application
    # Only nginx is allowed to supply the HTTPS marker; no forwarded client-IP trust.
    serve(application, host='127.0.0.1', port=9080, threads=4,
          trusted_proxy='127.0.0.1', trusted_proxy_headers={'x-forwarded-proto', 'x-forwarded-for'},
          clear_untrusted_proxy_headers=True, max_request_body_size=32768)
