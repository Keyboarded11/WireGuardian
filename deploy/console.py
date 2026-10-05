import json
import os
from pathlib import Path
import sys
sys.path.insert(0, '/opt/keyboarded')
os.environ.update(json.loads(Path('/etc/keyboarded/web.env').read_text()))
os.environ['DJANGO_SETTINGS_MODULE'] = 'app.settings'
if os.geteuid() == 0:
    import pwd
    account = pwd.getpwnam('wireguardian-svc')
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
from django.core.management import execute_from_command_line
execute_from_command_line(sys.argv)
