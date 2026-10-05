import json
import os
from pathlib import Path
import sys
sys.path.insert(0, '/opt/keyboarded')
os.environ.update(json.loads(Path('/etc/keyboarded/web.env').read_text()))
os.environ['DJANGO_SETTINGS_MODULE'] = 'app.settings'
import django
django.setup()
from django.core.management import call_command
call_command('clearsessions')
