"""Maintainer command: resolve hashes for the already-installed runtime versions."""
import importlib.metadata as metadata
import json
from pathlib import Path
import urllib.request

names = ['Django', 'django-otp', 'argon2-cffi', 'argon2-cffi-bindings', 'waitress', 'whitenoise', 'cryptography', 'qrcode', 'asgiref', 'sqlparse', 'tzdata', 'cffi', 'pycparser', 'colorama']
lines = ['# Exact runtime versions and distribution hashes. Python >=3.11.']
for name in names:
    version = metadata.version(name)
    with urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{version}/json', timeout=30) as response:
        data = json.load(response)
    hashes = sorted({item['digests']['sha256'] for item in data['urls']})
    lines.append(name + '==' + version + ' ' + ' '.join('--hash=sha256:' + value for value in hashes))
Path('requirements.lock').write_text('\n'.join(lines) + '\n', encoding='utf-8')
Path('requirements.txt').write_text('\n'.join(f'{name}=={metadata.version(name)}' for name in names) + '\n', encoding='utf-8')
print('Pinned', len(names), 'runtime packages with distribution hashes.')
