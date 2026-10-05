"""Build a source release. Optionally sign its manifest using an external key file."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import zipfile
from compile_translations import compile_catalogs

ROOT = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser()
parser.add_argument('--url', help='HTTPS URL of the future published ZIP')
parser.add_argument('--signing-key', help='External file containing Base64 Ed25519 private key (32 bytes)')
args = parser.parse_args()
compile_catalogs()
version = (ROOT / 'VERSION').read_text().strip()
out = ROOT / 'artifacts'
out.mkdir(exist_ok=True)
archive_path = out / f'wireguardian-{version}.zip'
entries = ['app', 'panel', 'deploy', 'static', 'templates', 'locale', 'tests', 'docs', '.github', 'install.sh', 'manage.py', 'requirements.lock', 'requirements.txt', 'README.md', 'SECURITY.md', 'LICENSE', 'VERSION', 'RELEASE_SEQUENCE', '.gitignore']
with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
    for name in entries:
        path = ROOT / name
        files = path.rglob('*') if path.is_dir() else [path]
        for item in files:
            if item.is_file() and '__pycache__' not in item.parts and item.suffix != '.pyc':
                archive.write(item, item.relative_to(ROOT).as_posix())
digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
(out / (archive_path.name + '.sha256')).write_text(digest + '  ' + archive_path.name + '\n')
if args.signing_key:
    if not args.url or not args.url.startswith('https://'):
        raise SystemExit('--url HTTPS required when signing')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    manifest = json.dumps({'version': version, 'sequence': int((ROOT / 'RELEASE_SEQUENCE').read_text()), 'url': args.url, 'sha256': digest}, sort_keys=True).encode()
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(args.signing_key).read_text().strip(), validate=True))
    (out / 'release.json').write_bytes(manifest)
    (out / 'release.json.sig').write_bytes(base64.b64encode(key.sign(manifest)))
print(archive_path)
print('SHA256', digest)
