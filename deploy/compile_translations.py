"""Build standard gettext PO/MO catalogs, without requiring GNU gettext on Windows.

Edit locale/catalog.json or locale/installer.json; values are
[English, German, Spanish, Italian].
French source messages stay stable, including stored audit actions.
"""
import ast
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parent.parent
LANGUAGES = ('en', 'de', 'es', 'it')


def source_messages():
    messages = set()
    for path in (ROOT / 'templates').glob('*.html'):
        source = path.read_text(encoding='utf-8')
        for match in re.finditer(r"(?:translate\s+|_\()('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")", source):
            messages.add(ast.literal_eval(match[1]))
    paths = list((ROOT / 'panel').rglob('*.py')) + [ROOT / 'deploy/install.py']
    for path in paths:
        for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ('_', 'N') and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                messages.add(node.args[0].value)
    return messages


def mo_bytes(messages):
    entries = sorted((key.encode('utf-8'), value.encode('utf-8')) for key, value in messages.items())
    count = len(entries)
    start = 28 + 16 * count
    ids = b''.join(key + b'\0' for key, _ in entries)
    translations = b''.join(value + b'\0' for _, value in entries)
    id_table, value_table = [], []
    id_offset, value_offset = start, start + len(ids)
    for key, value in entries:
        id_table.append(struct.pack('<2I', len(key), id_offset))
        value_table.append(struct.pack('<2I', len(value), value_offset))
        id_offset += len(key) + 1
        value_offset += len(value) + 1
    return struct.pack('<7I', 0x950412de, 0, count, 28, 28 + 8 * count, 0, 0) + b''.join(id_table) + b''.join(value_table) + ids + translations


def compile_catalogs():
    catalog = load_catalog()
    missing = source_messages() - catalog.keys()
    if missing:
        raise ValueError('Missing translations: ' + repr(sorted(missing)))
    for key, values in catalog.items():
        if len(values) != 4 or any(not value for value in values):
            raise ValueError('Incomplete translations: ' + key)
    for language in ('fr', *LANGUAGES):
        plural = '(n > 1)' if language == 'fr' else '(n != 1)'
        header = f'Project-Id-Version: WireGuardian\nContent-Type: text/plain; charset=UTF-8\nLanguage: {language}\nPlural-Forms: nplurals=2; plural={plural};\n'
        messages = {'': header, **{key: key if language == 'fr' else values[LANGUAGES.index(language)] for key, values in catalog.items()}}
        directory = ROOT / 'locale' / language / 'LC_MESSAGES'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'django.mo').write_bytes(mo_bytes(messages))
        po = '# Generated from locale/catalog.json.\n' + '\n\n'.join('msgid ' + json.dumps(key, ensure_ascii=False) + '\nmsgstr ' + json.dumps(value, ensure_ascii=False) for key, value in sorted(messages.items())) + '\n'
        (directory / 'django.po').write_text(po, encoding='utf-8')
    print(f'{len(catalog)} messages compiled for 5 languages.')


def load_catalog():
    catalog = {}
    for name in ('catalog.json', 'installer.json'):
        catalog.update(json.loads((ROOT / 'locale' / name).read_text(encoding='utf-8')))
    return catalog


if __name__ == '__main__':
    compile_catalogs()
