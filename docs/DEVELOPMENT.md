# Développement

Python 3.11 ou ultérieur. Dépendances verrouillées :

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
export KEYBOARDED_DEV=1
python manage.py migrate
python manage.py createsuperuser
python manage.py collectstatic --noinput
python manage.py runserver 127.0.0.1:8000
```

Sous PowerShell, utiliser `.venv/Scripts/python.exe` et `$env:KEYBOARDED_DEV='1'`.

Le mode de développement n’utilise que des réseaux de laboratoire pour l’affichage. Il n’installe aucun tunnel et désactive les cookies Secure/redirect HTTPS : ne jamais l’activer en production. En production, la politique réseau et les hôtes HTTP viennent obligatoirement de l’installation.

## Tests

```sh
KEYBOARDED_DEV=1 python manage.py test tests --noinput
python deploy/compile_translations.py
python deploy/package_release.py
```

Les tests unitaires ne lancent pas APT, ne modifient pas le pare-feu et ne valident pas un vrai démarrage Debian. La recette système est dans `SECURITY.md`.

## Traductions

`locale/catalog.json` et `locale/installer.json` : source française, valeurs dans l’ordre anglais, allemand, espagnol, italien. Compiler avec `python deploy/compile_translations.py`. Les catalogues `.po` et `.mo` sont inclus pour que le questionnaire fonctionne avant installation des dépendances Python.

## Architecture

- `install.sh` : bootstrap Debian et validation des options.
- `deploy/install.py` : questionnaire, précontrôles et installation.
- `deploy/core.py` : validation des réseaux et génération de la politique WireGuard/nftables.
- `deploy/agent.py` : agent privilégié, socket Unix et UID du compte de service.
- `panel/` et `templates/` : dashboard Django.
- `deploy/maintenance.py` : maintenance et publications signées.

Conserver les secrets hors dépôt, utiliser des adresses de documentation pour les exemples et ne jamais introduire de compte administrateur de démonstration dans une release. L’archive est construite depuis une liste blanche de chemins ; ajouter explicitement chaque nouveau composant nécessaire.
