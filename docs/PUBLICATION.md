# Publication et versions signées

## Dépôt public

Dépôt : `https://github.com/Keyboarded11/WireGuardian`.

Publier uniquement les fichiers de l’archive produite par `python deploy/package_release.py`, ou les fichiers suivis dans le dépôt public nettoyé. Ne jamais importer le dossier de travail entier : `artifacts`, `.venv`, les bases, sauvegardes, clés, certificats et l’original du kit ne font pas partie de la distribution.

La CI teste les sources sous Python 3.11 et 3.13 et construit l’archive. Cela ne remplace pas une installation sur Debian vierge. Une release candidate doit être marquée **prerelease**, et le statut de recette indiqué clairement.

## Construire une release

1. Mettre à jour `VERSION`, puis augmenter strictement `RELEASE_SEQUENCE`.
2. Exécuter les tests et la recette dans `SECURITY.md`.
3. Lancer `python deploy/package_release.py`.
4. Publier le ZIP et son `.sha256` dans GitHub Releases, avec le tag `vVERSION`.
5. Ne pas réutiliser le numéro d’une release distribuée avec un contenu différent.

## Activer les mises à jour applicatives

Un dépôt GitHub seul ne suffit pas : les installations font confiance à une **clé Ed25519**. Générer cette clé sur le poste de publication, jamais sur le serveur VPN. Conserver le fichier privé hors du checkout et le sauvegarder dans un coffre. La clé publique peut être publiée.

Exemple avec le Python du projet, depuis un répertoire privé situé hors du dépôt :

```python
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
key = Ed25519PrivateKey.generate()
fd = os.open('release-private.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as stream:
    stream.write(base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())))
Path('release-public.txt').write_bytes(base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)))
```

Depuis le dépôt :

```sh
python deploy/package_release.py \
  --url https://github.com/Keyboarded11/WireGuardian/releases/download/vVERSION/wireguardian-VERSION.zip \
  --signing-key /chemin/prive/release-private.key
```

Remplacer `VERSION` par le numéro exact. Publier ensemble le ZIP, `release.json` et `release.json.sig`. Le programme de mise à jour télécharge la signature à l’URL du manifeste suivie de `.sig`. Utiliser un emplacement stable (par exemple `releases/latest/download/release.json` après publication stable) uniquement lorsque l’éditeur maîtrise son évolution. Les prereleases ne sont pas nécessairement sélectionnées par `latest`.

Communiquer aux utilisateurs l’URL du manifeste et la clé **publique**, à saisir dans le questionnaire. La clé privée ne doit jamais être demandée à un utilisateur final ni envoyée à son serveur. Les anciennes installations sans flux nécessitent une configuration root de `/etc/keyboarded/release.json` contenant `manifest_url` et `public_key` ; garder ce fichier root:root en mode 0600.

Ne pas publier une migration incompatible avec les chemins, comptes de service ou formats de sauvegarde existants sans procédure explicite. Les noms de services historiques sont conservés dans cette version pour cette raison.

## Avant une version stable

Tester au minimum : installation Debian vierge, redémarrage, restrictions réseau externes, tunnel réel, sauvegarde/restauration et mise à jour signée avec échec et retour arrière. Archiver des résultats expurgés de toute donnée personnelle. Le README doit distinguer ce qui a été vérifié de ce qui reste à faire.
