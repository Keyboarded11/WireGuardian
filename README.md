# WireGuardian

**WireGuard et sa dashboard, installés ensemble sur un serveur Debian dédié.**

Interface en français, anglais, allemand, espagnol et italien. Gestion des appareils, routage par client, comptes, 2FA facultative, sauvegardes chiffrées et maintenance. Créé par **Keyboarded**, sous licence MIT ; attributions du kit UI conservées.

**Version 0.3.0 — candidate de publication.** Aucun compte, mot de passe, adresse publique ou réseau personnel n’est fourni. Chaque installation génère ses propres clés. La version précédente a été exercée sur Debian 13, y compris après redémarrage et avec un tunnel de test. Le nouvel installateur doit encore passer une installation complète sur une VM vierge avant une publication stable. Voir [SECURITY.md](SECURITY.md).

## 1. Préparer le serveur

Utilisez **Debian 13 minimale** (Debian 12 également accepté), avec systemd, dans une VM ou sur une machine dédiée. Évitez un serveur hébergeant déjà des applications, Docker, un pare-feu complexe ou un VPN. Cette version refuse les autres distributions ; antiX et LXC ne font pas partie de la recette supportée.

Point de départ conseillé pour quelques appareils : 2 vCPU, 2 Go de RAM, disque de 20 Go. Ce n’est pas une garantie de débit. Au moins 2 Gio d’espace libre sont exigés par l’installateur.

Avec l’ISO netinst, sélectionnez **serveur SSH** et **utilitaires usuels du système**, sans environnement de bureau. Créez votre propre utilisateur. Le guide officiel est disponible sur [debian.org](https://www.debian.org/releases/trixie/installmanual).

Avant de continuer :

- Donnez au serveur une **IP fixe ou une réservation DHCP durable**. L’installateur réutilise cette adresse ; il ne change pas la configuration réseau Debian.
- Gardez une **console indépendante de SSH** (console Proxmox, console du fournisseur ou écran local).
- Faites un snapshot ou une sauvegarde du système propre.
- Assurez-vous que Debian accède aux dépôts APT et à PyPI par Internet.
- Relevez votre IP publique ou votre nom DNS. Derrière une box, vérifiez la possibilité de rediriger un port UDP ; un CGNAT peut empêcher les connexions entrantes.

Commandes de lecture utiles :

```sh
ip -br -4 address
ip -4 route
```

L’adresse du serveur, son interface et son réseau local sont détectés et proposés par l’assistant. Vérifiez-les : une détection n’est pas une réservation DHCP.

## 2. Récupérer WireGuardian

Choisissez **une seule** méthode. Utilisez le dépôt et les releases de l’éditeur de confiance ; une somme SHA-256 vérifie une copie, mais ne prouve pas à elle seule l’identité de l’éditeur.

### Option A — Git

Depuis une console root (`su -`, ou `sudo -i` si configuré) :

```sh
apt-get update
apt-get install -y git ca-certificates
git clone https://github.com/Keyboarded11/WireGuardian.git /root/wireguardian-source
cd /root/wireguardian-source
sh install.sh
```

Dépôt prévu : [Keyboarded11/WireGuardian](https://github.com/Keyboarded11/WireGuardian). Pour une installation reproductible, choisissez le tag correspondant à la release examinée plutôt qu’une branche en cours de développement.

### Option B — Archive, sans Git

Téléchargez le ZIP d’une release et son fichier `.sha256`. Transférez-les par SCP/SFTP ou importez-les manuellement sur le serveur. Exemple de commande à adapter, exécutée **depuis votre ordinateur** :

```sh
scp wireguardian-0.3.0.zip wireguardian-0.3.0.zip.sha256 UTILISATEUR@ADRESSE_DU_SERVEUR:~/
```

Les mots en majuscules sont à remplacer par vos valeurs. Puis, dans une console root sur Debian :

```sh
apt-get update
apt-get install -y unzip ca-certificates
cd /chemin/vers/les/fichiers
sha256sum -c wireguardian-0.3.0.zip.sha256
mkdir /root/wireguardian-source
unzip wireguardian-0.3.0.zip -d /root/wireguardian-source
cd /root/wireguardian-source
sh install.sh
```

Vous pouvez aussi transférer directement le dossier décompressé, puis lancer `sh install.sh` dedans. N’utilisez pas `curl ... | sh` : téléchargez et examinez les fichiers avant de les exécuter en root.

## 3. Suivre le questionnaire

Le lanceur installe d’abord Python et les outils réseau minimaux manquants. L’assistant demande ensuite une langue. La partie APT utilise la langue de Debian.

Pour choisir une langue directement :

```sh
sh install.sh --language fr
```

Codes disponibles : `fr`, `en`, `de`, `es`, `it`.

Pour essayer le questionnaire **sans installer ni écrire de configuration**, si Python 3.11 ou ultérieur est déjà présent :

```sh
sh install.sh --questionnaire-only --language fr
```

| Question | Que saisir ? |
|---|---|
| IPv4 fixe du serveur | L’adresse déjà présente sur Debian et réservée à cette machine. |
| Interface de sortie | Le nom indiqué par `ip -br address`, confirmé avec la route par défaut. |
| Réseaux LAN | Les réseaux que les clients pourront joindre, en CIDR, séparés par des virgules. Ne mettez pas une route Internet universelle. |
| Réseaux d’administration | Les réseaux autorisés à ouvrir la dashboard et SSH. Incluez votre poste actuel et le réseau du serveur. Jamais `0.0.0.0/0`. |
| Réseau VPN | Un réseau IPv4 privé inutilisé, avec un préfixe de `/22` à `/29`, distinct des réseaux LAN et des routes existantes. Aucune valeur personnelle n’est proposée. |
| Adresse VPN du serveur | Une adresse utilisable du réseau VPN ; la première est calculée et proposée. |
| Port WireGuard | Un port UDP libre. `51820` est proposé comme valeur conventionnelle, modifiable. |
| Port SSH actuel | Le port effectivement utilisé par SSH, sans le changer. L’assistant le vérifie. |
| Adresse publique | Votre IPv4 publique ou votre nom DNS, sans `https://` ni port. Ce n’est généralement pas l’IP LAN. |
| DNS des profils | Facultatif pour l’installation en mode fractionné. Nécessaire pour créer ensuite des profils en tunnel complet. Il doit être joignable via le VPN. |
| Premier administrateur | Un identifiant choisi par vous. Aucune valeur par défaut. |
| Mot de passe | Au moins 14 caractères, à confirmer ; il n’est ni affiché dans le récapitulatif ni transmis dans les arguments des processus. |
| Correctifs Debian | `y` pour les mises à jour de sécurité automatiques, sans redémarrage automatique ; `n` pour gérer celles-ci manuellement. |
| Releases signées | Laissez vide si l’éditeur n’a pas encore publié un manifeste et sa clé publique. Ne saisissez pas une URL de ZIP à la place du manifeste. |

Confirmez les prérequis, relisez le récapitulatif et saisissez **INSTALLER**. Vous pouvez annuler avec Ctrl+C. Une interruption après le début des opérations ne désinstalle pas automatiquement les paquets ou fichiers déjà créés : voir le dépannage.

L’installation inclut WireGuard, son agent local, la dashboard Python, nginx/HTTPS, nftables, les outils de sauvegarde et les services de démarrage. Les dépendances Python sont verrouillées par version et SHA-256 et installées depuis des roues binaires. Pas de Docker, Node.js ou compilation Rust nécessaires. Si aucune roue compatible n’existe pour votre architecture, l’installation échoue explicitement plutôt que de compiler du code non prévu.

## 4. Ouvrir la dashboard

Depuis un réseau d’administration autorisé, ouvrez :

```text
https://ADRESSE_DU_SERVEUR
```

Un certificat HTTPS propre à l’installation est créé. Il n’est pas reconnu publiquement : récupérez **uniquement le certificat public** `/etc/keyboarded/tls.crt` et importez-le dans le magasin de confiance du poste administrateur, ou remplacez-le par un certificat de votre PKI. Ne copiez jamais `tls.key`. Vérifiez l’empreinte du certificat depuis la console du serveur :

```sh
openssl x509 -in /etc/keyboarded/tls.crt -noout -fingerprint -sha256
```

Connectez-vous avec le compte choisi pendant le questionnaire. Dans **Utilisateurs → Options**, changez votre mot de passe si nécessaire et activez facultativement la 2FA avec votre application d’authentification. Gardez un accès console pour la récupération.

Les chemins historiques `/opt/keyboarded`, `/etc/keyboarded` et les services `keyboarded-*` sont des noms techniques conservés pour compatibilité. **Ils ne créent aucun compte de connexion nommé Keyboarded.** Le seul compte système dédié est `wireguardian-svc`, sans shell de connexion ; les comptes de la dashboard sont indépendants des comptes Debian.

## 5. Configurer la box ou le pare-feu amont

Redirigez **uniquement le port UDP WireGuard choisi** vers l’adresse fixe du serveur, sur le même port. Ne redirigez pas HTTPS, HTTP ni SSH pour ce produit. Si le serveur est directement exposé, configurez également le pare-feu du fournisseur.

Le serveur ne connaît pas vos identifiants de box : **la redirection du routeur n’est pas automatique**. Un DNS dynamique se configure chez votre fournisseur si l’IP publique change. Pour un test depuis Internet, utilisez une connexion extérieure, par exemple un téléphone en données mobiles ; un test depuis le LAN ne prouve pas la redirection entrante.

## 6. Ajouter le premier appareil

1. Dans **Réseau**, vérifiez l’adresse publique, le port et les réseaux autorisés.
2. Dans **Appareils**, ajoutez un appareil et choisissez son mode.
3. Téléchargez immédiatement sa configuration `.conf` : sa clé privée n’est pas conservée par le serveur.
4. Cliquez **Appliquer au serveur**.
5. Installez le client WireGuard sur l’appareil, importez le fichier et activez le tunnel.
6. Vérifiez la date du dernier échange, puis l’accès à une machine du LAN.

**Mode fractionné** : le LAN passe par le VPN, Internet reste sur la connexion du client. **Mode complet** : Internet IPv4 passe par le serveur, IPv6 est envoyé vers le tunnel et bloqué ; le routage IPv6 natif n’est pas pris en charge. Configurez un DNS avant de créer un profil complet.

Un changement de mode nécessite de modifier/réimporter aussi le profil client : WireGuard ne pousse pas les routes. Le serveur ne peut pas empêcher un appareil autonome de désactiver son VPN. Le réseau local du client ne doit pas chevaucher le LAN distant. Les clients VPN sont isolés les uns des autres ; l’accès aux hôtes du LAN est accordé selon les réseaux configurés.

Ne partagez pas un profil entre appareils. En cas de perte de clé privée, supprimez l’ancien appareil, appliquez la suppression et créez un nouveau profil. Documentation du protocole : [guide WireGuard](https://www.wireguard.com/quickstart/).

## 7. Vérifier le démarrage automatique

Avant d’utiliser le service au quotidien, redémarrez une fois depuis une console disponible :

```sh
reboot
```

Puis contrôlez :

```sh
ip -br address
systemctl is-active keyboarded-agent keyboarded-web nginx nftables
wg show wg0
```

Vérifiez à nouveau la dashboard et un client. `wg show` masque la clé privée dans cet affichage ; ne publiez pas des fichiers de configuration ou des commandes qui révèlent les clés.

## 8. Sauvegarder et restaurer

Dans **Maintenance**, choisissez une phrase de sauvegarde distincte d’au moins 14 caractères, confirmez votre mot de passe de compte pour autoriser l’opération, créez l’archive puis actualisez et téléchargez-la. Conservez l’archive `.kwg` hors serveur et la phrase séparément.

La sauvegarde chiffrée AES-256-GCM/scrypt inclut les comptes, TOTP, pairs, configuration et clé WireGuard serveur. Elle ne remplace pas une sauvegarde de la VM : les certificats HTTPS, la configuration Debian et les clés privées des clients ne sont pas inclus. Une nouvelle sauvegarde remplace la précédente sur le serveur.

Pour restaurer sur un serveur avec une installation et une topologie identiques, en root :

```sh
/opt/keyboarded/.venv/bin/python /opt/keyboarded/deploy/restore.py /chemin/sauvegarde.kwg
```

Le programme demande la phrase et une confirmation, sauvegarde l’état précédent et invalide les sessions. Testez cette procédure sur une VM de recette avant de dépendre de vos sauvegardes. Une topologie différente est refusée.

## 9. Mettre à jour

**Debian/WireGuard** : utilisez Maintenance ou vos outils APT habituels. Les mises à jour automatiques choisies pendant l’installation n’impliquent aucun redémarrage automatique.

**WireGuardian** : Maintenance vérifie les publications signées par la clé Ed25519 de l’éditeur configurée à l’installation. Sans manifeste publié et clé de confiance, cette fonction n’est pas disponible. Une archive ZIP et son hash seuls ne configurent pas ce service. Ne réexécutez pas l’installateur pour mettre à jour une installation existante : il refuse l’écrasement.

La procédure de publication du dépôt et des versions signées est décrite dans [docs/PUBLICATION.md](docs/PUBLICATION.md).

## 10. Dépannage et récupération

Depuis la console root :

```sh
systemctl status keyboarded-web keyboarded-agent nginx --no-pager
journalctl -u keyboarded-web -u keyboarded-agent -n 60 --no-pager
nginx -t
nft list table inet keyboarded
```

| Symptôme | Vérification |
|---|---|
| Dashboard inaccessible | IP fixe, réseau source autorisé, certificat, état nginx et du service web. Le port 80 n’est pas utilisé. |
| Agent indisponible | Service `keyboarded-agent`, permissions `/run/keyboarded` et compte `wireguardian-svc`. Ne rendez pas le socket accessible à tous. |
| Pas de handshake | UDP entrant, adresse publique/DNS, port, configuration appliquée et clé correcte. |
| Handshake mais pas de LAN | Routes des deux côtés, chevauchement de réseaux, pare-feu de l’hôte cible. |
| Tunnel complet sans Internet | DNS configuré/joignable et mode appliqué au serveur comme au client. |
| Installation interrompue | Conservez les messages, inspectez l’état depuis la console. Sur une VM de test neuve, restaurez le snapshot initial avant de recommencer. Ne supprimez pas aveuglément les répertoires protégés. |
| Refus d’installation existante | Utilisez Maintenance ou restaurez le snapshot vierge ; l’installateur ne reprend pas une installation partielle. |

Récupérer un compte :

```sh
cd /opt/keyboarded
.venv/bin/python deploy/console.py changepassword NOM_DU_COMPTE
.venv/bin/python deploy/console.py reset_2fa NOM_DU_COMPTE
```

Pour changer la topologie applicative depuis la console :

```sh
/opt/keyboarded/.venv/bin/python /opt/keyboarded/deploy/reconfigure.py
```

Cet outil ne change pas l’IP Debian ni le port du daemon SSH. Préparez ces changements séparément et conservez une console. Un certificat local recréé doit être réimporté. Le certificat initial expire après un an : son renouvellement est manuel dans cette version.

## Contribuer et limites

Le compte de service n’a pas sudo, la dashboard écoute sur loopback derrière nginx, et le pare-feu bloque par défaut les entrées non autorisées et les transferts hors politique. Une compromission d’un compte administrateur ou de root reste grave. Ce projet n’est pas une garantie de serveur inviolable.

Voir [SECURITY.md](SECURITY.md) pour le périmètre de sécurité et les tests restant à effectuer, et [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) pour travailler sur le code. Aucun secret ou fichier de votre installation ne doit être ajouté dans GitHub.
