# Sécurité et statut de validation

WireGuardian est une candidate 0.3.0, pas une solution auditée ni une garantie d’inviolabilité. Ne pas présenter une réussite des tests Python ou une capture d’écran comme une validation Debian/antiX, réseau, redémarrage ou restauration.

## Frontières de confiance

- nginx termine HTTPS et limite les sources aux réseaux d’administration/VPN. Le port applicatif écoute seulement sur loopback.
- Django tourne sous `wireguardian-svc`, sans sudo et sans accès à la clé privée WireGuard du serveur. Sessions côté serveur, Argon2, CSRF, échappement HTML, CSP sans scripts tiers, cookies Secure/HttpOnly/SameSite en production.
- Les comptes peuvent rester protégés par mot de passe uniquement ; la 2FA est un choix explicite. Son activation invalide les anciennes sessions. Les codes TOTP sont temporisés, non rejouables, avec limitation des échecs.
- L’agent root est joint uniquement par socket Unix avec contrôle des UID, permissions et messages structurés bornés. Il ne reçoit ni commandes shell libres, ni chemins arbitraires, ni scripts WireGuard PostUp/PostDown.
- Un administrateur web peut modifier les accès VPN, démarrer les mises à jour et télécharger une sauvegarde chiffrée. Une compromission du compte administrateur reste donc grave. Le compte root conserve tout pouvoir ; les secrets TOTP sont dans la base protégée par les permissions du système, non chiffrés indépendamment sur disque.
- nftables filtre les transferts et isole les clients entre eux. Le mode complet transmet IPv4 ; IPv6 est bloqué dans le tunnel. Ce produit ne gère pas encore le routage IPv6 natif.
- Le journal local est une piste d’activité, pas un stockage inviolable. Une compromission de l’application peut altérer sa base. Prévoir une collecte externe si une traçabilité indépendante est requise.
- Le mot de passe de sauvegarde circule uniquement par HTTPS et localement au worker ; il n’est ni journalisé ni stocké. La sauvegarde contient des secrets et doit rester privée, même chiffrée.
- Les mises à jour applicatives font confiance à la clé Ed25519 configurée par root. Garder la clé privée d’éditeur hors GitHub et hors serveur. Une publication signée peut exécuter des migrations : elle équivaut à faire confiance à son éditeur.

## Recette obligatoire avant publication stable

1. Installer depuis une Debian 12 neuve puis une Debian 13 neuve avec systemd. antiX n’est pas accepté par cet installateur.
2. Vérifier HTTPS depuis les sources autorisées et le refus depuis les autres ; scanner TCP/UDP depuis un hôte externe. Préserver une console Proxmox indépendante.
3. Redémarrer la VM : vérifier le chargement nftables, les services, l’adresse VPN, HTTPS et la persistance des pairs.
4. Tester un client réel en fractionné : LAN joignable, adresse IP publique du client inchangée, DNS direct. Tester un client complet : IP publique du serveur, DNS configuré, absence de sortie IPv6 directe.
5. Vérifier changement de mode + réimport des routes, suspension, suppression et révocation de connexions déjà établies. Vérifier absence de communication entre clients.
6. Tester 2FA activée/désactivée, rejeu, limitation, sessions anciennes et récupération console.
7. Sauvegarder, télécharger, restaurer sur une VM de recette, vérifier une mauvaise phrase et une archive corrompue. Comparer comptes, clé publique serveur, pairs et accès réels.
8. Publier une version signée de test ; rejeter signature invalide, archive modifiée et séquence ancienne. Tester migration réussie et migration échouée avec retour arrière.
9. Tester mises à jour APT, manque d’espace disque, coupure pendant maintenance et récupération console.

Les scripts d’installation, de migration, de restauration et de mise à jour doivent être exercés avant usage en production. Leur comportement lors d’une extinction brutale n’est pas garanti atomique entre base, fichiers et noyau réseau.

Signaler les vulnérabilités en privé à l’éditeur du dépôt GitHub lorsque celui-ci sera publié. Ne pas ouvrir d’issue publique contenant une clé, un profil WireGuard, une base ou une sauvegarde.
