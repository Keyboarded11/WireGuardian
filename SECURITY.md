# Security

## Access model

The dashboard is served over HTTPS through nginx and restricted to the configured administration and VPN networks. The application listens on loopback and runs as `wireguardian-svc`, without sudo or access to the server's WireGuard private key.

A separate privileged service manages WireGuard and firewall changes. It accepts structured requests over a local Unix socket and verifies the caller's UID. It does not accept arbitrary shell commands or WireGuard hook scripts.

The firewall drops unauthorized incoming traffic and forwarding by default. VPN clients are isolated from one another. Full-tunnel profiles support IPv4; IPv6 traffic inside the tunnel is blocked.

## Accounts and secrets

Passwords are hashed with Argon2. Sessions use secure, HTTP-only cookies, and forms are protected against CSRF. Optional TOTP authentication includes replay protection and throttling.

An administrator can change VPN access, run updates and download encrypted backups. Protect administrator accounts accordingly. Root access provides full control of the installation.

TOTP secrets are stored in the application database and protected by filesystem permissions. The local audit log is not tamper-proof. Use external logging if independent audit records are required.

Backups contain sensitive data even though they are encrypted. Store them off the server and keep their passphrase separately. Client private keys are displayed during provisioning and are not retained by the server.

## Updates

Debian updates use the configured APT repositories. Application updates require a trusted Ed25519 publisher key and a signed manifest. Keep the publisher's private key outside the repository and off VPN servers.

## Operational notes

Keep console access available before changing network settings. Test backup restoration and application updates on a separate installation before using them on a production server. An interrupted system operation may require manual recovery.

The local HTTPS certificate expires after one year and requires renewal. Native IPv6 forwarding and automatic router configuration are not supported.

## Reporting a vulnerability

Report vulnerabilities privately to the repository maintainer. Do not include private keys, client profiles, database files or backups in public issues. Include the affected version, reproduction steps and the impact without exposing credentials.
