# WireGuardian

WireGuardian installs WireGuard and a web dashboard on a Debian server. Use it to manage VPN devices, choose how their traffic is routed, and maintain the server from your local network or VPN.

## Features

- Add, disable and remove VPN devices.
- Choose split tunneling or full tunneling for each device.
- Manage administrator and read-only accounts, with optional two-factor authentication.
- Download encrypted configuration backups and run system updates.
- Use the dashboard in English, French, German, Spanish or Italian.

## Requirements

- A dedicated **Debian 12 or 13** server with systemd.
- Root access and an Internet connection for downloading packages.
- A static IPv4 address or a DHCP reservation.
- A public IPv4 address or DNS name reachable by your VPN clients.
- Access to your router's UDP port forwarding settings, if the server is behind a router.

For a small installation, start with 2 CPU cores, 2 GB of RAM and a 20 GB disk. The installer requires at least 2 GiB of free disk space.

A minimal Debian installation is sufficient. Select **SSH server** and **standard system utilities** during Debian setup; a desktop environment is unnecessary.

Use a dedicated machine or VM. The installer configures the firewall and refuses existing installations, conflicting services and existing firewall rules. Keep console access available and take a snapshot before installation.

## Installation

### Using Git

Open a root shell with `su -` or `sudo -i`, then run:

```sh
apt-get update
apt-get install -y git ca-certificates
git clone https://github.com/Keyboarded11/WireGuardian.git /root/wireguardian
cd /root/wireguardian
sh install.sh --language en
```

The installer downloads the dependencies and starts the setup wizard. WireGuard, the dashboard, nginx, HTTPS and firewall rules are configured together.

### Without Git

Download the ZIP and its `.sha256` file from [Releases](https://github.com/Keyboarded11/WireGuardian/releases). Upload both files to the server using SCP or SFTP.

From a root shell, open the directory containing the files and run:

```sh
apt-get update
apt-get install -y unzip ca-certificates
sha256sum -c wireguardian-0.3.0.zip.sha256
mkdir /root/wireguardian
unzip wireguardian-0.3.0.zip -d /root/wireguardian
cd /root/wireguardian
sh install.sh --language en
```

Replace the version in the filenames when installing another release. You can also upload an already extracted directory and run `sh install.sh` from that directory.

### Setup wizard

The wizard detects the server's current network settings and asks you to confirm or change them. It does not change Debian's IP configuration: set a static address or DHCP reservation before starting.

| Setting | What to enter |
|---|---|
| Server address | The fixed IPv4 address already assigned to the server. |
| Network interface | The interface used to reach your LAN and the Internet. |
| LAN networks | The networks VPN clients should be able to reach, in CIDR notation, separated by commas. |
| Administration networks | Networks allowed to access HTTPS and SSH. Include your current workstation's network and the server's network. |
| VPN subnet | An unused private IPv4 subnet, between `/22` and `/29`, that does not overlap your existing networks. |
| VPN server address | An available address inside that subnet. The wizard suggests its first usable address. |
| WireGuard port | An available UDP port. The default is `51820`. |
| SSH port | Your current SSH port. The installer checks it but does not change it. |
| Public endpoint | Your public IPv4 address or DNS name, without a protocol or port. |
| DNS server | Optional for split tunneling. Required before creating full-tunnel profiles. |
| Administrator account | Choose a username and a password of at least 14 characters. |
| Security updates | Whether Debian should install security updates automatically. Automatic reboots are disabled. |
| Application updates | A signed release manifest URL and the publisher's public key, if available. Otherwise leave this blank. |

To check the server's network settings:

```sh
ip -br -4 address
ip -4 route
```

Review the summary and type **INSTALLER** to proceed. This confirmation word is the same in every language.

Supported installer languages: `en`, `fr`, `de`, `es` and `it`. Omit `--language en` to choose interactively.

To preview the questionnaire without installing anything, with Python 3.11 or later already installed:

```sh
sh install.sh --questionnaire-only --language en
```

## Open the dashboard

Visit `https://YOUR_SERVER_IP` from an allowed administration network and sign in with the account created during setup.

The installer creates a local HTTPS certificate. Import `/etc/keyboarded/tls.crt` into your administration computer's trusted certificate store, or replace it with a certificate from your own certificate authority. Transfer only the public certificate, never `tls.key`.

You can check its fingerprint from the server console:

```sh
openssl x509 -in /etc/keyboarded/tls.crt -noout -fingerprint -sha256
```

To change a password or configure two-factor authentication, open **Users → Options** for the account.

## Configure your router

Forward the chosen **WireGuard UDP port** to the server's fixed address, using the same port on both sides. Do not forward the dashboard or SSH ports to the Internet.

Port forwarding must be configured on your router. If your provider uses CGNAT, you may need to request a reachable public address. If your public address changes, use a DNS name with a dynamic DNS service.

## Connect your first device

1. Open **Network** and check the public endpoint and LAN networks.
2. Open **Devices**, add a device and choose its routing mode.
3. Download the configuration file immediately. Client private keys are not stored on the server.
4. Apply the changes to the server.
5. Install the [WireGuard client](https://www.wireguard.com/install/) on the device and import the configuration.
6. Connect from an external network, such as mobile data, and check that you can reach a LAN device.

### Routing modes

**Split tunnel:** traffic to the configured LAN networks goes through WireGuard. Other Internet traffic uses the client's own connection.

**Full tunnel:** IPv4 Internet traffic goes through the VPN server. Configure a reachable DNS server before creating a full-tunnel profile. IPv6 traffic is routed into the tunnel and blocked; native IPv6 forwarding is not supported.

After changing a device's routing mode, apply the server configuration and update the client profile as well. WireGuard does not push route changes to clients.

Use a separate profile for each device. If a private key is lost, replace the profile. Avoid overlapping networks between the client's local network and the remote LAN.

## Check startup

With console access available, restart the server and verify that the dashboard and VPN return:

```sh
reboot
```

After reconnecting:

```sh
ip -br address
systemctl is-active keyboarded-agent keyboarded-web nginx nftables
wg show wg0
```

## Backups

Open **Maintenance**, enter and confirm a backup passphrase, then enter your account password to authorize the operation. Create the backup, refresh its status and download the `.kwg` file.

Keep a copy off the server and store the passphrase separately. Each new backup replaces the previous downloadable backup.

Backups include accounts, two-factor authentication settings, VPN devices, configuration and the server's WireGuard key. They do not include client private keys, TLS certificates or the complete Debian system.

To restore a backup on an installation with the same network topology, run as root:

```sh
/opt/keyboarded/.venv/bin/python /opt/keyboarded/deploy/restore.py /path/to/backup.kwg
```

The restore tool asks for the passphrase and confirmation. It saves the previous state and invalidates existing sessions. Test your recovery procedure before relying on a backup.

## Updates

Use **Maintenance** to update Debian packages, including WireGuard. The server is not rebooted automatically.

Application updates require a signed release manifest and a trusted publisher key configured during installation. Without these, application updates are unavailable. Do not rerun the installer over an existing installation.

## Troubleshooting

Run these commands from the server console:

```sh
systemctl status keyboarded-web keyboarded-agent nginx --no-pager
journalctl -u keyboarded-web -u keyboarded-agent -n 60 --no-pager
nginx -t
nft list table inet keyboarded
```

| Problem | Check |
|---|---|
| Dashboard unavailable | Server address, allowed administration network, certificate and service status. HTTP port 80 is not used. |
| WireGuard agent unavailable | The `keyboarded-agent` service and permissions on `/run/keyboarded`. Do not make the socket publicly writable. |
| No handshake | Public endpoint, UDP forwarding, client keys and whether server changes were applied. |
| Connected, but no LAN access | Overlapping networks, client routes and the destination device's firewall. |
| Full tunnel without Internet | DNS settings and routing mode on both server and client. |
| Installation interrupted | Inspect the error and current state from the console. On a fresh VM, restore the initial snapshot before trying again. |
| Existing installation detected | Use Maintenance. The installer does not overwrite or resume a partial installation. |

### Account recovery

From a root shell:

```sh
cd /opt/keyboarded
.venv/bin/python deploy/console.py changepassword ACCOUNT_NAME
.venv/bin/python deploy/console.py reset_2fa ACCOUNT_NAME
```

### Network changes

To change the application's network configuration:

```sh
/opt/keyboarded/.venv/bin/python /opt/keyboarded/deploy/reconfigure.py
```

This tool does not change Debian's IP address or SSH daemon port. Keep console access available during network changes. If the HTTPS certificate is replaced, import the new certificate on administration devices. The initial certificate is valid for one year and must be renewed manually.

## Documentation

- [Security](SECURITY.md)
- [Development](docs/DEVELOPMENT.md)
- [Release publishing](docs/PUBLICATION.md)

## License

[MIT](LICENSE). Copyright Keyboarded. Third-party license notices are included in `static/vendor`.
