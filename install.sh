#!/bin/sh
# Run a reviewed local checkout/archive; never pipe remote code into a root shell.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
case "${1:-}" in
  --help|-h) printf '%s\n' 'WireGuardian AIO — Debian 12/13' 'Usage: sh install.sh [--language fr|en|de|es|it] [--questionnaire-only]' 'Questionnaire-only requires Python 3.11+ and performs no installation.'; exit 0 ;;
esac
preview=false
language_pending=false
for argument in "$@"; do
  if [ "$language_pending" = true ]; then
    case "$argument" in fr|en|de|es|it) ;; *) echo 'Invalid language.'; exit 1 ;; esac
    language_pending=false
  else
    case "$argument" in
      --questionnaire-only) preview=true ;;
      --language) language_pending=true ;;
      *) echo 'Unknown option. Use --help.'; exit 1 ;;
    esac
  fi
done
[ "$language_pending" = false ] || { echo 'Missing language.'; exit 1; }
if [ "$preview" = true ]; then
  command -v python3 >/dev/null || { echo 'Python 3.11+ required for questionnaire preview.'; exit 1; }
  exec python3 deploy/install.py "$@"
fi
[ "$(id -u)" -eq 0 ] || { echo 'Run as root: su - then sh /path/to/wireguardian/install.sh'; exit 1; }
. /etc/os-release
[ "$ID" = debian ] || { echo 'This release supports Debian 12/13 only.'; exit 1; }
case "$VERSION_ID" in 12|13) ;; *) echo 'Debian 12/13 required.'; exit 1 ;; esac
[ -d /run/systemd/system ] || { echo 'systemd required.'; exit 1; }
[ ! -e /opt/keyboarded ] && [ ! -e /etc/keyboarded ] || { echo 'Existing installation: use Maintenance.'; exit 1; }
echo 'WireGuardian: bootstrap Python and network tools, then interactive configuration.'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 ca-certificates iproute2 openssh-server
exec python3 deploy/install.py "$@"
