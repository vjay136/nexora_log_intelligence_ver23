#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Uninstall the NLI Ver23 client.

Usage:
  sudo bash uninstall-client-ver23.sh [--yes] [--purge]

The default removal preserves client configuration, node identity, spool,
cache, and logs for recovery or reinstall. --purge permanently removes those
local files after a second explicit confirmation. Controller and Supabase data
are never deleted by this script.
EOF
}

fail() { printf 'uninstall-client-ver23: %s\n' "$*" >&2; exit 1; }
info() { printf 'uninstall-client-ver23: %s\n' "$*"; }

assume_yes=0
purge=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) assume_yes=1 ;;
    --purge) purge=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unexpected argument: $1" ;;
  esac
  shift
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || fail 'run as root with sudo'
for command in dnf rpm systemctl; do command -v "$command" >/dev/null || fail "$command is required"; done

if [[ $assume_yes -ne 1 ]]; then
  [[ -t 0 ]] || fail 'interactive confirmation is unavailable; rerun with --yes'
  read -r -p 'Stop services and uninstall nli-client? [y/N]: ' answer
  [[ ${answer,,} == y || ${answer,,} == yes ]] || { info 'cancelled'; exit 0; }
fi

# Confirm the irreversible choice before stopping services or removing packages.
if [[ $purge -eq 1 && $assume_yes -ne 1 ]]; then
  read -r -p 'Type PURGE-CLIENT to delete local identity, spool, cache, configuration, and logs: ' confirmation
  [[ $confirmation == PURGE-CLIENT ]] || fail 'purge confirmation did not match; nothing was uninstalled'
fi

systemctl disable --now nli-client-bootstrap.service nli-client-control.service nli-agent.service >/dev/null 2>&1 || true
if rpm -q nli-client >/dev/null 2>&1; then
  dnf -y remove nli-client
else
  info 'nli-client is not installed'
fi
systemctl daemon-reload
systemctl reset-failed nli-client-bootstrap.service nli-client-control.service nli-agent.service >/dev/null 2>&1 || true

if [[ $purge -eq 1 ]]; then
  rm -f -- /etc/nli/nli.json /etc/nli/nli.json.rpmsave /etc/nli/nli.json.rpmnew
  rm -f -- /etc/nli/nli.env /etc/nli/nli.env.rpmsave /etc/nli/nli.env.rpmnew
  rm -f -- /etc/nli/client-control.json /etc/nli/client-control.json.rpmsave /etc/nli/client-control.json.rpmnew
  rm -f -- /etc/nli/client-control.env /etc/nli/client-control.env.rpmsave /etc/nli/client-control.env.rpmnew
  rm -f -- /etc/nli/nli.json.backup /etc/nli/nli.env.backup
  for generated in /etc/nli/controller-ca.crt /etc/nli/bootstrap.env; do
    rm -f -- "$generated" "$generated.rpmsave" "$generated.rpmnew"
  done
  rm -rf -- /etc/nli/parsers /var/lib/nli /var/lib/nli-control-client
  # A coinstalled controller can still own shared GeoIP/cache/log material.
  if ! rpm -q nli-controller-agent >/dev/null 2>&1; then
    rm -rf -- /var/cache/nli /var/log/nli /var/lib/nli-geoip
    rm -f -- /etc/nli/geoip.env /etc/nli/geoip.env.rpmsave /etc/nli/geoip.env.rpmnew
    rmdir /etc/nli 2>/dev/null || true
  fi
  info 'local client configuration, identity, spool, cache, and logs were purged'
else
  info 'client configuration, identity, spool, cache, and logs were preserved for reinstall/recovery'
fi
info 'PASS: client package is not installed'
