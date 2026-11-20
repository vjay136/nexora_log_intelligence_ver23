#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'uninstall-cloudflare-tunnel-v23: run with sudo/root' >&2; exit 1; }
purge=0
case ${1:-} in
  --purge) purge=1; shift ;;
  -h|--help) echo 'Usage: uninstall-cloudflare-tunnel-v23.sh [--purge]; default preserves token/config for recovery'; exit 0 ;;
esac
[[ $# == 0 ]] || { echo 'unexpected option' >&2; exit 1; }
unit=/etc/systemd/system/cloudflared.service
marker=/etc/cloudflared/nli-controller-owned
if [[ -f $unit ]] && ! grep -Fxq 'Description=Cloudflare Tunnel for NLI controller' "$unit"; then
  echo 'uninstall-cloudflare-tunnel-v23: unrelated connector preserved'
  exit 0
fi
if [[ ! -f $unit && ! -f $marker ]]; then
  echo 'uninstall-cloudflare-tunnel-v23: no NLI-owned named tunnel'
  exit 0
fi
systemctl disable --now cloudflared.service 2>/dev/null || true
install -d -m 0750 /etc/cloudflared
printf 'NLI controller named tunnel\n' >"$marker"
rm -f -- "$unit"
if [[ $purge == 1 ]]; then
  rm -f -- /etc/cloudflared/tunnel-token /etc/cloudflared/deployment.conf "$marker"
  rmdir /etc/cloudflared /var/lib/cloudflared 2>/dev/null || true
fi
systemctl daemon-reload
systemctl reset-failed cloudflared.service 2>/dev/null || true
echo 'uninstall-cloudflare-tunnel-v23: NLI connector removed; unrelated files, shared RPM and Cloudflare dashboard data preserved'
