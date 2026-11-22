# Embedded into the release installers after bundle checksum verification.
# Keep the original runtime files; install matching existing roles atomically.
nli_install_role_set() {
  local role=$1 primary=$2 bundle=$3 other package other_file old_identity target_identity
  local old_evr target_evr primary_release other_release unit
  local -a other_services=() active_services=()
  if [[ $role == client ]]; then
    other=controller; package=nli-controller-agent; other_file="$bundle/nli_controller_agent_ver23.rpm"
    other_services=(nli-controller-agent.service)
  else
    other=client; package=nli-client; other_file="$bundle/nli_client_ver23.rpm"
    other_services=(nli-agent.service nli-client-control.service)
  fi
  if ! rpm -q "$package" >/dev/null 2>&1; then
    dnf -y install "$primary"
    return
  fi
  [[ -f $other_file ]] || fail "the installed $other role needs its matching RPM from the complete release bundle"
  [[ $(rpm -qp --qf '%{NAME}' "$other_file") == "$package" ]] || fail "invalid matching $other RPM"
  [[ $(rpm -qp --qf '%{VERSION}' "$other_file") == "$expected_version" ]] || fail "matching $other RPM has a different version"
  [[ $(rpm -qp --qf '%{ARCH}' "$other_file") == "$expected_arch" ]] || fail "matching $other RPM has a different architecture"
  primary_release=$(rpm -qp --qf '%{RELEASE}' "$primary")
  other_release=$(rpm -qp --qf '%{RELEASE}' "$other_file")
  [[ $primary_release == "$other_release" ]] || fail 'client and controller RPM releases do not match'
  old_identity=$(rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}' "$package")
  target_identity=$(rpm -qp --qf '%{VERSION}-%{RELEASE}.%{ARCH}' "$other_file")
  if [[ $old_identity == "$target_identity" ]]; then
    dnf -y install "$primary"
    return
  fi
  old_evr=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$package")
  target_evr=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$other_file")
  [[ $(rpm -q --qf '%{EPOCHNUM}' "$package") == 0 ]] || fail "the installed $other role has a custom epoch; use an explicitly reviewed matching bundle"
  if [[ $old_evr != "$target_evr" && $(printf '%s\n%s\n' "$old_evr" "$target_evr" | sort -V | tail -n 1) == "$old_evr" ]]; then
    fail "the installed $other role ($old_evr) is newer than this bundle; use a matching newer release"
  fi
  for unit in "${other_services[@]}"; do
    if systemctl is-active --quiet "$unit"; then active_services+=("$unit"); fi
  done
  info "existing $other role $old_identity detected; upgrading the two already-selected roles together to $target_identity"
  dnf -y install "$primary" "$other_file"
  # Only previously active counterpart daemons are restarted. Upgrade RPM
  # scriptlets leave disabled bootstrap services and inactive roles unchanged.
  for unit in "${active_services[@]}"; do
    systemctl try-restart "$unit" || fail "matching role installed but $unit could not restart; inspect its journal"
    systemctl is-active --quiet "$unit" || fail "matching role installed but $unit is not active"
  done
}
