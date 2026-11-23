#!/usr/bin/env bash
# Explicit host opt-in. This helper does not change installer modes 1..10.
set -euo pipefail
fail(){ printf 'nli-node-terminal-setup: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || fail 'run as root on the intended NLI node'
action= role= purge=0
while (($#)); do case $1 in
 --enable|--disable) [[ -z $action ]] || fail 'select one action'; action=$1; shift;;
 --role) role=${2:-}; shift 2;;
 --purge) purge=1; shift;;
 --help|-h) printf '%s\n' 'Usage: nli-node-terminal-setup --enable --role controller|client' '       nli-node-terminal-setup --disable [--purge]' 'Operator sessions may manage test input logs. Credentials remain restricted.'; exit 0;;
 *) fail "unknown argument: $1";; esac; done
[[ -n $action ]] || fail 'select --enable or --disable'
for tool in systemctl python3 getent useradd groupadd setfacl visudo; do command -v "$tool" >/dev/null || fail "required host tool unavailable: $tool"; done
if [[ $action == --disable ]]; then
 systemctl disable --now nli-node-terminal.service >/dev/null 2>&1 || true
 rm -f -- /etc/sudoers.d/nli-terminal /etc/systemd/system/nli-controller-agent.service.d/90-node-terminal.conf
 rm -f -- /usr/libexec/nli-terminal/bin/systemctl /usr/libexec/nli-terminal/bin/journalctl /usr/libexec/nli-terminal/bin/sudo
 systemctl daemon-reload
 # ACLs use pinned inode descriptors: never follow a user-created link.
 python3 - <<'PY'
import os,stat,subprocess
roots=['/var/log/nli/input','/var/log/nli/output','/etc/nli/parsers','/var/lib/nli/parsers','/var/lib/nli/parser-assets','/var/lib/nli-controller/parser-assets']
def clear(fd):
 st=os.fstat(fd)
 if stat.S_ISREG(st.st_mode) and st.st_nlink!=1:return
 subprocess.run(['/usr/bin/setfacl','-x','u:nli-terminal','--','/proc/self/fd/'+str(fd)],pass_fds=(fd,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 if stat.S_ISDIR(st.st_mode):
  subprocess.run(['/usr/bin/setfacl','-x','d:u:nli-terminal','--','/proc/self/fd/'+str(fd)],pass_fds=(fd,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for name in os.listdir(fd):
   try:child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
   except OSError:continue
   try:clear(child)
   finally:os.close(child)
def openroot(path):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in path.strip('/').split('/'):
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  return fd
 except:os.close(fd);raise
for root in roots:
 try:fd=openroot(root)
 except OSError:continue
 try:clear(fd)
 finally:os.close(fd)
for parent in ['/var/log/nli','/var/lib/nli','/var/lib/nli-controller','/etc/nli']:
 try:fd=openroot(parent)
 except OSError:continue
 try:subprocess.run(['/usr/bin/setfacl','-x','u:nli-terminal','--','/proc/self/fd/'+str(fd)],pass_fds=(fd,),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 finally:os.close(fd)
PY
 if [[ $purge == 1 ]]; then
  rm -f -- /etc/nli/node-terminal.json
  # Only this fixed dedicated account/home are removed, never customer log paths.
  if getent passwd nli-terminal >/dev/null; then userdel nli-terminal; fi
  [[ ! -L /var/lib/nli-terminal ]] || fail 'refusing symlink terminal home'
  rm -rf -- /var/lib/nli-terminal
 fi
 printf '%s\n' 'Terminal disabled. NLI input logs and parser data were preserved.'
 exit 0
fi
[[ $role == controller || $role == client ]] || fail '--role must be controller or client'
[[ $purge == 0 ]] || fail '--purge applies only to --disable'
[[ -x /usr/bin/nli-node-terminal ]] || fail 'install the R10 node RPM first'
getent passwd nli >/dev/null || fail 'NLI service account is unavailable'
getent group nli-terminal >/dev/null || groupadd -r nli-terminal
getent group nli-terminal-api >/dev/null || groupadd -r nli-terminal-api
if ! getent passwd nli-terminal >/dev/null; then useradd -r -g nli-terminal -d /var/lib/nli-terminal -s /sbin/nologin nli-terminal; fi
[[ $(id -u nli-terminal) != 0 ]] || fail 'terminal account cannot be root'
[[ $(id -Gn nli-terminal) == nli-terminal ]] || fail 'terminal account must have only its dedicated group'
[[ -z $(getent group nli-terminal-api | cut -d: -f4) ]] || fail 'API socket group must not contain global account memberships'
for path in /etc/nli /var/lib/nli-terminal /usr/libexec/nli-terminal /usr/libexec/nli-terminal/bin; do [[ ! -L $path ]] || fail "refusing symlink: $path"; done
install -d -o root -g root -m 0755 /usr/libexec/nli-terminal/bin
install -d -o nli-terminal -g nli-terminal -m 0700 /var/lib/nli-terminal
for name in systemctl journalctl sudo; do ln -sfn /usr/bin/nli-node-terminal "/usr/libexec/nli-terminal/bin/$name"; done
# Backend validates argv again as root and forces --no-pager; never generic sudo.
tmp=$(mktemp /etc/sudoers.d/.nli-terminal.XXXXXX)
trap 'rm -f -- "${tmp:-}"' EXIT
cat >"$tmp" <<'SUDO'
Defaults:nli-terminal env_reset
Defaults:nli-terminal !setenv
Defaults:nli-terminal secure_path="/usr/libexec/nli-terminal/bin:/usr/sbin:/usr/bin:/sbin:/bin"
nli-terminal ALL=(root) NOPASSWD: /usr/bin/nli-node-terminal --systemctl *, /usr/bin/nli-node-terminal --journal *
SUDO
chmod 0440 "$tmp"
visudo -cf "$tmp" >/dev/null || fail 'sudo policy did not validate'
mv -f -- "$tmp" /etc/sudoers.d/nli-terminal
# No project, cloud secret, node token or user password is stored in this policy.
python3 - <<'PY'
import os,json,stat,subprocess,tempfile,pwd,grp
path='/etc/nli/node-terminal.json'
if os.path.lexists(path) and (os.path.islink(path) or not stat.S_ISREG(os.lstat(path).st_mode)):raise SystemExit('refusing non-regular terminal policy')
cfg=dict(enabled=True,privilege_mode='operator',allow_input_write=True,max_sessions=4,idle_timeout_seconds=300,lifetime_seconds=1800,max_output_bytes=262144,output_bytes_per_second=131072)
fd,tmp=tempfile.mkstemp(prefix='.node-terminal.',dir='/etc/nli')
with os.fdopen(fd,'w') as f:json.dump(cfg,f);f.write('\n');f.flush();os.fsync(f.fileno())
os.chmod(tmp,0o600);os.chown(tmp,0,0);os.replace(tmp,path)
# Pin each path component and inode. Skip symlinks/hardlinks/special files.
def openroot(path):
 fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
 try:
  for part in path.strip('/').split('/'):
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  return fd
 except:os.close(fd);raise
def acl(fd,spec):
 subprocess.run(['/usr/bin/setfacl','-m',spec,'--','/proc/self/fd/'+str(fd)],pass_fds=(fd,),check=True)
def walk(fd,write=False):
 st=os.fstat(fd)
 if stat.S_ISREG(st.st_mode):
  if st.st_nlink==1:acl(fd,'u:nli-terminal:rw-' if write else 'u:nli-terminal:r--')
  return
 if not stat.S_ISDIR(st.st_mode):return
 acl(fd,'u:nli-terminal:rwx,d:u:nli-terminal:rwx,d:u:nli:r-x' if write else 'u:nli-terminal:r-x,d:u:nli-terminal:r-x')
 for name in os.listdir(fd):
  try:child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
  except OSError:continue
  try:walk(child,write)
  finally:os.close(child)
# A controller-only RPM may have no parsing input/output directories yet.
# Create only the fixed demo directories, without following links or changing
# ownership/mode of an existing deployment's directories.
base=openroot('/var/log')
try:
 for name in ['nli']:
  try:os.mkdir(name,0o750,dir_fd=base);created=True
  except FileExistsError:created=False
  fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=base)
  if created:os.fchown(fd,pwd.getpwnam('nli').pw_uid,grp.getgrnam('nli').gr_gid)
 try:
  for name in ['input','output']:
   try:os.mkdir(name,0o750,dir_fd=fd);created=True
   except FileExistsError:created=False
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
   try:
    if created:os.fchown(child,pwd.getpwnam('nli').pw_uid,grp.getgrnam('nli').gr_gid)
   finally:os.close(child)
 finally:os.close(fd)
finally:os.close(base)
for path in ['/var/log/nli','/var/lib/nli','/var/lib/nli-controller','/etc/nli']:
 try:fd=openroot(path)
 except FileNotFoundError:continue
 try:acl(fd,'u:nli-terminal:--x')
 finally:os.close(fd)
for path in ['/var/log/nli/input','/var/log/nli/output','/etc/nli/parsers','/var/lib/nli/parsers','/var/lib/nli/parser-assets','/var/lib/nli-controller/parser-assets']:
 try:fd=openroot(path)
 except FileNotFoundError:continue
 try:walk(fd,path.endswith('/input'))
 finally:os.close(fd)
PY
if [[ $role == controller ]]; then
 install -d -o root -g root -m 0755 /etc/systemd/system/nli-controller-agent.service.d
 printf '[Service]\nSupplementaryGroups=nli-terminal-api\n' >/etc/systemd/system/nli-controller-agent.service.d/90-node-terminal.conf
 chmod 0644 /etc/systemd/system/nli-controller-agent.service.d/90-node-terminal.conf
fi
systemctl daemon-reload
systemctl enable --now nli-node-terminal.service
if [[ $role == controller ]]; then systemctl try-restart nli-controller-agent.service; else systemctl try-restart nli-client-control.service; fi
printf '%s\n' 'PASS: operator terminal enabled. Sign in as an administrator, open Command Center > Node Terminal, select this node and connect using your current NLI password.' 'Input log writes/deletes are immediate. Output and parser files are read-only. No unrestricted sudo is granted.'
