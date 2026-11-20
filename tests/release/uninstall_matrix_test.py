#!/usr/bin/env python3
"""Execute role uninstallers with real temporary files and fake package/system services."""
import json,os,pathlib,re,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
assert os.name!='nt','run in Linux container; fixture never touches host paths'
count=0
for mode in range(1,11):
 for role in ['controller','client']:
  for purge in [False,True]:
   for other in [False,True]:
    with tempfile.TemporaryDirectory() as tmp:
     tree=pathlib.Path(tmp)/'root';bin=pathlib.Path(tmp)/'bin';bin.mkdir();log=pathlib.Path(tmp)/'commands';packages=pathlib.Path(tmp)/'packages';packages.write_text('\n'.join(['nli-controller-agent' if role=='controller' else 'nli-client']+(['nli-client' if role=='controller' else 'nli-controller-agent'] if other else [])))
     def put(name,value='owned'):
      p=tree/name.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value);return p
     def has(name):return (tree/name.lstrip('/')).exists()
     for name in ['etc/nli/controller.json','etc/nli/controller.env','etc/nli/controller.json.rpmsave','etc/nli/controller.env.rpmnew','etc/nli/controller-bootstrap.env.rpmsave','etc/nli/nli.json','etc/nli/nli.json.backup','etc/nli/client-control.json','etc/nli/client-control.env.rpmsave','etc/nli/controller-ca.crt.rpmnew','etc/nli/bootstrap.env.rpmsave','etc/nli/geoip.env.rpmsave','etc/nli/cloudflare/tunnel-token','var/lib/nli-controller/users.json','var/lib/nli/spool/item','var/lib/nli-control-client/node.token','var/lib/nli-geoip/state.json','var/lib/nli-tunnel/state','var/www/nli-acme/file','var/log/nli/output.json','root/nli-controller-credentials.env','root/nli-client-bootstrap.env','etc/systemd/system/nli-cloudflared.service','etc/systemd/system/nli-cloudflared-quick.service','etc/systemd/system/nli-certbot-renew.timer','etc/nginx/conf.d/nli-controller.conf','etc/httpd/conf.d/nli-controller.conf','etc/nginx/conf.d/operator.conf','etc/operator/server.key','var/operator/raw.log','etc/cloudflared/operator-config.yml']:
      put(name)
     put('etc/nli/controller-edge.json',json.dumps({'mode':mode,'selinux_proxy_boolean_changed':False}))
     put('etc/systemd/system/cloudflared.service','Description=Cloudflare Tunnel for NLI controller\n');put('etc/cloudflared/tunnel-token');put('etc/cloudflared/deployment.conf')
     for name,script in {'systemctl':'if [[ $1 == is-active ]]; then exit 1; fi\nexit 0','rpm':'grep -Fxq "$2" "$PACKAGES"','dnf':'sed -i "/^${3}$/d" "$PACKAGES"','nginx':'exit 0','httpd':'exit 0'}.items():
      p=bin/name;p.write_text('#!/usr/bin/env bash\nprintf "%s %s\\n" "'+name+'" "$*" >>"$COMMANDS"\n'+script+'\n');p.chmod(0o755)
     source=(root/f'scripts/uninstall-{role}-ver23.sh').read_text()
     # Rewrite only filesystem roots into the disposable tree; assertions verify boundaries.
     source=re.sub(r'/(?:etc|var|root)/',lambda match:str(tree)+match.group(),source)
     target=pathlib.Path(tmp)/'uninstall.sh';target.write_text(source)
     env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],PACKAGES=str(packages),COMMANDS=str(log))
     result=subprocess.run(['bash',str(target),'--yes']+(['--purge'] if purge else []),env=env,capture_output=True,text=True)
     assert result.returncode==0,(mode,role,purge,other,result.stderr)
     commands=log.read_text()
     if role=='client':
      assert 'nli-geoip-update' not in commands and 'nli-controller-agent.service' not in commands
     else:
      assert 'nli-geoip-update.timer' in commands and 'nli-geoip-update.service' in commands
      assert 'nli-client-control.service' not in commands and 'nli-agent.service' not in commands

     assert has('etc/operator/server.key') and has('var/operator/raw.log') and has('etc/nginx/conf.d/operator.conf') and has('etc/cloudflared/operator-config.yml')
     if role=='controller':
      assert has('etc/nli/controller.env')== (not purge)
      assert has('var/lib/nli-controller/users.json')==(not purge)
      assert has('etc/nli/nli.json')
      assert not has('etc/systemd/system/nli-cloudflared.service')
      assert has('etc/nli/cloudflare/tunnel-token')==(not purge)
      assert has('etc/cloudflared/tunnel-token')==(not purge)
      assert has('var/lib/nli-tunnel/state')==(not purge)
      assert has('etc/nli/geoip.env.rpmsave')==(not purge)
     else:
      assert has('etc/nli/nli.json')==(not purge)
      assert has('etc/nli/nli.json.backup')==(not purge)
      assert has('var/lib/nli/spool/item')==(not purge)
      assert has('var/lib/nli-controller/users.json')
     assert has('var/lib/nli-geoip/state.json')==((not purge) or other)
     count+=1
# Refusal must precede every stop/remove command, including client purge.
for role in ['controller','client']:
 s=(root/f'scripts/uninstall-{role}-ver23.sh').read_text()
 assert s.index('Type PURGE-')<s.index('systemctl disable --now')
print(f'Uninstall matrix: PASS ({count} complete shell executions, ten modes, preserve/purge, shared-role guards)')

# Raw rpm erasure executes the actual spec postun script with disposable roots.
for owned in [False,True]:
 with tempfile.TemporaryDirectory() as tmp:
  tree=pathlib.Path(tmp)/'root';bin=pathlib.Path(tmp)/'bin';bin.mkdir()
  def put(name,value='preserve'):
   path=tree/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.write_text(value);return path
  for name in ['etc/nli/controller.env','var/lib/nli-controller/users.json','etc/nli/cloudflare/tunnel-token','etc/nginx/conf.d/nli-controller.conf','etc/httpd/conf.d/nli-controller.conf','etc/systemd/system/nli-cloudflared.service','etc/cloudflared/tunnel-token','etc/cloudflared/operator.conf']:put(name)
  unit=put('etc/systemd/system/cloudflared.service','Description=Cloudflare Tunnel for '+('NLI controller' if owned else 'another application')+'\n')
  commandlog=pathlib.Path(tmp)/'service-commands'
  for name in ['systemctl','nginx','httpd']:
   path=bin/name;path.write_text('#!/bin/sh\n'+'printf \"%s %s\\n\" \"'+name+'\" \"$*\" >>\"$COMMANDS\"\n'+('if [ \"$1\" = is-active ]; then exit 1; fi\n' if name=='systemctl' else '')+'exit 0\n');path.chmod(0o755)

  spec=(root/'packaging/rpm/nli-controller-agent.spec').read_text();script=spec.split('%postun\n',1)[1].split('\n%files',1)[0]
  script=re.sub(r'/(?:etc|var|root)/',lambda match:str(tree)+match.group(),script)
  p=pathlib.Path(tmp)/'postun';p.write_text(script)
  environment=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],COMMANDS=str(commandlog))
  preun=spec.split('%preun\n',1)[1].split('\n%postun',1)[0]
  pre=pathlib.Path(tmp)/'preun';pre.write_text(preun)
  subprocess.run(['bash',str(pre),'0'],env=environment,check=True)
  subprocess.run(['bash',str(p),'0'],env=environment,check=True)
  commands=commandlog.read_text()
  assert 'nli-geoip-update.timer' in commands and 'nli-geoip-update.service' in commands
  assert 'nli-client-control.service' not in commands and 'nli-agent.service' not in commands

  assert (tree/'etc/nli/controller.env').exists() and (tree/'var/lib/nli-controller/users.json').exists()
  assert not (tree/'etc/systemd/system/nli-cloudflared.service').exists()
  assert not (tree/'etc/nginx/conf.d/nli-controller.conf').exists()
  assert (tree/'etc/cloudflared/tunnel-token').exists() and (tree/'etc/cloudflared/operator.conf').exists()
  assert unit.exists()==(not owned)
print('Raw RPM preservation and owned/unrelated connector cleanup: PASS')

# GeoIP candidate updater is controller-only; the client consumes preserved DBs.
client_spec=(root/'packaging/rpm/nli-client.spec').read_text()
assert '/usr/lib/systemd/system/nli-geoip-update' not in client_spec
assert '/usr/lib/systemd/system/nli-geoip-update.service' in spec
assert '/usr/lib/systemd/system/nli-geoip-update.timer' in spec
print('Controller-only GeoIP unit ownership and shared-role service protection: PASS')
