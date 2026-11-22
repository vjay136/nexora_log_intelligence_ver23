#!/usr/bin/env python3
"""Exercise packaging transaction selection and failure guards, with no host changes."""
import json,os,pathlib,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]).resolve()
assert os.name!='nt'
cases=[('clean',{'present':False},1,True),('matching',{'installed':'23.0.0-6.el9'},1,True),
 ('legacy-inactive',{},2,True),('legacy-active',{'active':True},2,True),
 ('newer',{'installed':'23.0.0-7.el9'},0,False),('wrong-target',{'version':'23.1.0'},0,False),
 ('custom-epoch',{'epoch':'2'},0,False),('failed-transaction',{'dnf_exit':9,'active':True},2,False)]
with tempfile.TemporaryDirectory() as tmp:
 d=pathlib.Path(tmp);bin=d/'bin';bin.mkdir()
 code=r'''#!/usr/bin/python3
import json,os,pathlib,sys
c=json.loads(os.environ['FIXTURE']);a=sys.argv[1:];name=pathlib.Path(sys.argv[0]).name
with open(os.environ['COMMAND_LOG'],'a') as f:f.write(json.dumps([name]+a)+'\n')
if name=='rpm':
 if a[0]=='-q' and '--qf' not in a:sys.exit(0 if c.get('present',True) else 1)
 fmt=a[a.index('--qf')+1];archive=a[0]=='-qp';evr=('23.0.0-6.el9' if archive else c.get('installed','22.20.1-0.el9'))
 values={'%{NAME}':os.environ['OTHER_PACKAGE'],'%{VERSION}':c.get('version','23.0.0') if archive else evr.split('-')[0],
 '%{ARCH}':'x86_64','%{RELEASE}':evr.split('-',1)[1],'%{EPOCHNUM}':c.get('epoch','0'),
 '%{VERSION}-%{RELEASE}':evr,'%{VERSION}-%{RELEASE}.%{ARCH}':evr+'.x86_64'}
 print(values[fmt],end='')
elif name=='dnf':sys.exit(c.get('dnf_exit',0))
elif name=='systemctl':sys.exit(0 if a[0]=='try-restart' or c.get('active',False) else 3)
'''
 for name in ['rpm','dnf','systemctl']:
  p=bin/name;p.write_bytes(code.encode());p.chmod(0o755)
 (d/'nli_client_ver23.rpm').write_bytes(b'fixture');(d/'nli_controller_agent_ver23.rpm').write_bytes(b'fixture')
 count=0
 for role in ['client','controller']:
  other='nli-controller-agent' if role=='client' else 'nli-client'
  primary=d/('nli_client_ver23.rpm' if role=='client' else 'nli_controller_agent_ver23.rpm')
  for label,cfg,argc,success in cases:
   log=d/'commands.jsonl';log.write_bytes(b'')
   env=dict(os.environ,PATH=str(bin)+':'+os.environ['PATH'],FIXTURE=json.dumps(cfg),COMMAND_LOG=str(log),OTHER_PACKAGE=other,
     HELPER=str(root/'scripts/release/install-role-coherence.sh'),PRIMARY=str(primary),BUNDLE=str(d),ROLE=role)
   shell='set -euo pipefail\nfail(){ echo "$*" >&2; exit 1; }; info(){ :; }; expected_version=23.0.0; expected_arch=x86_64; source "$HELPER"; nli_install_role_set "$ROLE" "$PRIMARY" "$BUNDLE"'
   p=subprocess.run(['bash','-c',shell],env=env,capture_output=True,text=True)
   assert (p.returncode==0)==success,(role,label,p.stdout,p.stderr)
   commands=[json.loads(line) for line in log.read_text().splitlines()]
   installs=[c for c in commands if c[0]=='dnf']
   assert len(installs)==(1 if argc else 0),(role,label,installs)
   if argc:assert len(installs[0][3:])==argc,(role,label,installs)
   restarts=[c for c in commands if c[:2]==['systemctl','try-restart']]
   assert bool(restarts)==(cfg.get('active',False) and success),(role,label,restarts)
   assert not any(c[0]=='systemctl' and c[1] in ['enable','start','stop','disable','mask'] for c in commands)
   count+=1
print(json.dumps({'role_transaction_guard_cases':count,'result':'passed','host_changes':False}))
