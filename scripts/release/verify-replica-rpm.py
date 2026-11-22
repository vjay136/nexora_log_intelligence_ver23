#!/usr/bin/env python3
"""Offline RPM identity and baseline install/upgrade preservation check."""
import json, pathlib, subprocess

def run(args,**kwargs):return subprocess.run(args,check=True,**kwargs)
def output(args):return run(args,capture_output=True,text=True).stdout
def names(s):return s.replace('V22_19_1_RELEASE_NOTES','V23_R6_RELEASE_NOTES')
query='[%{FILENAMES}|%{FILEMODES}|%{FILEUSERNAME}|%{FILEGROUPNAME}|%{FILEFLAGS}|%{FILEVERIFYFLAGS}\n]'
for old,new in [('nli_client_ver22.rpm','nli_client_ver23.rpm'),('nli_controller_agent_ver22.rpm','nli_controller_agent_ver23.rpm')]:
    before=output(['rpm','-qp','--qf',query,'/baseline/'+old])
    after=output(['rpm','-qp','--qf',query,'/release/'+new])
    assert sorted(names(before).splitlines())==sorted(after.splitlines()),'permissions/config/ghost flags changed'
    assert output(['rpm','-qpR','/baseline/'+old])==output(['rpm','-qpR','/release/'+new]),'dependency requirements changed'
    before_scripts=output(['rpm','-qp','--scripts','/baseline/'+old])
    role='client' if old.startswith('nli_client') else 'controller'
    bootstrap='nli-'+role+'-bootstrap.service';profile='/etc/nli/bootstrap.env' if role=='client' else '/etc/nli/controller-bootstrap.env'
    enable='systemctl enable '+bootstrap+' >/dev/null 2>&1 || :'
    before_scripts=before_scripts.replace(enable,'if [ "$1" -eq 1 ]; then '+enable+'; fi').replace('if [ -s '+profile+' ]; then systemctl start','if [ "$1" -eq 1 ] && [ -s '+profile+' ]; then systemctl start')
    assert before_scripts==output(['rpm','-qp','--scripts','/release/'+new]),'unexpected RPM scriptlets change'
    assert output(['rpm','-qp','--qf','%{VERSION}-%{RELEASE}\n','/release/'+new]).strip()=='23.0.0-6.el9'
run(['rpm','-Uvh','/baseline/nli_client_ver22.rpm','/baseline/nli_controller_agent_ver22.rpm'])
cfg=pathlib.Path('/etc/nli/controller.env');cfg.write_bytes(cfg.read_bytes()+b'\n# R6 offline preservation marker\n')
expected=cfg.read_bytes();state=pathlib.Path('/var/lib/nli-controller/r4-offline-preservation.marker');state.write_text('preserve')
run(['rpm','-Uvh','/release/nli_client_ver23.rpm','/release/nli_controller_agent_ver23.rpm'])
assert cfg.read_bytes()==expected and state.read_text()=='preserve'
version=output(['/usr/bin/nli','--version']).strip();assert '22.19.1' in version,version
for package in ['nli-client','nli-controller-agent']:
    assert output(['rpm','-q','--qf','%{VERSION}-%{RELEASE}',package])=='23.0.0-6.el9'
run(['rpm','-Uvh','--oldpackage','/baseline/nli_client_ver22.rpm','/baseline/nli_controller_agent_ver22.rpm'])
assert cfg.read_bytes()==expected and state.read_text()=='preserve'
print(json.dumps({'rpm_release_identity':'23.0.0-6.el9','native_version':version,
 'file_attributes_config_and_ghost_flags':'identical','dependencies':'identical','scriptlets':'fresh-install-only bootstrap activation on upgrade; otherwise baseline',
 'baseline_install_r6_upgrade_and_rollback':'passed','configuration_and_state_preserved':True},indent=2))
