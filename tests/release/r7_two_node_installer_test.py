#!/usr/bin/env python3
"""Run the real R7 installers against systemd, including legacy-controller coexistence."""
import argparse,json,pathlib,subprocess,time,uuid

def main():
    p=argparse.ArgumentParser();p.add_argument('--release',type=pathlib.Path,required=True)
    p.add_argument('--legacy',type=pathlib.Path,required=True);p.add_argument('--result',type=pathlib.Path,required=True)
    p.add_argument('--reciprocal-only',action='store_true')
    a=p.parse_args();root=pathlib.Path(__file__).resolve().parents[2]
    suffix=uuid.uuid4().hex[:10];network='nli-r7-net-'+suffix;volume='nli-r7-boot-'+suffix
    controller='nli-r7-controller-'+suffix;client='nli-r7-client-'+suffix;nodes=[]
    def call(args,input=None,ok=True):
        r=subprocess.run(['docker']+args,input=input,text=True,capture_output=True)
        if ok and r.returncode:raise RuntimeError('Docker test failed: '+str(args[:4])+'\n'+r.stdout[-2200:]+'\n'+r.stderr[-2200:])
        return r
    def execute(node,command,env=None,input=None,ok=True):
        args=['exec']+(['-i'] if input is not None else [])
        for key,value in (env or {}).items():args+=['-e',key+'='+value]
        return call(args+[node,'bash','-lc','set -euo pipefail\n'+command],input=input,ok=ok)
    def start(name,hostname):
        args=['run','-d','--name',name,'--hostname',hostname,'--network',network,'--network-alias',hostname,
          '--privileged','--cgroupns=host','--tmpfs','/run','--tmpfs','/run/lock',
          '--mount','type=bind,src='+a.release.resolve().as_posix()+',dst=/artifacts,readonly',
          '--mount','type=bind,src='+a.legacy.resolve().as_posix()+',dst=/legacy,readonly',
          '--mount','type=bind,src='+root.as_posix()+',dst=/src,readonly',
          '--mount','type=volume,src='+volume+',dst=/bootstrap','nli-rocky-test:rocky9']
        call(args);nodes.append(name)
        for _ in range(60):
            state=execute(name,'systemctl is-system-running',ok=False).stdout.strip()
            if state in ('running','degraded'):break
            time.sleep(1)
        else:raise RuntimeError('systemd not ready in '+name)
        execute(name,'dnf -y install iproute >/tmp/prerequisites.log 2>&1; mkdir /root/release; tar -xzf /artifacts/nli-v23.0.0-7-x86_64.tar.gz -C /root/release')
    release='/root/release/nli-v23.0.0-7-x86_64'
    try:
        call(['network','create',network]);call(['volume','create',volume])
        if a.reciprocal_only:
            print('Testing the reciprocal legacy-client / new-controller installation',flush=True)
            start(controller,'controller')
            execute(controller,'dnf -y install /legacy/nli_client_ver22.rpm >/tmp/legacy-client.log 2>&1; systemctl disable --now nli-agent.service nli-client-control.service nli-client-bootstrap.service; printf "# preserved legacy client profile\\n" >/etc/nli/bootstrap.env; printf "\\n# preserve-client-env\\n" >>/etc/nli/client-control.env; sha256sum /etc/nli/client-control.env >/root/client-before.sha256; printf preserve >/var/lib/nli/r6-state.marker')
            execute(controller,"umask 077; printf '%s\\n' 'R6-Local-Only-Admin-2026!' >/root/admin-password")
            env={'NLI_SETUP_STORAGE_PROVIDER':'local','NLI_SETUP_QUARANTINE_RAW_RETENTION':'false',
              'NLI_SETUP_MODE':'2','NLI_SETUP_ENDPOINT':'controller','NLI_SETUP_ADMIN_PASSWORD_FILE':'/root/admin-password',
              'NLI_SETUP_TLS_IDENTITIES':'controller.internal.test','NLI_CLIENT_BOOTSTRAP_FILE':'/bootstrap/nli-client-bootstrap.env'}
            execute(controller,'cd '+release+'; bash install-controller-ver23.sh --mode 2',env=env)
            execute(controller,"test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' nli-client)\" = 23.0.0-7.el9; test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' nli-controller-agent)\" = 23.0.0-7.el9; sha256sum -c /root/client-before.sha256; test \"$(cat /var/lib/nli/r6-state.marker)\" = preserve; systemctl is-active --quiet nli-controller-agent.service")
            for unit in ['nli-agent.service','nli-client-control.service','nli-client-bootstrap.service']:
                assert execute(controller,'systemctl is-active --quiet '+unit,ok=False).returncode!=0
                assert execute(controller,'systemctl is-enabled --quiet '+unit,ok=False).returncode!=0
            result={'release':'v23.0.0-7','actual_controller_installer_with_legacy_22_20_client':'passed',
              'disabled_client_counterpart_remains_disabled_and_inactive':True,'client_config_and_state_preserved':True,
              'controller_service':'active','production_nodes_modified':False}
            a.result.write_bytes((json.dumps(result,indent=2)+'\n').encode('utf-8'));print(json.dumps(result,indent=2),flush=True)
            return
        print('Starting isolated controller and client systemd nodes',flush=True)
        start(controller,'controller');start(client,'client')
        execute(controller,"umask 077; printf '%s\\n' 'R6-Local-Only-Admin-2026!' >/root/admin-password")
        env={'NLI_SETUP_STORAGE_PROVIDER':'local','NLI_SETUP_QUARANTINE_RAW_RETENTION':'false',
          'NLI_SETUP_MODE':'2','NLI_SETUP_ENDPOINT':'controller','NLI_SETUP_ADMIN_PASSWORD_FILE':'/root/admin-password',
          'NLI_SETUP_TLS_IDENTITIES':'controller.internal.test','NLI_CLIENT_BOOTSTRAP_FILE':'/bootstrap/nli-client-bootstrap.env'}
        print('Running the actual fresh controller installer',flush=True)
        execute(controller,'cd '+release+'; bash install-controller-ver23.sh --mode 2',env=env)
        assert execute(controller,'rpm -q nli-client',ok=False).returncode!=0,'fresh controller unexpectedly installed client role'
        execute(controller,'systemctl is-active --quiet nli-controller-agent.service; test -s /bootstrap/nli-client-bootstrap.env')
        print('Installing the actual legacy 22.20 controller on the client fixture',flush=True)
        execute(client,'dnf -y install /legacy/nli_controller_agent_ver22.rpm >/tmp/legacy-install.log 2>&1')
        execute(client,'systemctl disable --now nli-controller-agent.service nli-controller-bootstrap.service; printf "# preserved inactive legacy profile\\n" >/etc/nli/controller-bootstrap.env; printf "\\n# R6 preserve-controller-config\\n" >>/etc/nli/controller.env; sha256sum /etc/nli/controller.env >/root/controller-before.sha256; printf preserve >/var/lib/nli-controller/r6-state.marker')
        execute(client,'cp /bootstrap/nli-client-bootstrap.env /root/nli-client-bootstrap.env; chmod 0600 /root/nli-client-bootstrap.env')
        print('Running the exact client installer --bootstrap command with the legacy opposite role present',flush=True)
        execute(client,'cd '+release+'; bash install-client-ver23.sh --bootstrap /root/nli-client-bootstrap.env',input='production\nrocky9\noperations\n')
        execute(client,"test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' nli-client)\" = 23.0.0-7.el9; test \"$(rpm -q --qf '%{VERSION}-%{RELEASE}' nli-controller-agent)\" = 23.0.0-7.el9; sha256sum -c /root/controller-before.sha256; test \"$(cat /var/lib/nli-controller/r6-state.marker)\" = preserve; test ! -e /root/nli-client-bootstrap.env; systemctl is-active --quiet nli-agent.service; systemctl is-active --quiet nli-client-control.service")
        assert execute(client,'systemctl is-active --quiet nli-controller-agent.service',ok=False).returncode!=0
        assert execute(client,'systemctl is-enabled --quiet nli-controller-bootstrap.service',ok=False).returncode!=0
        assert execute(client,'systemctl is-enabled --quiet nli-controller-agent.service',ok=False).returncode!=0
        execute(client,"/usr/bin/nli parse --service smtp --multiline=false - </src/tests/release/smtp_input.txt >/root/parsed.json; python3 -c 'import json; assert json.load(open(\"/root/parsed.json\"))==json.load(open(\"/src/tests/release/smtp_expected.json\"))'")
        version=execute(client,'/usr/bin/nli --version').stdout.strip();assert '23.0.0' in version
        print('Restarting controller and client services and verifying their persisted bundles',flush=True)
        before_controller=execute(controller,'sha256sum /var/lib/nli-controller/parser-assets/bundle.json').stdout.split()[0]
        before_client=execute(client,'sha256sum /var/lib/nli/parser-assets/bundle.json').stdout.split()[0]
        execute(controller,'systemctl restart nli-controller-agent.service; systemctl is-active --quiet nli-controller-agent.service; systemctl is-enabled --quiet nli-controller-agent.service')
        execute(client,'systemctl restart nli-client-control.service nli-agent.service; systemctl is-active --quiet nli-client-control.service nli-agent.service; systemctl is-enabled --quiet nli-client-control.service nli-agent.service')
        assert execute(controller,'sha256sum /var/lib/nli-controller/parser-assets/bundle.json').stdout.split()[0]==before_controller
        assert execute(client,'sha256sum /var/lib/nli/parser-assets/bundle.json').stdout.split()[0]==before_client
        result={'release':'v23.0.0-7','fresh_controller_actual_installer':'passed','fresh_controller_does_not_add_client':True,
          'client_actual_bootstrap_installer_with_legacy_22_20_controller':'passed','both_existing_roles_match_bundle':True,
          'disabled_counterpart_remains_disabled_and_inactive':True,'controller_config_and_state_preserved':True,
          'tls_enrollment_and_initial_heartbeat':'passed','client_parser_and_control_services':'active',
          'original_smtp_parser_sample':'passed','service_restart_and_bundle_preservation':'passed','native_version':version,'production_nodes_modified':False}
        a.result.write_bytes((json.dumps(result,indent=2)+'\n').encode('utf-8'));print(json.dumps(result,indent=2),flush=True)
    finally:
        for name in nodes:call(['rm','-f',name],ok=False)
        call(['volume','rm',volume],ok=False);call(['network','rm',network],ok=False)

if __name__=='__main__':main()
