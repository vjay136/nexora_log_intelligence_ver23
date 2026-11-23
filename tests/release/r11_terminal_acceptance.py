#!/usr/bin/env python3
"""Exercise real packaged terminals on isolated Docker controller/client fixtures.

No SSH, browser automation, production targets, transcripts or credentials are
stored. Existing r9_live_sync_restore.py separately qualifies rollout/restore.
"""
import argparse
import base64
import json
import hashlib
import re
import shlex
from pathlib import Path
import secrets
import subprocess
import time

WORKER = r'''
import http.cookiejar,json,ssl,sys,urllib.request,urllib.error,pathlib
password=pathlib.Path('/root/admin-password').read_text().strip()
context=ssl.create_default_context(cafile='/var/lib/nli-controller/tls/ca.crt')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),urllib.request.HTTPSHandler(context=context))
csrf=None
for line in sys.stdin:
 try:
  data=json.loads(line); method=data['method']; path=data['path']; body=data.get('body')
  if body is not None and body.pop('_password',False):body['password']=password
  headers={'Accept':'application/json'}
  if csrf and method!='GET':headers['X-CSRF-Token']=csrf
  if body is not None:headers['Content-Type']='application/json'
  req=urllib.request.Request('https://localhost:12382/api/v1'+path,None if body is None else json.dumps(body).encode(),headers,method=method)
  try:
   with opener.open(req,timeout=12) as reply: status=reply.status; result=json.load(reply)
  except urllib.error.HTTPError as exc:status=exc.code;result={}
  if path=='/auth/csrf' and status==200:csrf=result['csrf_token']
  print(json.dumps({'status':status,'body':result}),flush=True)
 except Exception as exc:print(json.dumps({'error':type(exc).__name__}),flush=True)
'''

class Failure(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Failure(message)


def docker(*args, script=None):
    p = subprocess.run(['docker', *args], input=script, text=True, capture_output=True, timeout=90)
    require(p.returncode == 0, 'Docker fixture operation failed: ' + ' '.join(args[:3]))
    return p.stdout


class HTTP:
    def __init__(self, controller):
        self.proc = subprocess.Popen(['docker', 'exec', '-i', controller, 'python3', '-u', '-c', WORKER], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            self.call('POST', '/auth/login', {'username':'admin', '_password':True})
            self.call('GET', '/auth/csrf')
        except Exception:
            self.shutdown()
            raise

    def call(self, method, path, body=None, status=200):
        self.proc.stdin.write(json.dumps({'method':method, 'path':path, 'body':body})+'\n')
        self.proc.stdin.flush()
        line=self.proc.stdout.readline()
        require(bool(line), 'HTTP fixture worker exited')
        reply=json.loads(line)
        require(reply.get('status') == status, f'{method} {path.split("?")[0]} expected HTTP {status}; got '+str(reply.get('status', reply.get('error'))))
        return reply.get('body')

    def shutdown(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=15)


def logical_display(text):
    display=re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return display.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")


class Terminal:
    def __init__(self, http, node):
        self.http=http;self.seq=0;self.cursor=0;self.text=''
        opened=http.call('POST','/terminal/sessions',{'node_id':node,'cols':100,'rows':30,'_password':True,'reason':'Isolated R11 packaged terminal qualification'})
        self.id=opened['session']['id'];self.path='/terminal/sessions/'+self.id
        self.wait(lambda d: d['session']['status']=='running',60)

    def read(self, after=None):
        data=self.http.call('GET',self.path+'?after='+str(self.cursor if after is None else after))
        self.cursor=data['next_sequence'];self.text+=base64.b64decode(data.get('data_b64','')).decode(errors='replace')
        return data

    def wait(self, predicate, timeout=20):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            data=self.read()
            if predicate(data):return data
            require(data['session']['status'] not in ('closed','exited'), 'Terminal unexpectedly closed')
            time.sleep(.25)
        raise Failure('Terminal output deadline exceeded')

    def send(self, data):
        sequence=self.seq+1
        deadline=time.monotonic()+15
        while True:
            # Only explicit not-admitted backpressure is safe to retry. Unknown
            # HTTP/network failures propagate without replaying a command.
            reply=self.http.call('POST',self.path+'/input',{'sequence':sequence,'data':data})
            if reply.get('accepted') is True:
                require(reply.get('acknowledged')==sequence,'Terminal acknowledgement sequence differs')
                self.seq=sequence
                return reply
            require(reply.get('accepted') is False and reply.get('code')=='terminal_input_backpressure' and reply.get('expected_sequence')==sequence,'Terminal input was not explicitly accepted or safely rejected')
            require(time.monotonic()<deadline,'Terminal input backpressure deadline exceeded')
            delay=reply.get('retry_after_ms',150)
            require(isinstance(delay,(int,float)) and 0<delay<=1000,'Invalid backpressure retry interval')
            time.sleep(min(delay/1000,max(0,deadline-time.monotonic())))

    def command(self, command, timeout=20):
        marker='R11_'+secrets.token_hex(8)
        self.text=''
        self.send(command+"; printf '\\n%s\\n' '"+marker+"'\n")
        self.wait(lambda d: '\r\n'+marker+'\r\n' in logical_display(self.text), timeout)
        return logical_display(self.text)

    def close(self):
        self.http.call('POST',self.path+'/close',{})



def journal_follow_running(node, session_id):
    unit='nli-terminal-session-'+hashlib.sha256(session_id.encode()).hexdigest()[:32]+'.scope'
    code="""import json,pathlib,sys
unit=sys.argv[1];found=False
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdecimal():continue
 try:
  if (p/'comm').read_text().strip()=='journalctl' and unit in (p/'cgroup').read_text().split('/')[-1].strip():
   uid=int(next(line for line in (p/'status').read_text().splitlines() if line.startswith('Uid:')).split()[1])
   if uid==0:found=True
 except (OSError,ProcessLookupError):pass
print(json.dumps(found))
"""
    return json.loads(docker('exec',node,'python3','-c',code,unit))


def start_journal_follow(t, node, unit):
    t.send('journalctl -u '+unit+' -f -n 1\n')
    deadline=time.monotonic()+15
    while not journal_follow_running(node,t.id):
        require(time.monotonic()<deadline,'Journal follow never became a live foreground process')
        t.read();time.sleep(.1)


def interrupt_journal_follow(t, node, unit):
    start_journal_follow(t,node,unit)
    # Queue admission is not shell readiness. As with SSH, Ctrl-C can flush
    # typeahead; wait for the newly emitted prompt before typing another command.
    t.text=''
    t.send('\x03')
    t.wait(lambda d:re.search(r'(?:^|\n)nli-terminal@[^\n]*\$ $',logical_display(t.text)) is not None,15)
    require(not journal_follow_running(node,t.id),'Journal follow survived the new shell prompt')
    require('INTERRUPTED' in t.command('printf INTERRUPTED'),'Command after journal Ctrl-C prompt failed')


def runtime_signature(http):
    r=http.call('GET','/parser-sync/runtime')
    b=r['bundle']
    return (b.get('desired_hash'),b.get('controller_applied_hash'),[(c.get('node_id'),c.get('desired_hash'),c.get('applied_hash')) for c in r['clients']])



def output_snapshot(client):
    code = """import json,pathlib
paths=list(pathlib.Path('/var/log/nli/output').glob('*.jsonl'))+[pathlib.Path('/var/log/nli/quarantine.jsonl')]
result={}
for p in paths:
 if p.is_file():
  s=p.stat();result[str(p)]={'inode':s.st_ino,'size':s.st_size}
print(json.dumps(result))
"""
    return json.loads(docker('exec','-i',client,'python3','-',script=code))


def output_delta(client, baseline, desired):
    code = r"""import hashlib,json,pathlib,sys
spec=json.load(sys.stdin);base=spec['baseline'];desired=spec['desired']
paths=list(pathlib.Path('/var/log/nli/output').glob('*.jsonl'))+[pathlib.Path('/var/log/nli/quarantine.jsonl')]
result={'exact':0,'different':0,'quarantined':0,'invalid':0,'partial':False,'bytes':0,'normalised_paths':[]}
for p in paths:
 if not p.is_file():continue
 st=p.stat();prior=base.get(str(p),{});offset=prior.get('size',0) if prior.get('inode')==st.st_ino else 0
 if st.st_size<offset:raise SystemExit('output truncated during proof')
 with p.open('rb') as f:f.seek(offset);data=f.read(1048577)
 if len(data)>1048576:raise SystemExit('output proof bound exceeded')
 result['bytes']+=len(data)
 if data and not data.endswith(b'\n'):result['partial']=True;data=data.rsplit(b'\n',1)[0] if b'\n' in data else b''
 for line in data.splitlines():
  if not line.strip():continue
  if 'quarant' in p.name:result['quarantined']+=1;continue
  try:value=json.loads(line)
  except Exception:result['invalid']+=1;continue
  if value==desired and 'kv_pair' not in value and all(not isinstance(v,(dict,list)) for v in value.values()):result['exact']+=1;result['normalised_paths'].append(str(p))
  else:result['different']+=1
result['desired_sha256']=hashlib.sha256(json.dumps(desired,sort_keys=True,separators=(',',':')).encode()).hexdigest()
print(json.dumps(result))
"""
    return json.loads(docker('exec','-i',client,'python3','-c',code,script=json.dumps({'baseline':baseline,'desired':desired})))


def prove_watched_pipeline(t, client, sample):
    require(isinstance(sample.get('raw'),str) and '\n' not in sample['raw'] and isinstance(sample.get('desired'),dict),'Invalid rollout sample fixture')
    baseline=output_snapshot(client)
    out=t.command("printf '%s\\n' "+shlex.quote(sample['raw'])+" >> /var/log/nli/input/auto.log; printf '\\nWATCHED_APPEND_RC_%s\\n' \"$?\"")
    require('\nWATCHED_APPEND_RC_0\r\n' in out,'Terminal could not append the watched input')
    end=time.monotonic()+60
    while True:
        proof=output_delta(client,baseline,sample['desired'])
        require(proof['different']==0 and proof['quarantined']==0 and proof['invalid']==0 and proof['exact']<=1,'Watched input emitted duplicate, invalid, unexpected or quarantine JSON')
        if proof['exact']==1 and not proof['partial']:break
        require(time.monotonic()<end,'Watched sample did not reach exact normalised output')
        t.read();time.sleep(.5)
    time.sleep(2)
    proof=output_delta(client,baseline,sample['desired'])
    require(proof['exact']==1 and proof['different']==0 and proof['quarantined']==0 and proof['invalid']==0 and not proof['partial'],'Output changed after exact emission')
    path=proof.pop('normalised_paths')[0]
    out=t.command('cat '+shlex.quote(path)+" >/dev/null; printf '\\nOUTPUT_READ_RC_%s\\n' \"$?\"; test ! -w "+shlex.quote(path)+" && printf '\\nOUTPUT_READONLY\\n'")
    require('\nOUTPUT_READ_RC_0\r\n' in out and '\nOUTPUT_READONLY\r\n' in out,'Generated normalised output is unreadable or writable by operator')
    return proof


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--controller',required=True);parser.add_argument('--client',required=True)
    parser.add_argument('--result',type=Path,required=True)
    parser.add_argument('--rollout-proof',type=Path,help='Packaged two-node result containing exact deployed NAPI SMTP fixture')
    a=parser.parse_args();checks=[];sessions=[];workers=[];pipeline_proof=None
    sample=None
    if a.rollout_proof:
        sample=json.loads(a.rollout_proof.read_text())['live_approved_publication_and_restore']['napi_smtp_parse_sample']
    # Refuse production endpoints: only privileged local containers with systemd.
    for node in (a.controller,a.client):
        info=json.loads(docker('inspect',node))[0]
        require(info['HostConfig']['Privileged'] and info['State']['Running'], 'Expected running privileged Docker test fixture')
        require(docker('exec',node,'test','-f','/.dockerenv') == '', 'Expected Docker fixture')
    try:
        h=HTTP(a.controller);workers.append(h)
        before=runtime_signature(h)
        for node in (a.controller,a.client):
            require(docker('exec',node,'bash','-c','if systemctl is-active --quiet nli-node-terminal.service; then exit 1; fi')=='','Host terminal must be disabled before opt-in')
        nodes=h.call('GET','/terminal/nodes')['items']
        require(nodes and all(not n['terminal_enabled'] for n in nodes),'Terminal unexpectedly enabled by default')
        h.call('POST','/terminal/sessions',{'node_id':'@controller','cols':100,'rows':30,'_password':True,'reason':'Disabled-host negative test'},409)
        checks.append('disabled_by_default_and_api_rejected')
        # Host opt-in intentionally restarts the controller, invalidating sessions.
        for node,role in ((a.controller,'controller'),(a.client,'client')):
            docker('exec',node,'/usr/sbin/nli-node-terminal-setup','--enable','--role',role)
        h.shutdown();workers.remove(h)
        end=time.monotonic()+60
        while True:
            try:h=HTTP(a.controller);workers.append(h);break
            except Failure:
                if time.monotonic()>end:raise
                time.sleep(1)
        end=time.monotonic()+75
        while True:
            nodes=h.call('GET','/terminal/nodes')['items']
            host_ready=[n for n in nodes if n.get('host_enabled')]
            for n in host_ready:
                access=n.get('access',{})
                if access.get('state')=='pending_enable':
                    h.call('POST','/terminal/sessions',{'node_id':n['id'],'cols':100,'rows':30,'_password':True,'reason':'Unapproved-host negative test'},409)
                    h.call('POST','/terminal/access',{'node_id':n['id'],'access_epoch':access['access_epoch'],'revision':access['revision'],'action':'approve'})
            enabled=[n for n in nodes if n['terminal_enabled']]
            if len(enabled)==2:break
            require(time.monotonic()<end,'Both fixture terminals did not become available')
            time.sleep(1)
        client=next(n['id'] for n in enabled if n['role']=='client')
        checks.append('explicit_host_optin_both_nodes')
        checks.append('host_enable_waits_for_explicit_webapp_approval')
        other=HTTP(a.controller);workers.append(other)
        for target in ('@controller',client):
            # Separate login avoids the five step-up attempts/minute safety bound.
            owner=HTTP(a.controller);workers.append(owner)
            t=Terminal(owner,target);sessions.append(t)
            other.call('GET',t.path+'?after=0',status=404)
            other.call('POST',t.path+'/input',{'sequence':1,'data':'id\n'},404)
            t.http.call('POST',t.path+'/resize',{'cols':120,'rows':40})
            out=t.command('id -un; stty size; cd /var/log/nli/input; pwd; printf abc | tr a-z A-Z')
            require('nli-terminal' in out and '40 120' in out and 'ABC' in out,'Real shell UID, resize, cd or pipeline failed')
            parser_path='/var/lib/nli-controller/parser-assets/bundle.json' if target=='@controller' else '/var/lib/nli/parser-assets/bundle.json'
            out=t.command('cat '+parser_path+" >/dev/null; printf '\\nPARSER_READ_RC_%s\\n' \"$?\"; test ! -w "+parser_path+" && printf '\\nPARSER_READONLY\\n'")
            require('\nPARSER_READ_RC_0\r\n' in out and '\nPARSER_READONLY\r\n' in out,'Published parser bundle unreadable or writable by operator')
            if target==client and sample:
                pipeline_proof=prove_watched_pipeline(t,a.client,sample)
                checks.append('web_terminal_watched_smtp_exact_flat_normalised_json_once')
            name='r11-terminal-'+secrets.token_hex(6)+'.log'
            out=t.command("printf 'first\\n' >"+name+'; cat '+name)
            require('\r\nfirst\r\n' in out,'Input create/read failed')
            # Exercise the real vi editor, not a script replacing file contents.
            t.send('TERM=xterm vi '+name+'\n');time.sleep(1);t.read()
            t.send('\x1bggccedited-by-vi\x1b:wq\r');time.sleep(1)
            out=t.command('cat '+name+'; rm '+name+'; test ! -e '+name+' && printf DELETED')
            require('edited-by-vi' in out and 'DELETED' in out,'vi save or input delete failed')
            out=t.command("for p in /etc/nli/controller.env /etc/nli/client-control.env /etc/shadow; do if test -e \"$p\"; then if test -r \"$p\"; then printf '\\nRESULT_SECRET_READABLE\\n'; else printf '\\nRESULT_PROTECTED\\n'; fi; fi; done; sudo /bin/sh -c true >/dev/null 2>&1; test $? -ne 0 && printf '\\nRESULT_SUDO_DENIED\\n'")
            require('\nRESULT_SECRET_READABLE\r\n' not in out and '\nRESULT_PROTECTED\r\n' in out and '\nRESULT_SUDO_DENIED\r\n' in out,'Protected credentials or sudo scope failed')
            unit='nli-controller-agent' if target=='@controller' else 'nli-agent'
            out=t.command('sudo systemctl status '+unit+' --no-pager; journalctl -u '+unit+' -n 3 --no-pager; printf \'\\nJOURNAL_RC_%s\\n\' "$?"')
            require('active (running)' in out and '\nJOURNAL_RC_0\r\n' in out,'NLI service/journal helper failed')
            interrupt_journal_follow(t,a.controller if target=='@controller' else a.client,unit)
            if target==client:
                out=t.command('sudo systemctl restart nli-agent; systemctl is-active nli-agent')
                require('\r\nactive\r\n' in out,'Limited service restart failed')
            # Flood without reading. Ring drops old bytes and reports cursor gap.
            t.send("head -c 700000 /dev/zero | tr '\\000' X; printf '\\nFLOOD_DONE\\n'\n")
            time.sleep(7)
            gap=t.read(after=0)
            require(gap['truncated'] and gap['start']>0,'Output flood did not report bounded-buffer gap')
            t.wait(lambda d:'FLOOD_DONE\r\n' in t.text,20)
            host=a.controller if target=='@controller' else a.client
            start_journal_follow(t,host,unit)
            t.close();sessions.remove(t)
            deadline=time.monotonic()+15
            while journal_follow_running(host,t.id):
                require(time.monotonic()<deadline,'Restricted root journal survived session close')
                time.sleep(.1)
            t.http.call('POST',t.path+'/input',{'sequence':t.seq+1,'data':'echo replay\n'},409)
            checks.append(('controller' if target=='@controller' else 'client')+'_shell_files_vi_helpers_owner_isolation_flood_close')
        require(runtime_signature(h)==before,'Terminal operations changed parser bundle hashes')
        checks.append('parser_sync_hashes_unchanged')
        # Open a client shell, restart the broker, prove old session cannot replay.
        fresh=HTTP(a.controller);workers.append(fresh)
        t=Terminal(fresh,client);sessions.append(t)
        start_journal_follow(t,a.client,'nli-agent')
        docker('exec',a.client,'systemctl','restart','nli-node-terminal.service')
        t.wait(lambda d:d['session']['status']=='closed',45)
        require(not journal_follow_running(a.client,t.id),'Restricted root journal survived broker restart')
        t.http.call('POST',t.path+'/input',{'sequence':t.seq+1,'data':'echo forbidden-replay\n'},409)
        sessions.remove(t);checks.append('broker_restart_closes_old_generation_without_replay')
        # A live browser must not keep a shell alive after client-control stops.
        lost=Terminal(fresh,client);sessions.append(lost)
        docker('exec',a.client,'systemctl','stop','nli-client-control.service')
        lost.wait(lambda d:d['session']['status']=='closed',35)
        fresh.call('POST',lost.path+'/input',{'sequence':1,'data':'echo forbidden-old-command\n'},409)
        sessions.remove(lost)
        docker('exec',a.client,'systemctl','start','nli-client-control.service')
        recovered=Terminal(fresh,client);sessions.append(recovered)
        require(recovered.id!=lost.id and 'FRESH_SHELL' in recovered.command('printf FRESH_SHELL'),'Client-control restart did not establish a fresh isolated session')
        recovered.close();sessions.remove(recovered)
        checks.append('client_control_loss_expires_despite_browser_polling_and_requires_fresh_session')
        # The Webapp approval is a separate gate; it changes no NLI service.
        approval_http=HTTP(a.controller);workers.append(approval_http)
        approved_terminal=Terminal(approval_http,client);sessions.append(approved_terminal)
        service_pids=docker('exec',a.client,'systemctl','show','--property=MainPID','nli-agent.service','nli-client-control.service')
        def access_change(action):
            n=next(n for n in approval_http.call('GET','/terminal/nodes')['items'] if n['id']==client)
            v=n['access']
            return approval_http.call('POST','/terminal/access',{'node_id':client,'access_epoch':v['access_epoch'],'revision':v['revision'],'action':action})
        access_change('request_disable')
        require(approved_terminal.read()['session']['status']=='running','Disable applied before approval')
        access_change('approve')
        approved_terminal.wait(lambda d:d['session']['status']=='closed',10)
        approval_http.call('POST','/terminal/sessions',{'node_id':client,'cols':100,'rows':30,'_password':True,'reason':'Disabled approval negative test'},409)
        require(service_pids==docker('exec',a.client,'systemctl','show','--property=MainPID','nli-agent.service','nli-client-control.service'),'Terminal disable restarted NLI client services')
        sessions.remove(approved_terminal)
        access_change('request_enable');access_change('approve')
        require(runtime_signature(approval_http)==before,'Terminal access approvals changed parser synchronization')
        checks.append('webapp_disable_approval_closes_sessions_blocks_access_and_preserves_client_services_and_parser_hashes')
        result={'release':'v23.0.0-11','checks':checks,'status':'passed','production_nodes_modified':False,'ssh_used':False,'transcripts_persisted':False,'tls':'verified fixture CA and localhost hostname'}
        if pipeline_proof is not None:result['watched_parser_pipeline']=pipeline_proof
        a.result.parent.mkdir(parents=True,exist_ok=True);a.result.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
    finally:
        for t in sessions:
            try:t.close()
            except Exception:pass
        for h in workers:
            try:h.shutdown()
            except Exception:pass

if __name__=='__main__':main()
