#!/usr/bin/env python3
"""Exercise real packaged terminals on isolated Docker controller/client fixtures.

No SSH, browser automation, production targets, transcripts or credentials are
stored. Existing r9_live_sync_restore.py separately qualifies rollout/restore.
"""
import argparse
import base64
import json
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


class Terminal:
    def __init__(self, http, node):
        self.http=http;self.seq=0;self.cursor=0;self.text=''
        opened=http.call('POST','/terminal/sessions',{'node_id':node,'cols':100,'rows':30,'_password':True,'reason':'Isolated R10 packaged terminal qualification'})
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
        self.seq+=1
        return self.http.call('POST',self.path+'/input',{'sequence':self.seq,'data':data})

    def command(self, command, timeout=20):
        marker='R10_'+secrets.token_hex(8)
        self.text=''
        self.send(command+"; printf '\\n%s\\n' '"+marker+"'\n")
        self.wait(lambda d: '\n'+marker+'\r\n' in self.text, timeout)
        return self.text

    def close(self):
        self.http.call('POST',self.path+'/close',{})


def runtime_signature(http):
    r=http.call('GET','/parser-sync/runtime')
    b=r['bundle']
    return (b.get('desired_hash'),b.get('controller_applied_hash'),[(c.get('node_id'),c.get('desired_hash'),c.get('applied_hash')) for c in r['clients']])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--controller',required=True);parser.add_argument('--client',required=True)
    parser.add_argument('--result',type=Path,required=True)
    a=parser.parse_args();checks=[];sessions=[];workers=[]
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
            enabled=[n for n in nodes if n['terminal_enabled']]
            if len(enabled)==2:break
            require(time.monotonic()<end,'Both fixture terminals did not become available')
            time.sleep(1)
        client=next(n['id'] for n in enabled if n['role']=='client')
        checks.append('explicit_host_optin_both_nodes')
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
            name='r10-terminal-'+secrets.token_hex(6)+'.log'
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
            t.send('journalctl -u '+unit+' -f -n 1\n');time.sleep(1);t.read();t.send('\x03')
            require('INTERRUPTED' in t.command('printf INTERRUPTED'),'Journal follow Ctrl-C failed')
            if target==client:
                out=t.command('sudo systemctl restart nli-agent; systemctl is-active nli-agent')
                require('\r\nactive\r\n' in out,'Limited service restart failed')
            # Flood without reading. Ring drops old bytes and reports cursor gap.
            t.send("head -c 700000 /dev/zero | tr '\\000' X; printf '\\nFLOOD_DONE\\n'\n")
            time.sleep(7)
            gap=t.read(after=0)
            require(gap['truncated'] and gap['start']>0,'Output flood did not report bounded-buffer gap')
            t.wait(lambda d:'FLOOD_DONE\r\n' in t.text,20)
            t.close();sessions.remove(t)
            t.http.call('POST',t.path+'/input',{'sequence':t.seq+1,'data':'echo replay\n'},409)
            checks.append(('controller' if target=='@controller' else 'client')+'_shell_files_vi_helpers_owner_isolation_flood_close')
        require(runtime_signature(h)==before,'Terminal operations changed parser bundle hashes')
        checks.append('parser_sync_hashes_unchanged')
        # Open a client shell, restart the broker, prove old session cannot replay.
        fresh=HTTP(a.controller);workers.append(fresh)
        t=Terminal(fresh,client);sessions.append(t)
        docker('exec',a.client,'systemctl','restart','nli-node-terminal.service')
        t.wait(lambda d:d['session']['status']=='closed',45)
        t.http.call('POST',t.path+'/input',{'sequence':1,'data':'echo forbidden-replay\n'},409)
        sessions.remove(t);checks.append('broker_restart_closes_old_generation_without_replay')
        result={'release':'v23.0.0-10','checks':checks,'status':'passed','production_nodes_modified':False,'ssh_used':False,'transcripts_persisted':False,'tls':'verified fixture CA and localhost hostname'}
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
