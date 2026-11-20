"""Exercise actual installer backend selection without mutating host config."""
import json, os, pathlib, shutil, subprocess, sys, tempfile
root=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
s=(root/'scripts/setup-controller-rocky.sh').read_text(encoding='utf-8')
block=s.split('# Preserve the metadata authority',1)[1].split("supabase_url=''",1)[0]
urlcheck=s.split('supabase_project_changed=false',1)[1].split('current_supabase_key=$(saved_supabase_value',1)[0]
bash=shutil.which('bash')
if os.name=='nt': bash='C:/Program Files/Git/bin/bash.exe'
assert bash
with tempfile.TemporaryDirectory() as tmp:
 d=pathlib.Path(tmp); config=d/'controller.json'; state=d/'state'; state.mkdir(); users=state/'users.json'
 env=dict(os.environ, CONFIG=str(config).replace('\\','/'),STATE_DIR=str(state).replace('\\','/'),NLI_TEST_PYTHON=sys.executable.replace('\\','/'))
 header='''set -eu
fail() { printf '%s\\n' "$*" >&2; exit 1; }
info() { :; }
read_env() { printf '%s' "${SAVED_TOKEN:-}"; }
python3() { "$NLI_TEST_PYTHON" "$@"; }
'''
 def run(provider='supabase',initialized=True,mode=1,**settings):
  config.write_text(json.dumps({'storage_provider':provider}))
  if initialized: users.write_text('{}')
  else: users.unlink(missing_ok=True)
  script=header+'# Preserve the metadata authority'+block+f'\nmode={mode}\n'
  script+='if [[ $mode == 7 || $mode == 8 || $mode == 10 ]]; then default_local_metadata_for_new_controller; fi\nprintf "%s" "$storage_provider"\n'
  return subprocess.run([bash,'-c',script],env=dict(env,**settings),capture_output=True,text=True)
 for provider in ['supabase','local']:
  for mode in range(1,11):
   r=run(provider,True,mode); assert r.returncode==0 and r.stdout==provider,(mode,provider,r.stderr)
 for mode in range(1,11):
  r=run('supabase',False,mode); assert r.returncode==0 and r.stdout==('local' if mode in (7,8,10) else 'supabase'),(mode,r.stderr)
 r=run('local',False,1,SAVED_TOKEN='x'*32); assert r.returncode==0 and r.stdout=='local'
 r=run('local',True,1,NLI_SETUP_STORAGE_PROVIDER='supabase'); assert r.returncode!=0 and 'back up' in r.stderr
 r=run('local',True,1,NLI_SETUP_STORAGE_PROVIDER='supabase',NLI_SETUP_ALLOW_METADATA_BACKEND_CHANGE='1'); assert r.returncode==0 and r.stdout=='supabase'
 config.write_text('{broken'); before=config.read_bytes()
 r=subprocess.run([bash,'-c',header+'# Preserve the metadata authority'+block],env=env,capture_output=True,text=True)
 assert r.returncode!=0 and config.read_bytes()==before
 for changed,ack,success in [('https://same.supabase.co/',False,True),('https://other.supabase.co',False,False),('https://other.supabase.co',True,True)]:
  e=dict(env,existing_metadata_provider='supabase',current_supabase_url='https://same.supabase.co',supabase_url=changed)
  if ack:e['NLI_SETUP_ALLOW_METADATA_BACKEND_CHANGE']='1'
  fn=block.split('metadata_backend_change_ack() {',1)[1].split('default_local_metadata_for_new_controller()',1)[0]
  r=subprocess.run([bash,'-c',header+'metadata_backend_change_ack() {'+fn+'\nsupabase_url=${supabase_url%/}'+urlcheck],env=e,capture_output=True,text=True)
  assert (r.returncode==0)==success,r.stderr
 assert 'deployment mode must be 1 through 10' in s
 assert '11)' not in s
print('Installer metadata preservation: PASS (all ten modes, project and provider guards, fresh defaults)')

# Classify auth failures using the actual setup probe without contacting a server.
probe=sources_probe=(root/'scripts/setup-controller-rocky.sh').read_text(encoding='utf-8').split('verify_supabase() {',1)[1].split('\n}\n',1)[0]
for status in ['200','401','403','404','503']:
 script="python3() { \"$NLI_TEST_PYTHON\" \"$@\"; }\ncurl() { printf '%s\\n%s' '{\"status\":\"ok\",\"schema_version\":1}' \"$STATUS\"; }\n"
 script+='verify_supabase() {'+probe+'\n}\nsupabase_public_key=test; supabase_controller_secret=test; supabase_url=https://test.supabase.co\nverify_supabase; rc=$?; printf \"%s %s\" \"$rc\" \"$supabase_auth_rejected\"'
 r=subprocess.run([bash,'-c',script],env=dict(os.environ,NLI_TEST_PYTHON=sys.executable.replace('\\','/'),STATUS=status),capture_output=True,text=True)
 assert r.stdout==('0 false' if status=='200' else '1 true' if status in ('401','403') else '1 false'),(status,r.stdout,r.stderr)
print('Supabase setup probe auth classification: PASS')
