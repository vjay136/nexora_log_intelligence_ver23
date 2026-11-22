#!/usr/bin/env python3
"""Test the actual Linux installer entrypoints from a fresh release extraction."""
import argparse, hashlib, json, os, pathlib, re, subprocess, tarfile, tempfile

def run_installer(folder, role, direct=False, expected=True):
    command=['./install-'+role+'-ver23.sh','--verify-only']
    if not direct:command.insert(0,'bash')
    p=subprocess.run(command,cwd=folder,text=True,capture_output=True)
    if expected:
        assert p.returncode==0,(role,p.stdout,p.stderr)
        assert 'PASS:' in p.stdout,(role,p.stdout)
    else:assert p.returncode!=0,(role,'unexpected acceptance of damaged bundle')
    return p

def check(output):
    assert os.name!='nt','Execute with Linux tools, not a Windows text-reader simulation'
    archive=output/'nli-v23.0.0-5-x86_64.tar.gz';prefix=archive.name[:-len('.tar.gz')]
    raw=(output/'SHA256SUMS').read_bytes()
    assert b'\r' not in raw and raw.endswith(b'\n'),'checksum manifest must be LF-only'
    assert b'\r' not in (output/'RELEASE_ID').read_bytes()
    with tempfile.TemporaryDirectory(prefix='nli-r5-entrypoint-') as temp:
        dest=pathlib.Path(temp)
        with tarfile.open(archive,'r:gz') as tar:
            members=tar.getmembers()
            assert members[0].name==prefix and members[0].isdir(),'original versioned archive directory missing'
            for member in members:
                path=pathlib.PurePosixPath(member.name)
                assert path.parts[0]==prefix and '..' not in path.parts and not path.is_absolute()
                assert member.isfile() or member.isdir(),'unexpected link or device in archive'
                assert member.mode & 0o002 == 0,member.name+' is world-writable'
                if member.isfile() and member.name.endswith('.sh'):assert member.mode==0o755,member.name
            tar.extractall(dest)
        folder=dest/prefix
        assert (folder/'SHA256SUMS').read_bytes()==raw
        hashes=0
        for line in raw.decode('utf-8').splitlines():
            match=re.fullmatch(r'([0-9a-f]{64})  ([^\r\n]+)',line);assert match,line
            digest,name=match.groups()
            with (folder/name).open('rb') as f:
                h=hashlib.sha256()
                for block in iter(lambda:f.read(1048576),b''):h.update(block)
            assert h.hexdigest()==digest,name
            hashes+=1
        for role in ['controller','client']:
            run_installer(folder,role)
            run_installer(folder,role,direct=True)
        # Exercise the user's default command, stopping only at the package
        # manager boundary so no configuration wizard or cloud calls can run.
        fake_bin=dest/'package-boundary';fake_bin.mkdir()
        fake_dnf=fake_bin/'dnf'
        fake_dnf.write_bytes(b'#!/bin/sh\nprintf "%s\\n" "$*" >"$NLI_TEST_DNF_CALL"\nexit 73\n')
        fake_dnf.chmod(0o755);dnf_call=dest/'dnf-call.txt'
        env=dict(os.environ,PATH=str(fake_bin)+':'+os.environ['PATH'],NLI_TEST_DNF_CALL=str(dnf_call))
        normal=subprocess.run(['bash','./install-controller-ver23.sh'],cwd=folder,env=env,
                              stdin=subprocess.DEVNULL,text=True,capture_output=True)
        assert normal.returncode==73,(normal.stdout,normal.stderr)
        assert 'installing nli-controller-agent-23.0.0-5.el9.x86_64' in normal.stdout
        assert '-y install ' in dnf_call.read_text()
        # Prove the unchanged original fail-closed validation still detects
        # both missing required entries and a present-but-tampered RPM.
        manifest=folder/'SHA256SUMS'
        manifest.write_bytes(b'\n'.join(line for line in raw.split(b'\n') if not line.endswith(b'  nli_client_ver23.rpm')))
        bad=run_installer(folder,'controller',expected=False)
        assert 'missing nli_client_ver23.rpm' in bad.stderr,bad.stderr
        manifest.write_bytes(raw)
        rpm=folder/'nli_controller_agent_ver23.rpm'
        with rpm.open('ab') as f:f.write(b'tamper fixture')
        bad=run_installer(folder,'controller',expected=False)
        assert 'checksum verification failed' in bad.stderr,bad.stderr
    return {'release':'v23.0.0-5','checksum_entries':hashes,'LF_only_manifest':True,
      'archive_versioned_directory':True,'shell_modes':'0755','world_writable_entries':0,
      'controller_and_client_bash_verify_only':'passed','controller_and_client_direct_verify_only':'passed',
      'controller_default_command_passes_checksum_stage':True,
      'missing_required_entry_rejected':True,'tampered_rpm_rejected':True}

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--output',type=pathlib.Path,required=True);a.add_argument('--result',type=pathlib.Path)
    args=a.parse_args();result=check(args.output.resolve())
    if args.result:args.result.write_bytes((json.dumps(result,indent=2)+'\n').encode('utf-8'))
    print(json.dumps(result,indent=2))
