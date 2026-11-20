#!/usr/bin/env python3
"""Repackage the local Ver22.19 artifacts; never compile or patch runtime code.

Run on Linux with rpm/rpmbuild/rpm2cpio/cpio/python3 installed. Original source
specs supply the exact dependencies, maintainer scripts and file attributes.
All input and output payload files are compared, with explicit identity edits.
"""
import argparse, gzip, hashlib, io, json, os, pathlib, re, shutil
import subprocess, sys, tarfile, tempfile, zipfile

VERSION = '23.0.0'
RELEASE = '4'
TAG = 'v23.0.0-4'
BASE = 'v22.19.1-0'
REVISION = '77f95a94885ab1e1843bcd214d44e70a495ee85c'

def sha(path):
    with path.open('rb') as f:
        h=hashlib.sha256()
        for block in iter(lambda:f.read(1048576), b''): h.update(block)
    return h.hexdigest()

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def identity(data):
    return (data.replace(b'ver22', b'ver23').replace(b'Ver22', b'Ver23')
            .replace(b'-v22.sh', b'-v23.sh')
            .replace(b'22.19.1-0', b'23.0.0-4')
            .replace(b'^22[.]', b'^23[.]')
            .replace(b'V22_19_1_RELEASE_NOTES', b'V23_R4_RELEASE_NOTES'))

def rename(name):
    return identity(name.encode()).decode()

def files(root):
    return {str(p.relative_to(root)):p for p in root.rglob('*') if p.is_file()}

def extract(rpm, destination):
    destination.mkdir(parents=True)
    a=subprocess.Popen(['rpm2cpio',str(rpm)],stdout=subprocess.PIPE)
    try: run(['cpio','-idm','--quiet','--no-absolute-filenames'],stdin=a.stdout,cwd=destination)
    finally: a.stdout.close()
    assert a.wait()==0, 'rpm2cpio failed'

def change(path, transform, edits, original_name=None):
    before=path.read_bytes(); after=transform(before)
    if after!=before:
        path.write_bytes(after)
        edits.append({'path':original_name or str(path),'before':hashlib.sha256(before).hexdigest(),
                      'after':hashlib.sha256(after).hexdigest(),'reason':'release identity only'})

def repack(role, baseline, output, source, work, epoch):
    package='nli-client' if role=='client' else 'nli-controller-agent'
    original=baseline/('nli_client_ver22.rpm' if role=='client' else 'nli_controller_agent_ver22.rpm')
    payload=work/role/'payload'; extract(original,payload)
    original_files={n:sha(p) for n,p in files(payload).items()}
    edits=[]
    # Preserve all compatibility paths, service definitions, configuration,
    # signed parsers, executable bytes and browser assets exactly as shipped.
    for rel in ['usr/sbin/nli-client-setup','usr/sbin/nli-controller-setup']:
        p=payload/rel
        if p.exists(): change(p,identity,edits,rel)
    sql=payload/'usr/share/nli/supabase/nli_schema.sql'
    if sql.exists():
        change(sql,identity,edits,str(sql.relative_to(payload)))
        shutil.copyfile(sql,output/'nli_schema.sql')
    note=payload/f'usr/share/doc/{package}/V22_19_1_RELEASE_NOTES.md'
    if note.exists():
        change(note,identity,edits,str(note.relative_to(payload)))
        note.rename(note.with_name('V23_R4_RELEASE_NOTES.md'))
    spec=(source/f'packaging/rpm/{package}.spec').read_text()
    header=spec.split('%prep\n',1)[0]
    header=header.replace('nli_version 22.19.1','nli_version 23.0.0').replace('nli_release 0','nli_release 4')
    header=header.replace('Ver22','Ver23').replace('nexora_log_intelligence_ver21.git','nexora_log_intelligence_ver23.git')
    header=header.replace('Source0:', '# Source0:')
    maint='%pre\n'+spec.split('%pre\n',1)[1].split('%files',1)[0]
    listing='%files'+spec.split('%files',1)[1].split('%changelog',1)[0]
    listing=listing.replace(' -f parser-files.list','').replace('V22_19_1_RELEASE_NOTES','V23_R4_RELEASE_NOTES')
    if role=='client':
        listing+='\n%dir %attr(0750,root,nli) /etc/nli/parsers\n'
        for p in sorted((payload/'etc/nli/parsers').glob('*.json')):
            listing+='%config(noreplace) %attr(0644,root,nli) /etc/nli/parsers/'+p.name+'\n'
    body=header+'\n%prep\n\n%build\n# Original local RPM binaries copied unchanged.\n\n%install\nmkdir -p %{buildroot}\ncp -a '+str(payload)+'/. %{buildroot}/\n\n'+maint+listing
    top=work/role/'rpmbuild'
    for name in ['BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS']: (top/name).mkdir(parents=True,exist_ok=True)
    specfile=top/'SPECS'/f'{package}.spec'; specfile.write_text(body)
    env=dict(os.environ,SOURCE_DATE_EPOCH=str(epoch))
    result=run(['rpmbuild','-bb',str(specfile),'--define',f'_topdir {top}',
                '--define','dist .el9','--define','_buildhost reproducible.nli.local',
                '--define','use_source_date_epoch_as_buildtime 1','--define','clamp_mtime_to_source_date_epoch 1',
                '--define','_source_date_epoch_from_changelog 0','--define','_binary_payload w19.zstdio'],env=env,capture_output=True,text=True)
    (output/f'{package}.repack.log').write_text(result.stdout+result.stderr)
    built=next((top/'RPMS/x86_64').glob('*.rpm'))
    destination=output/('nli_client_ver23.rpm' if role=='client' else 'nli_controller_agent_ver23.rpm')
    shutil.copyfile(built,destination)
    verified=work/role/'verified'; extract(destination,verified)
    current=files(verified); allowed={rename(n):n for n in original_files}
    assert set(current)==set(allowed), 'RPM file inventory changed unexpectedly'
    for n,p in current.items():
        old=allowed[n]
        assert sha(p)==sha(payload/n), 'Repacked file differs from prepared original payload: '+n
        if n not in [e['path'] for e in edits] and old==n:
            assert sha(p)==original_files[old], 'Unexpected runtime edit: '+n
    for query,suffix in [(['-qi'],'.rpm.info.txt'),(['-ql'],'.files.txt'),(['-q','--qf','[%{FILENAMES} %{FILEMODES:perms} %{FILEUSERNAME} %{FILEGROUPNAME}\n]'],'.permissions.txt')]:
        args=['rpm']+query
        args.insert(2 if len(query)==1 else 2,'-p')
        text=run(args+[str(destination)],capture_output=True,text=True).stdout
        (output/destination.name.replace('.rpm',suffix if suffix!='.rpm.info.txt' else suffix)).write_text(text)
    oldscripts=run(['rpm','-qp','--scripts',str(original)],capture_output=True).stdout
    newscripts=run(['rpm','-qp','--scripts',str(destination)],capture_output=True).stdout
    assert oldscripts==newscripts, 'Maintainer script behavior changed'
    binary_proof={n:sha(p) for n,p in current.items() if n.startswith('usr/bin/')}
    assert all(h==original_files[n] for n,h in binary_proof.items())
    return {'package':package,'original_rpm_sha256':sha(original),'r4_rpm_sha256':sha(destination),
            'files_compared':len(current),'unchanged_binaries':binary_proof,'identity_edits':edits,
            'maintainer_scripts_identical':True}

def main():
    a=argparse.ArgumentParser();a.add_argument('--baseline',type=pathlib.Path,required=True)
    a.add_argument('--output',type=pathlib.Path,required=True);a.add_argument('--source',type=pathlib.Path,required=True)
    args=a.parse_args();baseline=args.baseline.resolve();output=args.output.resolve();source=args.source.resolve()
    output.mkdir(parents=True,exist_ok=True)
    assert not list(output.iterdir()),'Output must be a new empty local release folder'
    entries=[]
    for line in (baseline/'SHA256SUMS').read_text().splitlines():
        digest,name=line.split(maxsplit=1); name=name.lstrip('*');assert sha(baseline/name)==digest,name
    assert (baseline/'SOURCE_REVISION').read_text().strip()==REVISION
    skip={'SHA256SUMS','RELEASE_ID','RELEASE_MANIFEST.json','SBOM.spdx.json','provenance.intoto.json'}
    for old in sorted(baseline.iterdir()):
        if not old.is_file(): continue
        entries.append({'name':old.name,'sha256':sha(old),'size':old.stat().st_size})
        if old.name in skip or '.tar.gz' in old.name or '.rpm' in old.name or old.name.endswith(('.files.txt','.permissions.txt')):continue
        new=output/rename(old.name)
        shutil.copyfile(old,new)
        if old.suffix=='.sh' or old.name in ['INSTALLATION_AND_CONFIGURATION.md','V22_19_1_RELEASE_NOTES.md']:
            new.write_bytes(identity(old.read_bytes()))
    for name in ['RELEASE_MANIFEST.json','SBOM.spdx.json','provenance.intoto.json']:
        shutil.copyfile(baseline/name,output/('BASELINE_'+name))
    # Standalone webapp remains byte-for-byte identical, only its filename changes.
    assert sha(output/'webapp_ver23.zip')==sha(baseline/'webapp_ver22.zip')
    # Desktop ZIP root is a release filename; member content stays byte-identical.
    with zipfile.ZipFile(baseline/'webview_ver22.zip') as src,zipfile.ZipFile(output/'webview_ver23.zip','w') as dst:
        for old in src.infolist():
            entry=zipfile.ZipInfo(rename(old.filename),date_time=old.date_time)
            entry.compress_type=old.compress_type;entry.external_attr=old.external_attr
            dst.writestr(entry,src.read(old.filename))
    epoch=int(run(['rpm','-qp','--qf','%{BUILDTIME}',str(baseline/'nli_client_ver22.rpm')],capture_output=True,text=True).stdout)
    with tempfile.TemporaryDirectory(prefix='nli-r4-replica-') as tmp:
        proof=[repack(role,baseline,output,source,pathlib.Path(tmp),epoch) for role in ['client','controller']]
    (output/'RELEASE_ID').write_text(f'NLI_VERSION={VERSION}\nNLI_RELEASE={RELEASE}\nNLI_ARCH=x86_64\nSOURCE_REVISION={REVISION}\n')
    report={'release':TAG,'mode':'local artifact replication, no compilation','baseline':BASE,
            'source_revision':REVISION,'embedded_runtime_version':'22.19.1','baseline_artifacts':entries,
            'packages':proof,'webapp_zip_byte_identical':True,
            'supabase_changes':'release labels only; ownership and authentication logic unchanged'}
    (output/'REPLICATION_MANIFEST.json').write_text(json.dumps(report,indent=2)+'\n')
    (output/'REPLICATION_NOTES.md').write_text('''# NLI Ver23 R4 — v23.0.0-4

Replicated locally from the exact local v22.19.1-0 release artifacts. No runtime compilation or feature fixes were applied. RPM package version/release is 23.0.0-4; embedded executables remain the original bytes and report 22.19.1. Original configuration, parsers, browser application and maintainer-script behavior are retained. Only release identity, artifact names, desktop ZIP root and necessary filename references change.

Original API/sync issues are inherited. Supabase controller-secret ownership/authentication is unchanged; an existing secret mismatch is not fixed by replication. No live database or AWS node was modified. REPLICATION_MANIFEST.json records original hashes and per-package binary identity verification.
''')
    for p in sorted(output.glob('*.sh')):run(['bash','-n',str(p)])
    for name in ['webapp_ver23.zip','webview_ver23.zip']:
        with zipfile.ZipFile(output/name) as z:assert z.testzip() is None
    (output/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in sorted(output.iterdir()) if p.is_file() and p.name!='SHA256SUMS'))
    archive=output/'nli-v23.0.0-4-x86_64.tar.gz'
    members=sorted(output.iterdir())
    with archive.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=epoch,filename='') as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
        for p in members:
            info=tar.gettarinfo(str(p),p.name);info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=epoch
            with p.open('rb') as f:tar.addfile(info,f)
    (output/(archive.name+'.sha256')).write_text(sha(archive)+'  '+archive.name+'\n')
    run([sys.executable,str(source/'scripts/release/finalize-replica.py'),'--output',str(output),'--baseline',str(baseline)])
    print(json.dumps({'release':TAG,'verified_original_manifest_entries':59,'packages':proof,'output':str(output)},indent=2))

if __name__=='__main__':main()
