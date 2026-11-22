#!/usr/bin/env python3
"""Refresh artifact evidence without changing any replicated product files."""
import argparse, datetime, gzip, hashlib, json, pathlib, tarfile

def write_lf(path, text):
    # Path.write_text uses host newline translation on Windows. Manifest
    # filenames must never acquire a trailing carriage return on Linux.
    path.write_bytes(text.replace('\r\n','\n').encode('utf-8'))

def sha(p):
    with p.open('rb') as f:
        h=hashlib.sha256()
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()

def finalize(root, baseline):
    proof=json.loads((root/'REPLICATION_MANIFEST.json').read_text(encoding='utf-8'))
    assert proof['release']=='v23.0.0-5'
    for package in proof['packages']:
        name='nli_client_ver23.rpm' if package['package']=='nli-client' else 'nli_controller_agent_ver23.rpm'
        assert sha(root/name)==package['r5_rpm_sha256']
    assert sha(root/'webapp_ver23.zip')==sha(baseline/'webapp_ver22.zip')
    archive=root/'nli-v23.0.0-5-x86_64.tar.gz'
    exclude={'SHA256SUMS',archive.name,archive.name+'.sha256','RELEASE_MANIFEST.json','SBOM.spdx.json','provenance.intoto.json'}
    assets=[p for p in sorted(root.iterdir()) if p.is_file() and p.name not in exclude]
    stamp='2026-11-22T00:00:00Z'
    def entry(p): return {'name':p.name,'size':p.stat().st_size,'sha256':sha(p)}
    subjects=[{'name':p.name,'digest':{'sha256':sha(p)}} for p in assets]
    prov={'_type':'https://in-toto.io/Statement/v1','subject':subjects,
          'predicateType':'https://slsa.dev/provenance/v1','predicate':{
           'buildDefinition':{'buildType':'https://nexora.local/buildtypes/local-rpm-artifact-repack/v1',
            'externalParameters':{'release':'v23.0.0-5','baseline':'v22.19.1-0','runtimeRecompiled':False},
            'resolvedDependencies':[{'uri':'local:v22.19.1-0/'+a['name'],'digest':{'sha256':a['sha256']}} for a in proof['baseline_artifacts']]},
           'runDetails':{'builder':{'id':'local-verified-artifact-replication'},'metadata':{'invocationId':'v23.0.0-5-local-replica'}}}}
    write_lf(root/'provenance.intoto.json',json.dumps(prov,indent=2)+'\n')
    packages=[]; relationships=[]
    for i,p in enumerate(assets):
        ident='SPDXRef-Artifact-'+str(i)
        packages.append({'SPDXID':ident,'name':p.name,'versionInfo':'23.0.0-5','downloadLocation':'NOASSERTION',
          'filesAnalyzed':False,'checksums':[{'algorithm':'SHA256','checksumValue':sha(p)}],
          'licenseConcluded':'NOASSERTION','licenseDeclared':'NOASSERTION','copyrightText':'NOASSERTION'})
        relationships.append({'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':ident})
    sbom={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT',
      'name':'NLI Ver23 R5 local artifact replica','documentNamespace':'https://nexora.local/spdx/v23.0.0-5-local-replica',
      'creationInfo':{'created':stamp,'creators':['Tool: NLI-local-artifact-replication'],
        'comment':'Artifact inventory; original unchanged runtime dependency inventory retained in BASELINE_SBOM.spdx.json. Native runtime reports 22.19.1.'},
      'packages':packages,'relationships':relationships}
    write_lf(root/'SBOM.spdx.json',json.dumps(sbom,indent=2)+'\n')
    evidence=assets+[root/'SBOM.spdx.json',root/'provenance.intoto.json']
    manifest={'release':'v23.0.0-5','version':'23.0.0','rpm_release':'5','architecture':'x86_64',
      'source_revision':proof['source_revision'],'runtime_version':'22.19.1','runtime_recompiled':False,
      'baseline':'v22.19.1-0','verification':'REPLICATION_MANIFEST.json','artifacts':[entry(p) for p in evidence]}
    write_lf(root/'RELEASE_MANIFEST.json',json.dumps(manifest,indent=2)+'\n')
    members=[p for p in sorted(root.iterdir()) if p.is_file() and p.name not in {'SHA256SUMS',archive.name,archive.name+'.sha256'}]
    write_lf(root/'SHA256SUMS',''.join(sha(p)+'  '+p.name+'\n' for p in members))
    members.append(root/'SHA256SUMS');members.sort()
    with tarfile.open(baseline/'nli-v22.19.1-0-x86_64.tar.gz','r:gz') as old:
        original_members=old.getmembers()
        epoch=int(original_members[0].mtime)
        original_modes={m.name.rsplit('/',1)[-1]:m.mode for m in original_members if m.isfile()}
    def original_name(name):
        return name.replace('ver23','ver22').replace('-v23.sh','-v22.sh').replace('V23_R5_RELEASE_NOTES','V22_19_1_RELEASE_NOTES')
    prefix=archive.name[:-len('.tar.gz')]
    with archive.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=epoch,filename='') as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
        directory=tarfile.TarInfo(prefix);directory.type=tarfile.DIRTYPE
        directory.mode=0o755;directory.uid=directory.gid=0;directory.uname=directory.gname='root';directory.mtime=epoch
        tar.addfile(directory)
        for p in members:
            info=tar.gettarinfo(str(p),prefix+'/'+p.name);info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=epoch
            info.mode=original_modes.get(original_name(p.name),0o755 if p.suffix=='.sh' else 0o644)
            with p.open('rb') as f:tar.addfile(info,f)
    write_lf(root/(archive.name+'.sha256'),sha(archive)+'  '+archive.name+'\n')
    print(json.dumps({'release':manifest['release'],'checksum_entries':len(members)-1,'assets':len(list(root.iterdir())),
      'controller_sha256':sha(root/'nli_controller_agent_ver23.rpm'),'client_sha256':sha(root/'nli_client_ver23.rpm'),
      'webapp_sha256':sha(root/'webapp_ver23.zip'),'runtime_recompiled':False},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--baseline',type=pathlib.Path,required=True)
    a=p.parse_args();finalize(a.output.resolve(),a.baseline.resolve())
