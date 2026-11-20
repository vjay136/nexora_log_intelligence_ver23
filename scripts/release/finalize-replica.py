#!/usr/bin/env python3
"""Refresh artifact evidence without changing any replicated product files."""
import argparse, datetime, gzip, hashlib, json, pathlib, tarfile

def sha(p):
    with p.open('rb') as f:
        h=hashlib.sha256()
        for b in iter(lambda:f.read(1048576),b''): h.update(b)
    return h.hexdigest()

def finalize(root, baseline):
    proof=json.loads((root/'REPLICATION_MANIFEST.json').read_text(encoding='utf-8'))
    assert proof['release']=='v23.0.0-4'
    for package in proof['packages']:
        name='nli_client_ver23.rpm' if package['package']=='nli-client' else 'nli_controller_agent_ver23.rpm'
        assert sha(root/name)==package['r4_rpm_sha256']
    assert sha(root/'webapp_ver23.zip')==sha(baseline/'webapp_ver22.zip')
    archive=root/'nli-v23.0.0-4-x86_64.tar.gz'
    exclude={'SHA256SUMS',archive.name,archive.name+'.sha256','RELEASE_MANIFEST.json','SBOM.spdx.json','provenance.intoto.json'}
    assets=[p for p in sorted(root.iterdir()) if p.is_file() and p.name not in exclude]
    stamp='2026-11-21T00:00:00Z'
    def entry(p): return {'name':p.name,'size':p.stat().st_size,'sha256':sha(p)}
    subjects=[{'name':p.name,'digest':{'sha256':sha(p)}} for p in assets]
    prov={'_type':'https://in-toto.io/Statement/v1','subject':subjects,
          'predicateType':'https://slsa.dev/provenance/v1','predicate':{
           'buildDefinition':{'buildType':'https://nexora.local/buildtypes/local-rpm-artifact-repack/v1',
            'externalParameters':{'release':'v23.0.0-4','baseline':'v22.19.1-0','runtimeRecompiled':False},
            'resolvedDependencies':[{'uri':'local:v22.19.1-0/'+a['name'],'digest':{'sha256':a['sha256']}} for a in proof['baseline_artifacts']]},
           'runDetails':{'builder':{'id':'local-verified-artifact-replication'},'metadata':{'invocationId':'v23.0.0-4-local-replica'}}}}
    (root/'provenance.intoto.json').write_text(json.dumps(prov,indent=2)+'\n',encoding='utf-8')
    packages=[]; relationships=[]
    for i,p in enumerate(assets):
        ident='SPDXRef-Artifact-'+str(i)
        packages.append({'SPDXID':ident,'name':p.name,'versionInfo':'23.0.0-4','downloadLocation':'NOASSERTION',
          'filesAnalyzed':False,'checksums':[{'algorithm':'SHA256','checksumValue':sha(p)}],
          'licenseConcluded':'NOASSERTION','licenseDeclared':'NOASSERTION','copyrightText':'NOASSERTION'})
        relationships.append({'spdxElementId':'SPDXRef-DOCUMENT','relationshipType':'DESCRIBES','relatedSpdxElement':ident})
    sbom={'spdxVersion':'SPDX-2.3','dataLicense':'CC0-1.0','SPDXID':'SPDXRef-DOCUMENT',
      'name':'NLI Ver23 R4 local artifact replica','documentNamespace':'https://nexora.local/spdx/v23.0.0-4-local-replica',
      'creationInfo':{'created':stamp,'creators':['Tool: NLI-local-artifact-replication'],
        'comment':'Artifact inventory; original unchanged runtime dependency inventory retained in BASELINE_SBOM.spdx.json. Native runtime reports 22.19.1.'},
      'packages':packages,'relationships':relationships}
    (root/'SBOM.spdx.json').write_text(json.dumps(sbom,indent=2)+'\n',encoding='utf-8')
    evidence=assets+[root/'SBOM.spdx.json',root/'provenance.intoto.json']
    manifest={'release':'v23.0.0-4','version':'23.0.0','rpm_release':'4','architecture':'x86_64',
      'source_revision':proof['source_revision'],'runtime_version':'22.19.1','runtime_recompiled':False,
      'baseline':'v22.19.1-0','verification':'REPLICATION_MANIFEST.json','artifacts':[entry(p) for p in evidence]}
    (root/'RELEASE_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    members=[p for p in sorted(root.iterdir()) if p.is_file() and p.name not in {'SHA256SUMS',archive.name,archive.name+'.sha256'}]
    (root/'SHA256SUMS').write_text(''.join(sha(p)+'  '+p.name+'\n' for p in members),encoding='utf-8')
    members.append(root/'SHA256SUMS');members.sort()
    with tarfile.open(baseline/'nli-v22.19.1-0-x86_64.tar.gz','r:gz') as old:
        epoch=int(old.next().mtime)
    with archive.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=epoch,filename='') as compressed,tarfile.open(fileobj=compressed,mode='w') as tar:
        for p in members:
            info=tar.gettarinfo(str(p),p.name);info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=epoch
            with p.open('rb') as f:tar.addfile(info,f)
    (root/(archive.name+'.sha256')).write_text(sha(archive)+'  '+archive.name+'\n',encoding='utf-8')
    print(json.dumps({'release':manifest['release'],'checksum_entries':len(members)-1,'assets':len(list(root.iterdir())),
      'controller_sha256':sha(root/'nli_controller_agent_ver23.rpm'),'client_sha256':sha(root/'nli_client_ver23.rpm'),
      'webapp_sha256':sha(root/'webapp_ver23.zip'),'runtime_recompiled':False},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--baseline',type=pathlib.Path,required=True)
    a=p.parse_args();finalize(a.output.resolve(),a.baseline.resolve())
