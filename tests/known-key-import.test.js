import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
const helper=app.slice(app.indexOf('  const KNOWN_KEY_IMPORT_MAX_BYTES'),app.indexOf('  // End isolated bulk key parser.'));
const parse=vm.runInNewContext(`${helper}\nparseKnownKeyImport`,{TextEncoder});

test('Bulk imports 1500 names from multiline, CSV, JSON and downloaded catalog without mutating spelling',()=>{
  const keys=Array.from({length:1500},(_,i)=>`KnownKey_${i}`);
  for(const raw of [keys.join('\r\n'),keys.map(key=>`"${key}"`).join(','),JSON.stringify(keys),JSON.stringify({keys}),JSON.stringify({name:'Exported catalog',config:{keys}})]) {
    const result=parse(raw);assert.equal(result.ready,true);assert.equal(result.keys.length,1500);
    assert.equal(result.keys[1499],'KnownKey_1499');assert.equal(result.invalidCount,0);
  }
});

test('Bulk removes case-insensitive duplicates and retains first observed spelling',()=>{
  const result=parse('\uFEFFInternalId;status\ninternalid\tSTATUS reason');
  assert.equal(result.ready,true);assert.equal(result.duplicates,2);assert.equal(result.received,5);
  assert.deepEqual(Array.from(result.keys),['InternalId','status','reason']);
});

test('Bulk never silently drops invalid key/value input or malformed JSON',()=>{
  for(const raw of ['status=failed\nreason=not_needed','valid\n9invalid','"valid name"',JSON.stringify(['valid',null,42,{}])]) {
    const result=parse(raw);assert.equal(result.ready,false);assert.ok(result.invalidCount>0);
  }
  assert.throws(()=>parse('{"keys":['),/Invalid JSON/);
  assert.throws(()=>parse('{"unknown":[]}'),/keys array/);
  assert.equal(parse('').ready,false);
});

test('Bulk matches controller boundaries at 10000 names and 128 identifier characters',()=>{
  assert.equal(parse(Array.from({length:10000},(_,i)=>`field_${i}`).join('\n')).ready,true);
  const over=parse(Array.from({length:10001},(_,i)=>`field_${i}`).join('\n'));
  assert.equal(over.ready,false);assert.equal(over.keys.length,10001);
  assert.equal(parse('a'.repeat(128)).ready,true);assert.equal(parse('a'.repeat(129)).ready,false);
  assert.throws(()=>parse('a'.repeat(2*1024*1024+1)),/2 MiB/);
});

test('Bulk save uses ordinary approval-gated catalog endpoint and requires fresh preview',()=>{
  const save=app.slice(app.indexOf("case 'known-key-bulk-form'"),app.indexOf("case 'known-key-quick-form'"));
  assert.match(save,/form\.knownKeyPreview!==data\.keys_source/);
  assert.match(save,/POST/);assert.match(save,/config:\{keys:imported\.keys\}/);
  assert.doesNotMatch(save,/\/publish|\/approve|\/rollout/);
});
