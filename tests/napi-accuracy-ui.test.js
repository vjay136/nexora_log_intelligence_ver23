import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
const start=app.indexOf('  function renderNAPISynthesisResult(');
const end=app.indexOf('  async function loadAssurance(',start);
assert.ok(start>=0&&end>start);
const escape=value=>String(value??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
const render=vm.runInNewContext(`(${app.slice(start,end).trim()})`,{
  esc:escape,number:value=>Number(value||0).toLocaleString('en-US'),pretty:value=>JSON.stringify(value),
  panel:(title,description,body,actions)=>`${title}\n${description}\n${body}\n${actions}`,
});

test('NAPI labels exact positive matches separately from correctly rejected negative records',()=>{
  const html=render({draft_created:true,id:'smtp',revision:1,validation:{training:{exact:2,total:2},held_out:{exact:1,total:1},negative:{false_positives:0,total:3}},review_validation:{status:'passed'}});
  assert.match(html,/Discovery: 2 of 2 outputs match exactly/);
  assert.match(html,/Held-out: 1 of 1 match exactly/);
  assert.match(html,/0 incorrectly accepted out of 3 tested/);
  assert.match(html,/Saved review validation: passed/);
  assert.match(html,/A test that confirms rejection is not a successful parse/);
});

test('NAPI mismatched outputs and negative false positives never get a passed review label',()=>{
  const html=render({validation:{training:{exact:1,total:2},held_out:{exact:0,total:1},negative:{false_positives:1,total:3}},review_validation:{status:'failed'}});
  assert.match(html,/Discovery: 1 of 2/);
  assert.match(html,/Held-out: 0 of 1/);
  assert.match(html,/1 incorrectly accepted out of 3/);
  assert.match(html,/Saved review validation: failed/);
  assert.doesNotMatch(html,/Saved review validation: passed/);
});

test('NAPI missing saved examples keep completion action and untrusted status remains escaped',()=>{
  const html=render({draft_created:true,id:'smtp',revision:1,requires_validation_examples:true,review_validation:{status:'<script>bad</script>'}});
  assert.match(html,/Complete validation examples/);
  assert.match(html,/&lt;script&gt;/);
  assert.doesNotMatch(html,/<script>/);
});
