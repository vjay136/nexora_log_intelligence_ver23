import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const app=fs.readFileSync(new URL('../web/app.js',import.meta.url),'utf8');
const helpers=app.slice(app.indexOf('  let clientDirectory='),app.indexOf('  function agentMetricsLabel('));
function directory(api=async()=>({nodes:[],groups:[]})) {
  const state={user:{username:'operator'}};
  return {state,...vm.runInNewContext(`${helpers}\n({label:clientLabel,groups:clientGroups,clear:clearClientDirectory,load:loadClientDirectory,changed:clientDirectoryChanged,signature:clientTargetSignature,seed:nodes=>{clientDirectory={nodes,groups:[]};clientDirectoryNodes=new Map(nodes.map(node=>[node.node_id,node]));},snapshot:()=>clientDirectory})`,{Map,Date,Number,String,JSON,state,api,can:()=>true,requestFailure:error=>error.message,esc:String,number:String,page:{dataset:{dirty:'true'},querySelector:()=>null},navigate:()=>{}})};
}

test('Shared labels use indexed10000-node directory, retain identity fallback and honor cleared aliases',()=>{
  const d=directory();d.seed(Array.from({length:10000},(_,i)=>({node_id:`node-${i}`,display_name:`Named node ${i}`,groups:[{id:'all',name:'All enrolled'}]})));
  for(let i=0;i<10000;i++)assert.equal(d.label({id:`node-${i}`,hostname:`reported-${i}`}),`Named node ${i}`);
  assert.equal(d.label({id:'node-0',display_name:'',hostname:'reported-0'}),'reported-0');
  assert.equal(d.groups('node-9999')[0].name,'All enrolled');d.clear();assert.equal(d.label('node-0'),'node-0');
});

test('A late directory response cannot restore labels after logout or another session',async()=>{
  let reply;const d=directory(()=>new Promise(resolve=>{reply=resolve;}));
  const request=d.load();d.clear();d.state.user={username:'operator'};reply({nodes:[{node_id:'private-node',display_name:'Previous session label'}],groups:[]});await request;
  assert.equal(d.snapshot().nodes.length,0);assert.equal(d.label('private-node'),'private-node');
});

test('Frozen group target signatures include revisions and normalized exact IDs',()=>{
  const d=directory(),first=d.signature({node_ids:['b','a'],groups:[{id:'mail',revision:3}]});
  assert.equal(first,d.signature({node_ids:['a','b'],groups:[{id:'mail',revision:3}]}));
  assert.notEqual(first,d.signature({node_ids:['a','b'],groups:[{id:'mail',revision:4}]}));
  assert.notEqual(first,d.signature({node_ids:['a','c'],groups:[{id:'mail',revision:3}]}));
  assert.match(app,/target_mode:all\?'all_eligible':'selected',node_ids:all\?\[\]:nodeIds,bundle_hash:bundleHash/);
  assert.match(app,/nodeIds\.length>1000/);assert.match(app,/targetNodes\.length>4096/);
});

test('A remote directory change supersedes an in-flight older snapshot',async()=>{
  const replies=[];const d=directory(()=>new Promise(resolve=>replies.push(resolve)));
  const oldRequest=d.load();
  const changed=d.changed();
  assert.equal(replies.length,2,'a fresh post-change request must replace the pending read');
  replies[0]({nodes:[{node_id:'one',display_name:'Stale label'}],groups:[]});
  await oldRequest;
  assert.notEqual(d.label('one'),'Stale label');
  replies[1]({nodes:[{node_id:'one',display_name:'Current label'}],groups:[]});
  await changed;
  assert.equal(d.label('one'),'Current label');
});
