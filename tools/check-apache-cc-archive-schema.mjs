import fs from'node:fs';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';import assert from'node:assert/strict';
import{apacheCCArchiveCases}from'./apache-cc-archive-fixtures.mjs';import{validateManifest}from'./lib.mjs';import{candidateSource}from'./candidate-source.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),stable=JSON.parse(fs.readFileSync(root+'registry/apps.json')),source=candidateSource(stable,JSON.parse(fs.readFileSync(root+'registry/candidate-apps.json'))),schema=JSON.parse(fs.readFileSync(root+'schema/app.schema.json'));
const cases=[...apacheCCArchiveCases(source.apps.find(a=>a.id==='apache-waf')),...stable.apps.map(manifest=>({name:'stable50:'+manifest.id,valid:true,manifest})),...source.apps.map(manifest=>({name:'candidate50:'+manifest.id,valid:true,manifest})),...['2.4.0','2.5.0'].map(version=>({name:'original-'+version,valid:true,manifest:JSON.parse(fs.readFileSync(root+'candidate/dist/apps/apache-waf/'+version+'/manifest.json'))}))];assert.equal(cases.length,128);
for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,'publisher:'+c.name);
const code=String.raw`import json,sys
from jsonschema import Draft202012Validator,FormatChecker
from referencing import Registry
p=json.load(sys.stdin);Draft202012Validator.check_schema(p['schema']);network=[]
def deny(uri):
 network.append(uri);raise AssertionError('External schema retrieval refused')
v=Draft202012Validator(p['schema'],registry=Registry(retrieve=deny),format_checker=FormatChecker());fail=[]
for c in p['cases']:
 errors=list(v.iter_errors(c['manifest']))
 if(not errors)!=c['valid']:fail.append({'name':c['name'],'expected':c['valid'],'errors':[e.message for e in errors[:3]]})
assert not network
print(json.dumps({'ok':not fail,'cases':len(p['cases']),'positive':sum(c['valid']for c in p['cases']),'negative':sum(not c['valid']for c in p['cases']),'external_schema_fetches':len(network),'failures':fail}));sys.exit(1 if fail else 0)
`;
const r=spawnSync(process.env.YUNZHAN_SCHEMA_PYTHON||'python3',['-I','-B','-c',code],{input:JSON.stringify({schema,cases}),encoding:'utf8',timeout:15000,maxBuffer:1<<20});process.stdout.write(r.stdout||'');process.stderr.write(r.stderr||'');assert.equal(r.status,0,'Independent archive schema must execute without skipped cases');const result=JSON.parse(r.stdout);assert(result.ok&&result.cases===128&&result.positive===103&&result.negative===25&&result.external_schema_fetches===0);
