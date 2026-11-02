import fs from'node:fs';import{fileURLToPath}from'node:url';import{spawnSync}from'node:child_process';import assert from'node:assert/strict';
import{analyticsClientCases}from'./analytics-client-fixtures.mjs';import{validateManifest}from'./lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),cases=analyticsClientCases(root),schema=JSON.parse(fs.readFileSync(root+'schema/app.schema.json'));
for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,'publisher:'+c.name);
const code=String.raw`import json,sys
from jsonschema import Draft202012Validator,FormatChecker
from referencing import Registry
def unique(pairs):
 value={}
 for key,item in pairs:
  if key in value:raise ValueError('duplicate property')
  value[key]=item
 return value
p=json.load(sys.stdin,object_pairs_hook=unique);Draft202012Validator.check_schema(p['schema']);network=[]
def deny(uri):
 network.append(uri);raise AssertionError('External schema retrieval refused')
v=Draft202012Validator(p['schema'],registry=Registry(retrieve=deny),format_checker=FormatChecker());fail=[]
for c in p['cases']:
 errors=list(v.iter_errors(c['manifest']))
 if(not errors)!=c['valid']:fail.append({'name':c['name'],'expected':c['valid'],'errors':[e.message for e in errors[:3]]})
assert not network
print(json.dumps({'ok':not fail,'cases':len(p['cases']),'positive':sum(c['valid']for c in p['cases']),'negative':sum(not c['valid']for c in p['cases']),'external_schema_fetches':len(network),'failures':fail}));sys.exit(1 if fail else 0)
`;
const r=spawnSync(process.env.YUNZHAN_SCHEMA_PYTHON||'python3',['-I','-B','-c',code],{input:JSON.stringify({schema,cases}),encoding:'utf8',timeout:15000,maxBuffer:1<<20});
process.stdout.write(r.stdout||'');process.stderr.write(r.stderr||'');assert.equal(r.status,0,'Independent schema validation must run without skipped cases');
const result=JSON.parse(r.stdout);assert(result.ok&&result.cases===70&&result.positive===52&&result.negative===18&&result.external_schema_fetches===0);
