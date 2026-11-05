import fs from'node:fs';
import {fileURLToPath}from'node:url';
import {spawnSync}from'node:child_process';
import assert from'node:assert/strict';
import {integrityKernelCases}from'./integrity-kernel-fixtures.mjs';
import {validateManifest}from'./lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),cases=integrityKernelCases(root),schemas=['schema/app.schema.json','candidate/schema/app.schema.json'].map(name=>({name,schema:JSON.parse(fs.readFileSync(root+name))}));
for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
const code=`import json,sys
from jsonschema import Draft202012Validator
data=json.load(sys.stdin);failures=[]
for schema in data['schemas']:
 Draft202012Validator.check_schema(schema['schema']);validator=Draft202012Validator(schema['schema'])
 for case in data['cases']:
  errors=list(validator.iter_errors(case['manifest']))
  if (not errors)!=case['valid']:failures.append({'schema':schema['name'],'case':case['name'],'errors':[e.message for e in errors[:2]]})
if failures:print(json.dumps(failures));sys.exit(1)
print(json.dumps({'ok':True,'cases':len(data['cases']),'schemas':len(data['schemas']),'independent_Draft202012':True,'not_installed_acceptance':True}))
`;
const result=spawnSync(process.env.YUNZHAN_SCHEMA_PYTHON||'python3',['-I','-B','-c',code],{input:JSON.stringify({schemas,cases}),encoding:'utf8',timeout:15000,maxBuffer:1<<20});
assert.equal(result.status,0,result.stderr||result.stdout);console.log(result.stdout.trim());
