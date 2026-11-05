import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {analyticsQueryCases} from './analytics-query-fixtures.mjs';
import {validateManifest} from './lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const cases=analyticsQueryCases(root),schemas=['schema/app.schema.json','candidate/schema/app.schema.json'].map(name=>({name,schema:JSON.parse(fs.readFileSync(root+name))}));
for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
const code=String.raw`import json,sys
from jsonschema import Draft202012Validator
v=json.load(sys.stdin)
for item in v['schemas']:
 Draft202012Validator.check_schema(item['schema']);validator=Draft202012Validator(item['schema'])
 for c in v['cases']:
  errors=list(validator.iter_errors(c['manifest']))
  assert (not errors)==c['valid'],(item['name'],c['name'],[e.message for e in errors[:2]])
print(json.dumps({'ok':True,'cases':len(v['cases']),'schemas':len(v['schemas']),'independent_Draft202012':True,'not_installed_acceptance':True}))
`;
const result=spawnSync(process.env.YUNZHAN_SCHEMA_PYTHON||'python3',['-I','-B','-c',code],{input:JSON.stringify({schemas,cases}),encoding:'utf8',timeout:15000,maxBuffer:1<<20});
assert.equal(result.status,0,result.stderr||result.stdout);console.log(result.stdout.trim());
