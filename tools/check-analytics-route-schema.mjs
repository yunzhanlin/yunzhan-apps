import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {analyticsRouteCases} from './analytics-route-fixtures.mjs';
import {validateManifest} from './lib.mjs';
const root=fileURLToPath(new URL('../',import.meta.url)),cases=analyticsRouteCases(root),schema=JSON.parse(fs.readFileSync(root+'schema/app.schema.json'));
for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
const code=`import json,sys
from jsonschema import Draft202012Validator
v=json.load(sys.stdin);Draft202012Validator.check_schema(v['schema']);validator=Draft202012Validator(v['schema']);fail=[]
for c in v['cases']:
 errors=list(validator.iter_errors(c['manifest']))
 if (not errors)!=c['valid']:fail.append({'name':c['name'],'expected':c['valid'],'errors':[e.message for e in errors[:2]]})
if fail:print(json.dumps(fail,ensure_ascii=False));sys.exit(1)
print(json.dumps({'ok':True,'cases':len(v['cases']),'independent_Draft202012':True,'source_only_not_installed':True}))
`;
const result=spawnSync(process.env.YUNZHAN_SCHEMA_PYTHON||'python3',['-I','-B','-c',code],{input:JSON.stringify({schema,cases}),encoding:'utf8',timeout:15000,maxBuffer:1<<20});
assert.equal(result.status,0,result.stderr||result.stdout);console.log(result.stdout.trim());
