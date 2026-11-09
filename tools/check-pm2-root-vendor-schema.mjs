import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {validateManifest} from './lib.mjs';
import {pm2RootVendorCases} from './pm2-root-vendor-fixtures.mjs';

const root=fileURLToPath(new URL('../',import.meta.url)),schema=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url))),cases=pm2RootVendorCases(root);
for(const c of cases)assert.equal(validateManifest(c.manifest).length===0,c.valid,c.name);
const code="import json,sys\nfrom jsonschema import Draft202012Validator\np=json.load(sys.stdin)\nDraft202012Validator.check_schema(p['schema'])\nv=Draft202012Validator(p['schema']); f=[]\nfor c in p['cases']:\n errors=list(v.iter_errors(c['manifest']))\n if (not errors)!=c['valid']: f.append({'name':c['name'],'valid':not errors,'errors':[e.message for e in errors][:3]})\nprint(json.dumps({'ok':not f,'draft':'2020-12','cases':len(p['cases']),'positive':sum(c['valid'] for c in p['cases']),'negative':sum(not c['valid'] for c in p['cases']),'failures':f,'not_installed_acceptance':True}))\nsys.exit(bool(f))";
process.stdout.write(execFileSync(process.env.YUNZHAN_SCHEMA_PYTHON??'python3',['-I','-B','-c',code],{input:JSON.stringify({schema,cases}),encoding:'utf8',timeout:30000,maxBuffer:2<<20}));
