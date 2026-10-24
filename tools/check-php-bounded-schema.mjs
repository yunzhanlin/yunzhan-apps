import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import {phpBoundedCases} from './php-bounded-fixtures.mjs';
const root=process.env.YUNZHAN_REGISTRY_FIXTURE_ROOT??fileURLToPath(new URL('../',import.meta.url));
const schema=JSON.parse(fs.readFileSync(new URL('../schema/app.schema.json',import.meta.url))),cases=phpBoundedCases(root);
const code="import json,sys\nfrom jsonschema import Draft202012Validator\np=json.load(sys.stdin)\nDraft202012Validator.check_schema(p['schema'])\nv=Draft202012Validator(p['schema'])\nfailures=[]\nfor c in p['cases']:\n errors=list(v.iter_errors(c['manifest']))\n if (not errors)!=c['valid']: failures.append({'case':c['name'],'actual_valid':not errors,'errors':[e.message for e in errors][:3]})\nprint(json.dumps({'ok':not failures,'draft':'2020-12','checked':len(p['cases']),'positive':sum(c['valid'] for c in p['cases']),'negative':sum(not c['valid'] for c in p['cases']),'failures':failures,'models_not_installed_acceptance':True}))\nsys.exit(bool(failures))";
process.stdout.write(execFileSync(process.env.YUNZHAN_SCHEMA_PYTHON??'python3',['-c',code],{input:JSON.stringify({schema,cases}),encoding:'utf8',timeout:30000,maxBuffer:2<<20}));
