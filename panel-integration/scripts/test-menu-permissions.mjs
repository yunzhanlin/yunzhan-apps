import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';

const source = fs.readFileSync(new URL('../web/src/menuPermissions.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: {target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext} }).outputText;
const {validAccessPlan,canOpenView,canReadPath,menuPermissionIDs} = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));
test('front-end catalog matches backend IDs and malformed plans fail closed', () => {
  const backend = fs.readFileSync(new URL('../internal/core/menu_permissions.go',import.meta.url),'utf8');
  for (const id of menuPermissionIDs) assert(backend.includes('{"'+id+'",'));
  for (const plan of [null,{}, {role:'root',menu_ids:[]},{role:'viewer',menu_ids:['terminal']},{role:'admin',menu_ids:['files','files']},{role:'admin',menu_ids:['future']},{role:'viewer',menu_ids:'files'}]) assert.equal(validAccessPlan(plan),false);
});
test('restricted navigation and refresh query gating retain the role ceiling', () => {
  const reader={role:'viewer',menu_ids:['files']};
  assert(validAccessPlan(reader));
  assert(canOpenView(reader,'files')); assert(canOpenView(reader,'account'));
  for(const key of ['overview','sites','terminal','audit','jobs','backups','runtimes','panel-access']) assert(!canOpenView(reader,key),key);
  assert(canReadPath(reader,'/sites'));
  for(const path of ['/overview','/sites/traffic','/certificates','/jobs','/software','/notifications?limit=30','/app-registry?refresh=1']) assert(!canReadPath(reader,path),path);
  const noMenus={role:'admin',menu_ids:[]};
  assert(canOpenView(noMenus,'account')); assert(canReadPath(noMenus,'/account'));
  assert(!canReadPath(noMenus,'/sites'));
  const storeOnly={role:'admin',menu_ids:['runtimes']};
  assert(canReadPath(storeOnly,'/app-registry?refresh=1')); assert(!canOpenView(storeOnly,'security'));
});
test('async refresh discards old account payloads and menu grants are not only hidden links', () => {
  const app=fs.readFileSync(new URL('../web/src/App.vue',import.meta.url),'utf8');
  assert(app.includes('epoch === accessEpoch && session === csrf.value ? result : undefined'));
  assert(app.includes('allNav.filter(item => canOpenView'));
  assert(app.includes('nav.value.map'));
  assert(app.includes(':access="accessPlan"'));
  assert(app.includes('面板用户与菜单授权'));
});
