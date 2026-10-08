import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import ts from '../web/node_modules/typescript/lib/typescript.js';

const source = fs.readFileSync(new URL('../web/src/softwareRouting.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {isSecuritySoftware, softwareManagerKind} = await import('data:text/javascript;base64,' + Buffer.from(js).toString('base64'));
const modules = ['site-diagnosis','network-threat-detection','website-analytics','files-sync','daily-report','website-statistics-v2','enterprise-tamper-proof','load-balance','mobile-pwa','apache-waf','php-code-security','task-manager','website-tamper-proof','user-manager','file-monitor','disk-analysis','platform-ops','nfs-manager','pm2-manager','pure-ftpd'];

test('only the three security handlers may use the security manager', () => {
  for (const id of ['nginx-waf','system-hardening','intrusion-prevention']) {
    assert.equal(isSecuritySoftware(id), true);
    assert.equal(softwareManagerKind({id,family:'security'}), 'security');
  }
});
test('all 20 compiled modules resolve to their own module manager', () => {
  for (const id of modules) {
    assert.equal(isSecuritySoftware(id), false, id);
    assert.equal(softwareManagerKind({id,family:'module'}), 'module', id);
  }
});
test('unknown families and malformed module targets fail closed', () => {
  for (const app of [{id:'unknown',family:'security'},{id:'website-analytics',family:'unknown'},{id:'../../intrusion-prevention',family:'module'},{id:'',family:'module'}]) assert.equal(softwareManagerKind(app), null);
});
test('all card actions use the shared routing and SSH fields have an explicit ID guard', () => {
  const app = fs.readFileSync(new URL('../web/src/App.vue', import.meta.url), 'utf8');
  const security = fs.readFileSync(new URL('../web/src/SecurityAppManager.vue', import.meta.url), 'utf8');
  assert(!app.includes('@click="softwareManager?.show'));
  assert(!app.includes(': softwareManager?.install'));
  assert(app.includes('@click="openSoftwareApp(app)"'));
  assert(app.includes('expected_sha256: app.sha256'));
  assert(security.includes('v-else-if="selected.id === \'intrusion-prevention\'"'));
  assert(security.includes('!isSecuritySoftware(app.id)'));
  assert(security.includes('!isSecuritySoftware(selected.value.id)'));
});
const lbSource=fs.readFileSync(new URL('../web/src/loadBalanceReport.ts',import.meta.url),'utf8');
const lbJS=ts.transpileModule(lbSource,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext}}).outputText;
const {loadBalanceEntryFields,loadBalanceEntryRow,loadBalanceNodeSummary,loadBalanceTransitions}=await import('data:text/javascript;base64,'+Buffer.from(lbJS).toString('base64'));
test('load balance selection preserves editable node arrays and policy without mutating report records',()=>{
 const row={domain:'lb.example.test',nodes:[{address:'127.0.0.1:41006',weight:1,backup:false},{address:'127.0.0.1:41007',weight:3,backup:true}],health_check:{path:'/ready',interval:30,failures:2,successes:2,scheme:'https',check_port:443,ca_pem:'public CA fixture'}};
 const carrier=loadBalanceEntryRow(row),fields=loadBalanceEntryFields({...row,...carrier});
 assert.equal(carrier.http_health_enabled,true);assert.deepEqual(fields.nodes,row.nodes);assert.deepEqual(fields.health_check,row.health_check);
 fields.nodes[0].weight=9;fields.health_check.path='/changed';
 assert.equal(row.nodes[0].weight,1);assert.equal(row.health_check.path,'/ready');
 assert.equal(loadBalanceNodeSummary(row.nodes),'127.0.0.1:41006 ×1, 127.0.0.1:41007 ×3（备用）');
 assert.equal(loadBalanceEntryFields({nodes:row.nodes}).health_check,null);
 const manager=fs.readFileSync(new URL('../web/src/AppModuleManager.vue',import.meta.url),'utf8');
 const report=fs.readFileSync(new URL('../web/src/AppModuleReport.vue',import.meta.url),'utf8');
 assert(manager.includes('Object.assign(form.value,loadBalanceEntryFields(row))'));
 assert(report.includes('loadBalanceEntryRow(v)'));
});
test('HTTP transition rows are deduplicated, bounded and keep the entry identity',()=>{
 const transitions=Array.from({length:240},(_,i)=>({sequence:i+1,revision:1,address:'127.0.0.1:41006',from:'unknown',to:'healthy',at:new Date(1700000000000+i*1000).toISOString()}));
 const rows=loadBalanceTransitions([{domain:'lb.example.test',transitions},{domain:'lb.example.test',transitions}]);
 assert.equal(rows.length,200);assert.equal(rows[0].sequence,240);assert.equal(rows[199].sequence,41);assert.equal(new Set(rows.map(r=>r.sequence)).size,200);
 assert.equal(loadBalanceTransitions([{domain:'owned.example.test',transitions:[{...transitions[0],domain:'other.example.test'}]}])[0].domain,'owned.example.test');
});
