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
