import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

test('published managers route modules independently and reject generic SSH fallback',async()=>{
  const app=await readFile(new URL('../panel-integration/web/src/App.vue',import.meta.url),'utf8');
  const security=await readFile(new URL('../panel-integration/web/src/SecurityAppManager.vue',import.meta.url),'utf8');
  const module=await readFile(new URL('../panel-integration/web/src/AppModuleManager.vue',import.meta.url),'utf8');
  assert(app.includes('@click="openSoftwareApp(app)"'));
  assert(!app.includes('@click="softwareManager?.show'));
  assert(app.includes(':on-install="queueSoftwareInstall"'));
  assert(app.includes('expected_sha256: app.sha256'));
  assert(security.includes('v-else-if="selected.id === \'intrusion-prevention\'"'));
  assert(security.includes('!isSecuritySoftware(selected.value.id)'));
  assert(module.includes('await props.onInstall(definition.value.id)'));
  assert(module.includes('安装并验证'));
});
