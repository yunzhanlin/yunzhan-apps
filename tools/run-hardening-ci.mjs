// Test-only compatibility repair. Immutable signed production and test exports
// remain byte-identical; Go sees one declared _test.go overlay, never runtime.
import fs from'node:fs';import os from'node:os';import path from'node:path';import assert from'node:assert/strict';import{fileURLToPath}from'node:url';import{createHash}from'node:crypto';import{spawnSync}from'node:child_process';
export const manifestFixtureOriginalSHA='8e08c18d869ce38f703a0263426b606fae169b86fcb4942b40d52b160aa58126';
const sha=b=>createHash('sha256').update(b).digest('hex');
export function hardeningManifestFixtureOverlay(raw){
 assert.equal(sha(raw),manifestFixtureOriginalSHA,'Only the exact original test fixture can be substituted');
 const old='\ts := New(Config{SecurityDir: filepath.Join(t.TempDir(), "security"), SystemRoot: t.TempDir()})';
 assert.equal(raw.toString().split(old).length-1,1);
 const corrected=old+'\n\tif id == "system-hardening" {\n\t\t// Explicit isolated trust roots and model kernel, not host permissions.\n\t\ts = newHardeningFixture(t).s\n\t\tif err := os.MkdirAll(s.systemPath("/etc/sysctl.d"), 0755); err != nil {\n\t\t\tt.Fatal(err)\n\t\t}\n\t}';
 return Buffer.from(raw.toString().replace(old,corrected));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert.equal(process.argv.length,3);const go=process.argv[2];assert(path.isAbsolute(go)&&fs.realpathSync(go)===go);const root=fileURLToPath(new URL('../panel-integration-hardening/',import.meta.url)),member='internal/executor/software_manifest_record_linux_test.go',target=path.join(root,member),raw=fs.readFileSync(target);
 const release=JSON.parse(fs.readFileSync(root+'release-source-inputs.json'));assert.equal(release.frozen_inputs_sha256,'3508a91003fd71ec4b8e79297f2d68eb8c3caffef3be070b8e5785905da6255a');assert.equal(release.files[member],manifestFixtureOriginalSHA);
 const parent=fs.realpathSync(os.tmpdir()),temporary=fs.mkdtempSync(path.join(parent,'yunzhan-hardening-test-overlay-'));fs.chmodSync(temporary,0o700);
 try{const replacement=path.join(temporary,'software_manifest_record_linux_test.go'),overlay=path.join(temporary,'overlay.json');fs.writeFileSync(replacement,hardeningManifestFixtureOverlay(raw),{flag:'wx',mode:0o600});fs.writeFileSync(overlay,JSON.stringify({Replace:{[target]:replacement}}),{flag:'wx',mode:0o600});
  const args=['test','-p','1','-overlay='+overlay,'./...','-count=1'];console.log(JSON.stringify({test_only_overlay:member,original_sha256:sha(raw),overlay_sha256:sha(fs.readFileSync(replacement)),production_source_overrides:0,original_assertions_unchanged:true}));
  const result=spawnSync(go,args,{cwd:root,stdio:'inherit',timeout:900000});assert.equal(sha(fs.readFileSync(target)),manifestFixtureOriginalSHA);assert(!result.error&&!result.signal);assert.equal(result.status,0);
 }finally{assert.equal(path.dirname(temporary),parent);assert(path.basename(temporary).startsWith('yunzhan-hardening-test-overlay-'));fs.rmSync(temporary,{recursive:true});}
}
