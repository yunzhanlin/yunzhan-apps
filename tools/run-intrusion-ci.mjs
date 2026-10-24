import{extendReviewedHTTPSFixtureOverlay}from'./run-https-fixture-ci.mjs';
// One exact _test.go correction. Signed production and export stay immutable.
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';import {spawnSync} from 'node:child_process';
const sha=x=>createHash('sha256').update(x).digest('hex');
export const originalIntrusionFeatureFixtureSHA='200f47bd949d0f7d4ad5a91c8014613d816226e122922c72b7fb1c5b1b3f277f',correctedIntrusionFeatureFixtureSHA='34e259a6e8740d19b652358fca99e2f448f05ec3337e19d9496c304bd41b9011';
export function intrusionFeatureFixtureOverlay(raw){
 assert.equal(sha(raw),originalIntrusionFeatureFixtureSHA);let source=raw.toString();
 const originalLoop='\tfor _, scenario := range []string{"missing", "duplicate", "extra", "alias", "future", "legacy-feature", "other-app", "target", "executor-name-as-app", "route", "runtime", "compose", "wrong-handler"} {';
 const correctedLoop=originalLoop.replace('"legacy-feature", "other-app"','"legacy-feature", "prototype-v1", "future-feature", "other-app"');
 const originalCase='\t\t\t\tm.Version = "1.0"',correctedCase=originalCase+'\n\t\t\tcase "prototype-v1":\n\t\t\t\tm.RequiredPanelFeatures = []string{"intrusion-preserving-journal-v1"}\n\t\t\tcase "future-feature":\n\t\t\t\tm.RequiredPanelFeatures = []string{"intrusion-preserving-journal-v3"}';
 const originalAvailability='\tif panelFeatureAvailable(IntrusionJournalFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("intrusion-preserving-journal-v2") {';
 const correctedAvailability='\tif IntrusionJournalFeature != "intrusion-preserving-journal-v2" || panelFeatureAvailable(IntrusionJournalFeature) != (runtime.GOOS == "linux") || panelFeatureAvailable("intrusion-preserving-journal-v1") || panelFeatureAvailable("intrusion-preserving-journal-v3") {';
 for(const[from,to]of [[originalLoop,correctedLoop],[originalCase,correctedCase],[originalAvailability,correctedAvailability]]){assert.equal(source.split(from).length,2);source=source.replace(from,()=>to);}
 const result=Buffer.from(source);assert.equal(sha(result),correctedIntrusionFeatureFixtureSHA);return result;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 assert.equal(process.platform,'linux');assert.equal(process.getuid(),0);assert([3,4].includes(process.argv.length));const go=process.argv[2],mode=process.argv[3]||'full';assert(['full','race'].includes(mode));assert(path.isAbsolute(go)&&fs.realpathSync(go)===go);
 const root=fileURLToPath(new URL('../panel-integration-intrusion/',import.meta.url)),member='internal/appcatalog/intrusion_journal_features_test.go',target=path.join(root,member),raw=fs.readFileSync(target),index=JSON.parse(fs.readFileSync(root+'source-sha256.json'));assert.equal(index.release.frozen_inputs_sha256,'e1bfb1c02c721a45628d999f8d8dea9a6646d73742899b99ac022e3023c224a3');assert.equal(index.files[member],originalIntrusionFeatureFixtureSHA);assert.deepEqual(index.test_overrides,{});
 const parent=fs.realpathSync(os.tmpdir()),temporary=fs.mkdtempSync(path.join(parent,'yunzhan-intrusion-test-overlay-'));fs.chmodSync(temporary,0o700);
 try{const replacement=path.join(temporary,'intrusion_journal_features_test.go'),overlay=path.join(temporary,'overlay.json');fs.writeFileSync(replacement,intrusionFeatureFixtureOverlay(raw),{flag:'wx',mode:0o600});fs.writeFileSync(overlay,JSON.stringify({Replace:{[target]:replacement}}),{flag:'wx',mode:0o600});
  extendReviewedHTTPSFixtureOverlay(root,temporary,overlay);
  const args=mode==='full'?['test','-p','1','-overlay='+overlay,'./...','-count=1']:['test','-race','-overlay='+overlay,'./internal/executor','./internal/core','./internal/appcatalog','-run','^TestIntrusion','-count=1'];console.log(JSON.stringify({mode,test_only_overlay:member,original_sha256:sha(raw),corrected_sha256:sha(fs.readFileSync(replacement)),production_source_overrides:0,immutable_export_changed:false,platform_gate_preserved:true,old_v1_and_unknown_v3_explicitly_refused:true}));
  const result=spawnSync(go,args,{cwd:root,stdio:'inherit',timeout:900000});assert.equal(sha(fs.readFileSync(target)),originalIntrusionFeatureFixtureSHA);assert(!result.error&&!result.signal);assert.equal(result.status,0);
 }finally{assert.equal(sha(fs.readFileSync(target)),originalIntrusionFeatureFixtureSHA);assert.equal(path.dirname(temporary),parent);assert(path.basename(temporary).startsWith('yunzhan-intrusion-test-overlay-'));fs.rmSync(temporary,{recursive:true});}
}
