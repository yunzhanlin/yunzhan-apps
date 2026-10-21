// Preserve the actual seventeen-job predecessor, never regenerate or overwrite.
import fs from 'node:fs';import assert from 'node:assert/strict';import {createHash}from'node:crypto';
const root=new URL('../',import.meta.url),raw=fs.readFileSync(new URL('.github/workflows/verify.yml',root)),sha=createHash('sha256').update(raw).digest('hex');assert.equal(sha,'324061ecf40bf956144d424c7ba905428dd6d44ac4ad4350e6bfb4727f2aac11');
const output=new URL('registry/reviewed-catalogs/before-waf-review24bjdc/',root);assert(!fs.existsSync(output));fs.mkdirSync(output,{mode:0o755});fs.writeFileSync(new URL('verify-pr71.yml',output),raw,{flag:'wx',mode:0o644});console.log(JSON.stringify({files:1,workflow_sha256:sha,signing_operations:0}));
