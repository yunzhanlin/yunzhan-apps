// Export a new immutable, archive-bound source scope. Never rewrite F48.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const repo = fileURLToPath(new URL('..', import.meta.url));
const source = process.argv[2], version = '0.1.0-dev.proapps24mobilelinkblgt';
assert(process.argv.length === 3 && path.isAbsolute(source) && path.normalize(source) === source && fs.realpathSync(source) === source);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const scope = 'panel-integration-mobile-delivery-links', output = path.join(repo, scope);
assert(!fs.existsSync(output), 'Never overwrite an immutable source export');
const previousRaw = fs.readFileSync(repo + 'panel-integration-memcached-retirement-handler/source-sha256.json');
assert.equal(sha(previousRaw), 'a1c1909d3a33c6abaf613e9feaf50af2c846d1db7055f4d1b4cb87e918bc1467');
const previous = JSON.parse(previousRaw), index = JSON.parse(fs.readFileSync(source + '/SOURCE_INPUTS.json'));
assert(index.inputs_sha256 === '3858db5be263ebb85537a695cd9fdf16c14b32df696aa289bf1cc5e383801255' && sha(JSON.stringify(index.files)) === index.inputs_sha256 && Object.keys(index.files).length === 17625);
const changed = ['internal/executor/app_load_balance_https_linux_test.go', 'packaging/build-release.sh', 'web/package-lock.json', 'web/package.json', 'web/src/AppModuleReport.vue'];
const added = ['scripts/test-mobile-delivery-links.mjs', 'web/src/mobileDelivery.ts'];
const archive = source + '/.local/releases/panel-' + version + '-linux-amd64.tar.gz', name = path.basename(archive), info = fs.lstatSync(archive);
assert(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.size > 0 && info.size < (500 << 20) && fs.realpathSync(archive) === archive);
const archived = JSON.parse(execFileSync('/usr/bin/tar', ['-xOf', archive, name.replace(/\.tar\.gz$/, '') + '/SOURCE_INPUTS.json'], { maxBuffer: 16 << 20 }));
assert.deepEqual(archived, index);
const names = [...Object.keys(previous.files), ...added].sort();
assert.equal(new Set(names).size, 1922);
assert.equal(names.filter(n => n.endsWith('.go')).length, 1459);
const files = {};
for (const n of names) {
  assert(path.posix.normalize(n) === n && !path.isAbsolute(n) && !n.split('/').some(v => ['..', '.git', '.local', 'node_modules'].includes(v)));
  const v = index.files[n], file = source + '/' + n, st = fs.lstatSync(file);
  assert(v.sha256 && st.isFile() && !st.isSymbolicLink() && st.nlink === 1 && (st.mode & 4095) === v.mode && st.size === v.bytes && v.bytes <= (2 << 20) && fs.realpathSync(file) === file);
  assert.equal(sha(fs.readFileSync(file)), v.sha256, n);
  files[n] = v.sha256;
}
assert.deepEqual(Object.keys(previous.files).filter(n => previous.files[n] !== files[n]), changed);
assert.deepEqual(Object.keys(files).filter(n => !Object.hasOwn(previous.files, n)), added);
assert.equal(files['internal/executor/app_load_balance_https_linux_test.go'], '026dce1a592366561eecba2ba4e7eb1c16828285f226c3fd9140e79be8e98ff3');
assert(Object.keys(previous.files).filter(n => n.endsWith('.go') && !n.endsWith('_test.go')).every(n => files[n] === previous.files[n]));
assert(!names.some(n => n.startsWith('internal/loadbalancestream/')));
const archiveSHA = sha(fs.readFileSync(archive)), after = fs.lstatSync(archive);
for (const key of ['dev', 'ino', 'nlink', 'size', 'mode', 'mtimeMs', 'ctimeMs']) assert.equal(after[key], info[key]);
fs.mkdirSync(output, { mode: 0o755 });
for (const n of names) {
  const dest = output + '/' + n;
  fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o755 });
  fs.copyFileSync(source + '/' + n, dest, fs.constants.COPYFILE_EXCL);
  assert.equal(sha(fs.readFileSync(dest)), files[n]);
}
const release = { archive: name, archive_sha256: archiveSHA, frozen_inputs_sha256: index.inputs_sha256 };
const raw = Buffer.from(JSON.stringify({ release, test_overrides: {}, files }, null, 2) + '\n');
const releaseRaw = Buffer.from(JSON.stringify({ ...release, files }, null, 2) + '\n');
fs.writeFileSync(output + '/source-sha256.json', raw, { flag: 'wx', mode: 0o644 });
fs.writeFileSync(output + '/release-source-inputs.json', releaseRaw, { flag: 'wx', mode: 0o644 });
console.log(JSON.stringify({ ok: true, scope, source_inputs: index.inputs_sha256, members: names.length, Go: 1459, production_Go_implementation_changes: 0, source_overlays: 0, index_sha256: sha(raw), release_index_sha256: sha(releaseRaw), release, signed: false, installed: false, all50_commercial: false }));
