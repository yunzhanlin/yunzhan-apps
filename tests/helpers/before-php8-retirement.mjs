// Immutable C208 acceptance inputs only. Production and active-store tests use current files.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../../',import.meta.url));
const base=path.join(root,'tests/fixtures/before-php8-retirement');
const indexRaw=fs.readFileSync(path.join(base,'snapshot-index.json'));
assert.equal(createHash('sha256').update(indexRaw).digest('hex'),'ab2a6748ee2331693f346b30a71c60767c0a16f53a78e43f2bcfe34db5f85168');
const index=JSON.parse(indexRaw);
assert.equal(index.source_revision,'8fc0034f031a3a9191c8f93a1f7fa9c708a526d6');
function historical(file) {
 if(typeof file!=='string'&&!(file instanceof URL))return file;
 const absolute=file instanceof URL?fileURLToPath(file):path.resolve(file);
 const relative=path.relative(root,absolute).split(path.sep).join('/');
 if(!Object.hasOwn(index.files,relative))return file;
 const target=path.join(base,relative),raw=fs.readFileSync(target),st=fs.lstatSync(target);
 assert(st.isFile()&&!st.isSymbolicLink()&&st.nlink===1);
 assert.equal(createHash('sha256').update(raw).digest('hex'),index.files[relative],relative);
 return target;
}
export const readFile=(file,...args)=>fsp.readFile(historical(file),...args);
const historicalFS={...fs,readFileSync:(file,...args)=>fs.readFileSync(historical(file),...args)};
export default historicalFS;

export const readdir=(...args)=>fsp.readdir(...args);
export const lstat=(...args)=>fsp.lstat(...args);
