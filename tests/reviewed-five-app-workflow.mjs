// Exact reviewed metadata ABI adapter; not a production capability override.
import assert from'node:assert/strict';
import{createHash}from'node:crypto';
export const historicalScope='registry/reviewed-catalogs/before-php-security24bkhe';
export const original34WorkflowSHA='beb05395b72dd5891329f3b8a15a09d8d3b75aa65ca3f506fe3e73c1aa77642d';
export const original34RootCalls=[
  {
    "job": "mobile-delivery-native-amd64",
    "line": "        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "php-security-native-amd64",
    "line": "        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "runtime-memory-native-amd64",
    "line": "        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "php-bounded-native-amd64",
    "line": "          sudo \"$(command -v go)\" test -race ./internal/appcatalog -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "php-bounded-native-amd64",
    "line": "        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "apache-noop-native-amd64",
    "line": "        run: sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^Test(PHP(Bounded|Security)|PublishedRepositoryCurrentSignedManifestABI)' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "module-version-native-amd64",
    "line": "          sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  },
  {
    "job": "redis-cli-native-amd64",
    "line": "          sudo \"$(command -v go)\" test -json ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -args -published-app-registry-root \"$GITHUB_WORKSPACE\""
  }
];
const oldBoundary='        run: node tools/verify-mobile-delivery-handler-boundary.mjs';
const newBoundary=oldBoundary+' --repo-root '+historicalScope;
const oldFlag='-published-app-registry-root "$GITHUB_WORKSPACE"';
const newFlag='-published-app-registry-root "$GITHUB_WORKSPACE/'+historicalScope+'"';
export const currentF48ABICommand="          sudo \"$(command -v go)\" test -p 1 ./internal/appcatalog -run '^TestPublishedRepositoryCurrentSignedManifestABI$' -count=1 -published-app-registry-root \"$GITHUB_WORKSPACE\"";
export const originalF47NegativeCommand="          sudo \"$(command -v node)\" \"$GITHUB_WORKSPACE/tools/verify-memcached-retirement-handler-boundary.mjs\" \"$(command -v go)\"";
export const originalPHPSchemaCommand="          YUNZHAN_SCHEMA_PYTHON=\"$GITHUB_WORKSPACE/.local/php-bounded-schema/bin/python\" node tools/check-php-security-schema.mjs";
export const currentUnixSchemaCommand="          YUNZHAN_SCHEMA_PYTHON=\"$GITHUB_WORKSPACE/.local/php-bounded-schema/bin/python\" node tools/check-memcached-unix-schema.mjs";
const digest=b=>createHash('sha256').update(b).digest('hex');
function exactJobs(bytes){const text=bytes.toString(),start=text.indexOf('\njobs:\n');assert(start>0);return text.slice(start).split('\n').filter(s=>/^  [a-z0-9-]+:$/.test(s));}
export function prepareFiveAppHistoricalWorkflow(bytes){
 assert(Buffer.isBuffer(bytes)&&digest(bytes)===original34WorkflowSHA,'Only actual previous34-job bytes may be scoped');
 const text=bytes.toString();let job,count=0;
 const lines=text.split('\n').map(line=>{
  const m=line.match(/^  ([a-z0-9-]+):$/);if(m)job=m[1];
  const plan=original34RootCalls.find(p=>p.job===job&&p.line===line);
  if(plan){count++;assert.equal(line.split(oldFlag).length,2);return line.replace(oldFlag,()=>newFlag);}
  if(line===oldBoundary){assert.equal(job,'mobile-delivery-native-amd64');return newBoundary;}
  return line;
 });
 assert.equal(count,8);assert.equal(text.split(oldBoundary).length,2);assert.equal(original34RootCalls.length,8);
 let scoped=lines.join('\n');assert.equal(scoped.split(currentF48ABICommand).length,2);scoped=scoped.replace(currentF48ABICommand,()=>currentF48ABICommand+'\n'+originalF47NegativeCommand);
 assert.equal(scoped.split(originalPHPSchemaCommand).length,2);scoped=scoped.replace(originalPHPSchemaCommand,()=>originalPHPSchemaCommand+'\n'+currentUnixSchemaCommand);
 const out=Buffer.from(scoped);assert.deepEqual(exactJobs(out),exactJobs(bytes));return out;
}
export function originalReviewedFiveAppHistoricalWorkflow(bytes){
 const wasBuffer=Buffer.isBuffer(bytes);
 if(digest(bytes)===original34WorkflowSHA)return bytes;
 const raw=bytes.toString();if(!raw.includes(newFlag)&&!raw.includes(newBoundary)&&!raw.includes(originalF47NegativeCommand)&&!raw.includes(currentUnixSchemaCommand))return bytes;
 assert.equal(raw.split('\n'+originalF47NegativeCommand).length,2);assert.equal(raw.split('\n'+currentUnixSchemaCommand).length,2);bytes=Buffer.from(raw.replace('\n'+originalF47NegativeCommand,()=>'').replace('\n'+currentUnixSchemaCommand,()=>''));
 let job,count=0,boundaries=0;
 const lines=bytes.toString().split('\n').map(line=>{
  const m=line.match(/^  ([a-z0-9-]+):$/);if(m)job=m[1];
  const plan=original34RootCalls.find(p=>p.job===job&&p.line.replace(oldFlag,()=>newFlag)===line);
  if(plan){count++;return plan.line;}
  if(job==='mobile-delivery-native-amd64'&&line===newBoundary){boundaries++;return oldBoundary;}
  return line;
 });
 assert.equal(count,8);assert.equal(boundaries,1);
 const restored=Buffer.from(lines.join('\n'));assert.equal(digest(restored),original34WorkflowSHA,'Every other original assertion, deadline and command byte must remain exact');return wasBuffer?restored:restored.toString();
}
