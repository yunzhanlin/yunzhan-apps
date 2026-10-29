import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { beforeLoadBalanceStreamBuild } from "./release-build-baseline.mjs";
import { reconcileRuntimeChoices as choose } from "../web/src/runtimeSelection.ts";
const release=(family,version,extra={})=>({id:family+"-"+version,version,channel:"stable",...extra});
const family=(name,releases,extra={})=>({family:name,state:"available",versions:releases.map(x=>x.version),releases,...extra});
const installed=(familyName,r,extra={})=>({id:r.id,family:familyName,version:r.version,status:"installed",...extra});
const snapshot=(catalog,rows=[],extra={})=>({catalog,installed:rows,...extra});
const plain=x=>Object.assign({},x);
test("default uses server recommendation when nothing has been installed",()=>{
 const a=release("nginx","1.30.6"),b=release("nginx","1.32.0");
 assert.equal(choose(snapshot([family("nginx",[a,b])])).selected.nginx,a.id);
 assert.equal(choose(snapshot([family("nginx",[b,a])])).selected.nginx,b.id);
});
test("real installed Nginx replaces obsolete hard-coded install appearance",()=>{
 const old=release("nginx","1.30.4"),current=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[old,current])],[installed("nginx",current)]);
 assert.equal(choose(data).selected.nginx,current.id);
});
test("actual managed active Nginx is shown without implying an automatic switch",()=>{
 const a=release("nginx","1.30.4"),b=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[b,a])],[installed("nginx",a),installed("nginx",b)],{active_nginx:a.id});
 assert.equal(choose(data).selected.nginx,a.id);
 assert.equal(choose({...data,active_nginx:"nginx-unknown"}).selected.nginx,b.id);
});
test("maintained installed PHP wins; affected and EOL remain history, not repaired sites",()=>{
 const old=release("php","8.4.25",{installation_allowed:false,security:{status:"affected"}});
 const eol=release("php","5.6.40",{installation_allowed:false,channel:"eol"});
 const fixed=release("php","8.5.12",{channel:"active",installation_allowed:true});
 const data=snapshot([family("php",[old,eol,fixed])],[installed("php",old),installed("php",fixed),installed("php",eol)]);
 const before=JSON.stringify(data);
 assert.equal(choose(data).selected.php,fixed.id);assert.equal(JSON.stringify(data),before);
 assert.equal(choose({...data,installed:[installed("php",old)]}).selected.php,old.id);
});
test("numeric ordering handles 1.10 vs 1.9 and does not mutate server arrays",()=>{
 const a=release("redis","1.9.99"),b=release("redis","1.10.0");
 const rows=[a,b];Object.freeze(a);Object.freeze(b);Object.freeze(rows);
 const data=snapshot([family("redis",rows)],[installed("redis",a),installed("redis",b)]);
 assert.equal(choose(data).selected.redis,b.id);assert.deepEqual(rows,[a,b]);
});
test("automatic choice follows a completed installation on a later refresh",()=>{
 const a=release("apache","2.4.67"),b=release("apache","2.4.68");
 const data=snapshot([family("apache",[a,b])],[installed("apache",a)]);
 const first=choose(data);
 assert.equal(first.selected.apache,a.id);
 assert.equal(choose({...data,installed:[...data.installed,installed("apache",b)]},first.selected,first.explicit).selected.apache,b.id);
});
test("explicit current choice survives polling and a newer installed version",()=>{
 const a=release("nginx","1.30.4"),b=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[b,a])],[installed("nginx",a),installed("nginx",b)]);
 const current={nginx:a.id},explicit={nginx:a.id};
 const next=choose(data,current,explicit);
 assert.equal(next.selected.nginx,a.id);assert.equal(next.explicit.nginx,a.id);
 assert.deepEqual(current,{nginx:a.id});assert.deepEqual(explicit,{nginx:a.id});
});
test("an explicit uninstalled but installable preview does not submit a request",()=>{
 const a=release("nginx","1.30.4"),b=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[b,a])],[installed("nginx",b)]);
 assert.equal(choose(data,{nginx:a.id},{nginx:a.id}).selected.nginx,a.id);
});
test("removed and unavailable manual choices are not retained as phantom selections",()=>{
 const a=release("nginx","1.30.4",{installation_allowed:false}),b=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[a,b])]);
 assert.equal(choose(data,{nginx:a.id},{nginx:a.id}).selected.nginx,b.id);
 assert.deepEqual(plain(choose(data,{nginx:"nginx-missing"},{nginx:"nginx-missing"}).explicit),{});
});
test("mismatched manual marker cannot pin a programmatic or previous-account choice",()=>{
 const a=release("nginx","1.30.4"),b=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[b,a])],[installed("nginx",b)]);
 const next=choose(data,{nginx:a.id},{nginx:b.id});
 assert.equal(next.selected.nginx,b.id);assert.deepEqual(plain(next.explicit),{});
});
test("uninstalled PHP requires explicit native admission and no affected/EOL status",()=>{
 for(const extra of [{},{installation_allowed:false},{installation_allowed:true,security:{status:"affected"}},{installation_allowed:true,channel:"eol"}]){
  const r=release("php","8.4.25",extra);assert.equal(choose(snapshot([family("php",[r])])).selected.php,undefined);
 }
 const r=release("php","8.4.27",{installation_allowed:true});
 assert.equal(choose(snapshot([family("php",[r])])).selected.php,r.id);
});
test("real installed affected or EOL releases remain inspectable by explicit choice",()=>{
 const old=release("php","7.4.33",{installation_allowed:false,channel:"eol"});
 const current=release("php","8.5.12",{installation_allowed:true});
 const data=snapshot([family("php",[current,old])],[installed("php",old),installed("php",current)]);
 assert.equal(choose(data,{php:old.id},{php:old.id}).selected.php,old.id);
});
test("unsupported family never defaults to an uninstalled release",()=>{
 const r=release("mysql","8.4.11");
 assert.equal(choose(snapshot([family("mysql",[r],{state:"unsupported"})])).selected.mysql,undefined);
 assert.equal(choose(snapshot([family("mysql",[r],{state:"unsupported"})],[installed("mysql",r)])).selected.mysql,r.id);
});
test("unknown, retired, wrong-family and wrong-version rows are not installed authority",()=>{
 const old=release("nginx","1.30.4",{installation_allowed:false}),current=release("nginx","1.30.6");
 for(const extra of[{status:"unknown"},{status:"retired"},{status:"installing"},{family:"apache"},{version:"1.30.5"}]){
  const data=snapshot([family("nginx",[old,current])],[installed("nginx",old,extra)]);
  assert.equal(choose(data).selected.nginx,current.id);
 }
});
test("duplicate installed rows cannot borrow one successful status",()=>{
 const old=release("nginx","1.30.4",{installation_allowed:false}),current=release("nginx","1.30.6");
 const data=snapshot([family("nginx",[old,current])],[installed("nginx",old),installed("nginx",old,{status:"unknown"})]);
 assert.equal(choose(data).selected.nginx,current.id);
});
test("duplicate release/family identities fail closed instead of choosing one copy",()=>{
 const a=release("nginx","1.30.6");
 assert.equal(choose(snapshot([family("nginx",[a,a])],[installed("nginx",a)])).selected.nginx,undefined);
 assert.equal(choose(snapshot([family("nginx",[a]),family("nginx",[a])],[installed("nginx",a)])).selected.nginx,undefined);
});
test("malformed and cross-family identities never become defaults",()=>{
 for(const bad of ["../nginx","nginx\nroot","nginx-"+"1".repeat(130),"apache-2.4.68","__proto__"]){
  const r=release("nginx","1.30.6",{id:bad});assert.equal(choose(snapshot([family("nginx",[r])])).selected.nginx,undefined);
 }
 for(const version of ["not-a-version","1.30.6\n","1".repeat(10)+".0","1.2;id"]){
  const r=release("nginx",version);assert.equal(choose(snapshot([family("nginx",[r])])).selected.nginx,undefined);
 }
});
test("bounded invalid top-level inventories do not invent choices",()=>{
 for(const value of[null,{},snapshot(null),snapshot([],null),snapshot(Array(33).fill(family("nginx",[]))),snapshot([],Array(1025).fill({}))]){
  assert.deepEqual(plain(choose(value).selected),{});
 }
 const r=release("nginx","1.30.6");
 assert.equal(choose(snapshot([family("nginx",Array(257).fill(r))])).selected.nginx,undefined);
});
test("legacy labels remain display-only and never fabricate exact release IDs",()=>{
 const next=choose(snapshot([{family:"python",state:"unavailable",versions:["legacy","3.12.8"]}]));
 assert.equal(next.selected.python,"3.12.8");assert.deepEqual(plain(next.explicit),{});
});
test("selection maps are new null-prototype objects and do not pollute prototypes",()=>{
 const old={polluted:{}.polluted};
 const next=choose(snapshot([{family:"__proto__",state:"available",versions:["1.0"]}]));
 assert.equal(Object.getPrototypeOf(next.selected),null);assert.equal(Object.getPrototypeOf(next.explicit),null);
 assert.deepEqual(plain(next.selected),{});assert.equal({}.polluted,old.polluted);
});
test("all eight current runtime families use server/installed identities, not literals",()=>{
 const names=["nginx","apache","php","mysql","mariadb","redis","node","docker"];
 const catalog=names.map(n=>family(n,[release(n,"2.0.0",{installation_allowed:true}),release(n,"2.1.0",{installation_allowed:true})]));
 const data=snapshot(catalog,catalog.map(f=>installed(f.family,f.releases[1])));
 const selected=choose(data).selected;
 for(const n of names)assert.equal(selected[n],n+"-2.1.0");
});
test("actual component wiring has exactly the reviewed UI-only delta from F55",()=>{
 const path=new URL("../web/src/App.vue",import.meta.url);
 let text=readFileSync(path,"utf8");
 const one=(a,b)=>{assert.equal(text.split(a).length,2,a);text=text.replace(a,()=>b);};
 // The independent country editor adds only current-actor plumbing here.
 one('const securityWorkspaceScope = shallowRef<{\n  actor: string;\n', 'const securityWorkspaceScope = shallowRef<{\n');
 one('    actor: (accessPlan.value as (AccessPlan & {user_id?: string}) | null)?.user_id || "",\n', '');
 one(' :actor="securityWorkspaceScope.actor"', '');
 one('import { reconcileRuntimeChoices } from "./runtimeSelection";\n',"");
 one('  versions.value = {}; explicitRuntimeVersions.value = {};\n',"");
 const block='const versions = ref<Record<string, string>>({});\nconst explicitRuntimeVersions = ref<Record<string, string>>({});\nfunction applyRuntimeChoices(value: Runtimes) {\n  const next = reconcileRuntimeChoices(value, versions.value, explicitRuntimeVersions.value);\n  versions.value = next.selected; explicitRuntimeVersions.value = next.explicit;\n}\nfunction rememberRuntimeVersion(family: string) {\n  explicitRuntimeVersions.value = { ...explicitRuntimeVersions.value, [family]: versions.value[family] };\n  applyRuntimeChoices(runtimes.value);\n}\n';
 const old='const versions = ref<Record<string, string>>({\n  nginx: "nginx-1.30.4",\n  apache: "apache-2.4.68",\n  php: "php-8.4.25",\n  mysql: "mysql-8.4.11",\n  mariadb: "mariadb-11.8.9",\n  redis: "redis-8.2.10",\n  node: "node-24.21.0",\n  docker: "docker-debian-26.1.5",\n});\n';
 one(block,old);
 one('        applyRuntimeChoices(d);\n','        for (const item of d.catalog) {\n          if (item.releases?.length && !item.releases.some(release => release.id === versions.value[item.family])) {\n            versions.value[item.family] = item.releases[0].id;\n          }\n        }\n');
 one('                        @change="rememberRuntimeVersion(rt.family)"\n',"");
 assert.equal(createHash("sha256").update(text).digest("hex"),"a6fa22dd366905f5f1e7a2c1b7ff14c7802762473a29443323dbd9b5befe483a");
});

test("ordinary portable release build requires this regression without changing earlier gates",()=>{
 const path=new URL("../packaging/build-release.sh",import.meta.url),text=readFileSync(path,"utf8");
 const line='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --experimental-strip-types --test scripts/test-runtime-selection.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert.equal(text.split(line).length,2);
 const memoryGate='(cd "$BUILD_ROOT" && /opt/homebrew/bin/node --test scripts/test-runtime-memory-wait.mjs) 2>&1 | tee -a "$STAGE/$NAME/BUILD_CHECKS.txt"\n';
 assert.equal(text.split(memoryGate).length,2);
 const original=beforeLoadBalanceStreamBuild(text).replace(memoryGate,"").replace(line,"");
 assert.equal(createHash("sha256").update(original).digest("hex"),"9efa9a1e0155a8d4c88caf370306191ffa4675011fdd0bb79a282dd9e2ee02c1");
});

