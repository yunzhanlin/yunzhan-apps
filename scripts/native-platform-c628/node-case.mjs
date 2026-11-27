import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer as httpServer, request as httpRequest } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';


process.umask(0o077);
let input='';for await(const chunk of process.stdin){input+=chunk;assert(input.length<8<<20)}const plan=JSON.parse(input);assert(plan.owned_QA&&plan.Main_changes===0&&plan.peers.length===2);

const q = path.dirname(fileURLToPath(import.meta.url));
const read = name => JSON.parse(readFileSync(path.join(q, name)));
const out = mkdtempSync(path.join(plan.out, 'C625-platform-native-paired-TLS-'));
const proof = { ok: false, Main_changed: false, targets: {} };
const sha = value => createHash('sha256').update(value).digest('hex');
const hex = size => randomBytes(size).toString('hex');
const tokenID = hex(8);
const moduleBase = '/api/app-modules/platform-ops/maintenance';
const targetBase = '/api/platform-maintenance';
const saves = (file, value) => writeFileSync(path.join(out, file + '.json'), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
const installed={originals:Object.fromEntries(plan.peers.map(p=>[p.id,{...p.prior,source:p.prior.source_inputs_sha256}]))};
const cleanups = [];
let operation='nginx-check';

function listen(server) {
  cleanups.push(async () => {
    if (server.listening) {
      server.closeAllConnections?.();
      await new Promise(resolve => server.close(resolve));
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject).listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function forwards(peer, options) {
  const child = spawn('/usr/bin/ssh', [...peer.ssh, '-oExitOnForwardFailure=yes', '-N', ...options, peer.target],
    { stdio: ['ignore','ignore','pipe'] });
  cleanups.push(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('close', resolve)), delay(4000)]);
    }
  });
  return child;
}

function remote(peer, code, args = []) {
  const quote = s => "'" + String(s).replaceAll("'", "'\\''") + "'";
  return JSON.parse(execFileSync('/usr/bin/ssh', [...peer.ssh, peer.target,
    ['sudo','-n','/usr/bin/python3','-I','-B','-'].concat(args).map(quote).join(' ')],
    { input: code, encoding: 'utf8', timeout: 45_000 }));
}

function cert(args) {
  execFileSync(plan.openssl, args,
    { cwd: out, stdio: ['ignore','pipe','pipe'], timeout: 15_000 });
}

const trust = String.raw`
import base64, json, os, subprocess, sys
from pathlib import Path
import time, urllib.request
os.umask(0o077)
operation, identity, boot, pin, pem = sys.argv[1:]
assert len(identity) == 16 and all(c in '0123456789abcdef' for c in identity)
assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == pin
fixture = Path('/run/panel-platform-qa-' + identity)
unit = Path('/run/systemd/system/panel.service.d')
drop = unit / ('98-platform-qa-' + identity + '.conf')
roots = fixture / 'roots.pem'
expected = ('[Service]\nEnvironment=SSL_CERT_FILE=' + str(roots) + '\n').encode()
if operation == 'add':
    assert not drop.exists() and not fixture.exists()
    fixture.mkdir(mode=0o755)
    fixture.chmod(0o755)
    with roots.open('xb') as f:
        f.write(Path('/etc/ssl/certs/ca-certificates.crt').read_bytes() + b'\n' + base64.b64decode(pem, validate=True))
    roots.chmod(0o644)
    unit.mkdir(mode=0o755, exist_ok=True)
    with drop.open('xb') as f:
        f.write(expected)
    drop.chmod(0o644)
elif operation == 'remove':
    if drop.exists():
        assert not drop.is_symlink() and drop.read_bytes() == expected
        drop.unlink()
else:
    raise ValueError(operation)
subprocess.run(['systemctl','daemon-reload'], check=True, timeout=15)
subprocess.run(['systemctl','restart','panel.service'], check=True, timeout=15)
for attempt in range(20):
    try:
        with urllib.request.urlopen('http://127.0.0.1:19100/', timeout=1) as res:
            assert res.status == 200
            break
    except (OSError, urllib.error.URLError):
        if attempt == 19:
            raise
        time.sleep(0.25)
if operation == 'remove' and fixture.exists():
    if roots.exists():
        assert roots.is_file() and not roots.is_symlink()
        roots.unlink()
    fixture.rmdir()
print(json.dumps({'ok': True, 'removed': not drop.exists()}))
`;

const snapshotCode = String.raw`
import hashlib,json,platform,sqlite3,subprocess,sys
from pathlib import Path
boot, source, operation = sys.argv[1:]
assert Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot
assert json.loads(Path('/opt/panel/current/SOURCE_INPUTS.json').read_bytes())['inputs_sha256'] == source
pid = int(subprocess.check_output(['systemctl','show','-p','MainPID','--value','nginx.service'], text=True).strip())
assert pid > 1
process = Path('/proc') / str(pid)
binary = (process / 'exe').resolve(strict=True)
start = (process / 'stat').read_text().rsplit(')',1)[1].split()[19]
conf = subprocess.check_output([str(binary),'-T'], stderr=subprocess.DEVNULL, timeout=12)
workers = sorted(int(p) for p in (process/'task'/str(pid)/'children').read_text().split())
with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True,timeout=12) as db:
    fields = {name: hashlib.sha256(repr(db.execute(query).fetchall()).encode()).hexdigest() for name,query in {
       'sites':'SELECT * FROM sites ORDER BY id',
       'runtimes':'SELECT id,version_id,binary_path,architecture,status FROM runtime_installations ORDER BY id',
       'apps':'SELECT * FROM app_registry_receipts ORDER BY app_id,scope'
    }.items()}
    commands = []
    if operation:
        commands = db.execute('SELECT request_sha,state,record FROM platform_maintenance_operations WHERE request_id=?',(operation,)).fetchall()
    receipts = []
    if operation:
        for ext in ('.request.json','.result.json'):
            p = Path('/var/lib/panel-executor/platform-maintenance-jobs') / (operation+ext)
            meta = p.lstat()
            assert meta.st_uid == 0 and meta.st_mode & 0o077 == 0 and meta.st_nlink == 1 and not p.is_symlink()
            receipts.append(hashlib.sha256(p.read_bytes()).hexdigest())
print(json.dumps({'pid':pid,'start':start,'workers':workers,'configuration':hashlib.sha256(conf).hexdigest(),'data':fields,
                  'commands':[(a,b,hashlib.sha256(c.encode()).hexdigest()) for a,b,c in commands],
                  'root_receipts':receipts,'architecture':platform.machine()}))
`;

let unexpectedResponses=0;
async function api(peer, route, payload, status = 200) {
  const method = payload === undefined ? 'get' : 'post';
  const r = await peer.session[method](peer.origin + route, {
    ...(payload === undefined ? {} : { data: payload }), maxRedirects: 0, timeout:route.startsWith('/api/app-registry')?90_000:38_000,
    headers: { Origin: peer.origin, 'X-CSRF-Token': peer.csrf ?? '' },
  });
  if(r.status()!==status){const v=await r.json();saves('original-unexpected-response-'+(unexpectedResponses++),{peer:peer.arch,route,status:r.status(),expected:status,error:typeof v.error==='string'?v.error:'No public error'});assert.equal(r.status(),status,peer.arch+' '+route)}
  return r.json();
}

function fixtureRelay(peer, upstream, secure) {
  const handler = (req, res) => {
    const route = req.url ?? '';
    if (!route.startsWith('/') || route.startsWith('//') ||
        secure && ![targetBase + '/plan',targetBase + '/commands','/api/platform/agent'].includes(route) &&
        !new RegExp('^' + targetBase + '/commands/[a-f0-9]{32}$').test(route)) {
      res.writeHead(404).end();
      return;
    }
    const headers = { ...req.headers, host: '127.0.0.1:19100' };
    if (headers.origin) headers.origin = 'http://127.0.0.1:19100';
    if (secure) {
      delete headers.cookie;
      delete headers.origin;
    }
    const r = httpRequest({ hostname: '127.0.0.1', port: upstream, method: req.method, path: route, headers }, reply => {
      if (secure) {
        peer.inbound.push({ method: req.method, route, status: reply.statusCode, tls: req.socket.getProtocol() });
        if (peer.dropReply && req.method === 'POST' && route === targetBase + '/commands') {
          peer.dropReply = false;
          reply.resume();
          reply.once('end', () => res.destroy());
          return;
        }
      }
      res.writeHead(reply.statusCode, reply.headers);
      reply.pipe(res);
    });
    r.on('error', () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(r);
  };
  return secure ? httpsServer({ key: readFileSync(path.join(out,'server.key')), cert: readFileSync(path.join(out,'server.pem')),
    minVersion: 'TLSv1.2' }, handler) : httpServer(handler);
}

async function reLogin(peer){
  if(peer.csrf)await api(peer,'/api/logout',{}).catch(()=>{});
  peer.cookie='';peer.csrf='';
  const login=remote(peer,"import json\nprint(json.dumps({k:v for k,v in json.load(open('/etc/panel/first-login.json')).items() if k in ('username','password')}))");
  try{peer.csrf=(await api(peer,'/api/login',login)).csrf;assert(peer.csrf)}finally{login.password=''}
}
async function connect(id){
  const setup=plan.peers.find(p=>p.id===id);assert(setup&&setup.owned_QA&&setup.prior.ok&&setup.prior.version==='1.3.1');
  const options=setup.ssh.slice(1,-1);const filtered=[];
  for(let i=0;i<options.length;i++){if(options[i]==='-o'&&options[i+1]==='LogLevel=ERROR'){i++;continue}filtered.push(options[i])}
  const peer={arch:id,native_arch:setup.architecture,prior:installed.originals[id],target:setup.ssh.at(-1),inbound:[],ssh:filtered,cookie:''};
  const temp=httpServer();const port=await listen(temp);await new Promise(resolve=>temp.close(resolve));assert.notEqual(port,19100);
  const tunnel=forwards(peer,['-L','127.0.0.1:'+port+':127.0.0.1:19100']);const proxyPort=await listen(fixtureRelay(peer,port,false));peer.origin='http://127.0.0.1:'+proxyPort;peer.tlsPort=await listen(fixtureRelay(peer,port,true));
  for(let attempt=0;attempt<40;attempt++){assert.equal(tunnel.exitCode,null);try{if((await fetch(peer.origin+'/')).ok)break}catch{}assert(attempt<39);await delay(250)}
  const call=async(method,url,options)=>{
    const r=await fetch(url,{method,redirect:'error',signal:AbortSignal.timeout(options.timeout??38000),headers:{...options.headers,...(peer.cookie?{Cookie:peer.cookie}:{}),...(options.data===undefined?{}:{'Content-Type':'application/json'})},...(options.data===undefined?{}:{body:JSON.stringify(options.data)})});
    const cookies=r.headers.getSetCookie();if(cookies.length)peer.cookie=cookies.map(x=>x.split(';',1)[0]).join('; ');return{status:()=>r.status,json:()=>r.json()};
  };
  peer.session={get:(url,options)=>call('GET',url,options),post:(url,options)=>call('POST',url,options),dispose:async()=>{}};
  cleanups.push(async()=>{if(peer.csrf)await api(peer,'/api/logout',{}).catch(()=>{});peer.cookie='';peer.csrf=''});await reLogin(peer);
  const catalogue=await api(peer,'/api/app-registry');saves('ordinary-'+id+'-current-signed-store-observation',catalogue);assert.equal(catalogue.catalog.apps.length,40);const originalCache=remote(peer,"from pathlib import Path\nimport hashlib,json,os,pwd,stat\np=Path('/var/lib/panel/app-registry/catalog/catalog-v1.bundle.json');s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()and s.st_nlink==1 and s.st_uid==pwd.getpwnam('panel').pw_uid and stat.S_IMODE(s.st_mode)==0o600\nraw=p.read_bytes();assert len(raw)<1<<20;bundle=json.loads(raw);assert set(bundle)=={'catalog','signature'};payload=bundle['catalog'].encode();expected='c4860ba82898bd9f4f15644ea1b6839f4af99b6234dbd0f211f78c3090fc69be';assert hashlib.sha256(payload).hexdigest()==expected;c=json.loads(payload);assert len(c['apps'])==40;app=next(a for a in c['apps']if a['id']=='platform-ops');assert app['version']=='1.3.1'and app['sha256']=='ac1f9da58bd25e563ea2fdd6be43f071bfbe25823a7017eb41a69fb31be58ae5';print(json.dumps({'ok':True,'original_signed_catalogue_payload_sha256':expected,'original_verified_cache_bundle_sha256':hashlib.sha256(raw).hexdigest(),'app_version':app['version'],'manifest_sha256':app['sha256'],'active_apps':40,'cache_readonly':True,'fresh_remote_head_not_claimed':True}))\n");saves('ordinary-'+id+'-original-signed-cache-binding',originalCache);assert(originalCache.ok);if(catalogue.source.source==='github'){assert.equal(catalogue.source.resolved_commit,'16eca3277e3846c38d2a075f35c4dd27827261bf');assert(!catalogue.source.stale)}else assert.equal(catalogue.source.source,'verified-cache');const current=catalogue.status.find(x=>x.id==='platform-ops');assert(current.state_known&&current.installed&&current.installed_version==='1.3.1'&&!current.update_available);
  const module=await api(peer,'/api/app-modules/platform-ops');assert(module.status.healthy&&module.status.version===peer.prior.version&&module.status.installation_id===peer.prior.installation_id);const actual=snapshot(peer);assert.equal(actual.architecture,setup.architecture==='arm64'?'aarch64':'x86_64');
  return peer;
}

function reverse(source, target) {
  const child = forwards(source, ['-R','127.0.0.1:0:127.0.0.1:' + target.tlsPort]);
  return new Promise((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(() => reject(Error('SSH reverse tunnel did not allocate a port')), 12000);
    const stop = () => { clearTimeout(timeout); reject(Error('SSH reverse tunnel exited')); };
    child.once('exit', stop);
    child.stderr.on('data', chunk => {
      output = (output + chunk.toString()).slice(-4096);
      const match = output.match(/Allocated port ([0-9]+) for remote forward/);
      if (!match) return;
      clearTimeout(timeout); child.off('exit', stop);
      assert.notEqual(Number(match[1]),19100);
      resolve('https://127.0.0.1:' + match[1]);
    });
  });
}

function snapshot(peer, requestID = '') {
  return remote(peer, snapshotCode, [peer.prior.boot, peer.prior.source, requestID]);
}

async function exercise(source, target, url) {
  const before = snapshot(target);
  const upstreamStart = target.inbound.length;
  const grant = await api(target,moduleBase + '/grants',
    {commands:[operation],minutes:5,confirm:'GRANT NGINX MAINTENANCE'},201);
  assert.equal(sha(grant.token),grant.grant_id);
  assert.equal(grant.installation_id,target.prior.installation_id);
  let revoked = false;
  cleanups.push(async () => {
    if (!revoked) await api(target,moduleBase + '/grants/' + grant.grant_id + '/revoke',{}).catch(() => {});
    grant.token = '';
  });
  const endpoint = moduleBase + '/remote';
  const planInput = { url, token: grant.token };
  if(!source.qaTrustEnabled){await api(source,endpoint + '/plan',planInput,503);assert.equal(target.inbound.length,upstreamStart);source.qaUntrustedVerified=true}
  await ensureTrust(source);
  const plan = await api(source,endpoint + '/plan',planInput);
  assert.deepEqual(plan.allowed_commands,[operation]);
  assert.equal(plan.grant_id,grant.grant_id);
  const requestID = hex(16);
  const submitted = {request_id:requestID,command:operation,expected_plan_sha256:plan.plan.sha256,
    confirm:operation === 'nginx-reload' ? 'RELOAD NGINX ' + plan.plan.sha256 : ''};
  const ticket = {...planInput,actor_id:plan.actor_id,operation:submitted};
  saves('original-' + target.arch + '-'+operation+'-request', {request:submitted,source:source.arch,target:target.arch,
    grant_id:grant.grant_id, maximum_dispatches:1});
  target.dropReply = true;
  await api(source,endpoint + '/commands',ticket,503);
  const afterDrop = target.inbound.slice(upstreamStart).filter(entry => entry.method === 'POST' && entry.route === targetBase + '/commands').length;
  assert.equal(afterDrop,1);
  const found = await api(source,endpoint + '/commands/status',ticket);
  assert.equal(found.state,'completed');
  assert.equal(found.outcome,operation === 'nginx-check' ? 'config_valid' : 'reload_signal_submitted');
  assert.deepEqual(found.request,{format:1,grant_id:grant.grant_id,actor_id:plan.actor_id,input:submitted});
  assert.equal(found.request_sha256,sha(JSON.stringify(found.request)));
  assert.deepEqual(await api(source,endpoint + '/commands/status',ticket),found);
  const after = snapshot(target,requestID);
  assert.equal(after.pid,before.pid);
  assert.equal(after.start,before.start);
  assert.equal(after.configuration,before.configuration);
  assert.deepEqual(after.data,before.data);
  assert.equal(after.commands.length,1);
  assert.deepEqual(after.commands[0].slice(0,2),[found.request_sha256,'completed']);
  assert.equal(after.root_receipts.length,2);
  if (operation === 'nginx-reload') assert(after.workers.some(pid => !before.workers.includes(pid)));
  else assert.deepEqual(after.workers,before.workers);
  const revoke = await api(target,moduleBase + '/grants/' + grant.grant_id + '/revoke',{});
  assert.equal(revoke.revoked,true);
  revoked = true;
  await api(source,endpoint + '/plan',planInput,503);
  assert(target.inbound.some(entry => entry.route === targetBase + '/plan' && entry.status === 401));
  assert.equal(target.inbound.slice(upstreamStart).filter(entry => entry.method === 'POST' && entry.route === targetBase + '/commands').length,1);
  assert(target.inbound.every(entry => ['TLSv1.2','TLSv1.3'].includes(entry.tls)));
  assert(source.qaTrustEnabled&&source.qaUntrustedVerified);
  grant.token = ''; planInput.token = ''; ticket.token = '';
  return { request_id:requestID, source:source.arch, target:target.arch, outcome:found.outcome,
    untrusted_certificate_refused:source.qaUntrustedVerified, revoked_authorization_refused:true, original_once_after_lost_response:true,
    root_receipts:after.root_receipts, nginx_same_master_and_configuration:true,
    new_worker_generation:operation === 'nginx-reload', before, after, tls:target.inbound };
}

async function ensureTrust(source){
 if(source.qaTrustEnabled)return;
 const pem=readFileSync(path.join(out,'ca.pem')).toString('base64');const args=change=>[change,tokenID,source.prior.boot,source.prior.source,pem];
 assert(remote(source,trust,args('add')).ok);source.qaTrustEnabled=true;await reLogin(source);
 cleanups.push(async()=>{if(source.qaTrustEnabled){assert(remote(source,trust,args('remove')).removed);source.qaTrustEnabled=false}});
}
async function withTrust(source,body){await ensureTrust(source);return body()}

async function exerciseFleet(source, targets, addresses){
 assert.equal(targets.length,2);assert.notEqual(targets[0].prior.installation_id,targets[1].prior.installation_id);assert.notEqual(addresses[0],addresses[1]);
 return withTrust(source,async()=>{
  const grants=[],revoked=[];for(const target of targets){const grant=await api(target,moduleBase+'/grants',{commands:['nginx-check'],minutes:10,confirm:'GRANT NGINX MAINTENANCE'},201);assert.equal(sha(grant.token),grant.grant_id);assert.equal(grant.installation_id,target.prior.installation_id);grants.push(grant);revoked.push(false);const i=grants.length-1;cleanups.push(async()=>{if(!revoked[i]){await api(target,moduleBase+'/grants/'+grant.grant_id+'/revoke',{});revoked[i]=true}grant.token=''})}
  const before=targets.map(p=>snapshot(p)),starts=targets.map(p=>p.inbound.length),tickets=[];
  for(let i=0;i<2;i++){const checked=await api(source,moduleBase+'/remote/plan',{url:addresses[i],token:grants[i].token});assert.deepEqual(checked.allowed_commands,['nginx-check']);tickets.push({url:addresses[i],token:grants[i].token,actor_id:checked.actor_id,operation:{request_id:hex(16),command:'nginx-check',expected_plan_sha256:checked.plan.sha256,confirm:''}})}
  const duplicated=[tickets[0],{...tickets[0],operation:{...tickets[0].operation,request_id:hex(16)}}];await api(source,moduleBase+'/remote/fleet/checks',{targets:duplicated},400);assert(targets.every((p,i)=>p.inbound.slice(starts[i]).filter(x=>x.method==='POST'&&x.route===targetBase+'/commands').length===0));
  saves('original-native-fleet-intent',{ids:tickets.map(x=>x.operation.request_id),target_installations:targets.map(x=>x.prior.installation_id),maximum_dispatches_per_target:1,duplicate_target_rejected_before_dispatch:true});targets[1].dropReply=true;
  const result=await api(source,moduleBase+'/remote/fleet/checks',{targets:tickets});assert.equal(result.all_succeeded,false);assert.deepEqual(result.results.map(x=>[x.request_id,x.state]),tickets.map((x,i)=>[x.operation.request_id,i===0?'completed':'needs_attention']));
  const found=[],after=[];for(let i=0;i<2;i++){const row=await api(source,moduleBase+'/remote/commands/status',tickets[i]);assert.equal(row.state,'completed');assert.equal(row.outcome,'config_valid');found.push(row);const current=snapshot(targets[i],tickets[i].operation.request_id);after.push(current);for(const key of ['pid','start','workers','configuration','data'])assert.deepEqual(current[key],before[i][key]);assert.equal(current.commands.length,1);assert.equal(current.root_receipts.length,2);assert.equal(targets[i].inbound.slice(starts[i]).filter(x=>x.method==='POST'&&x.route===targetBase+'/commands').length,1)}
  for(let i=0;i<2;i++){assert.equal((await api(targets[i],moduleBase+'/grants/'+grants[i].grant_id+'/revoke',{})).revoked,true);revoked[i]=true;tickets[i].token='';grants[i].token=''}
  return{ok:true,distinct_native_target_installations:true,duplicate_target_refused_before_dispatch:true,original_request_ids:tickets.map(x=>x.operation.request_id),mixed_original_batch_states:result.results,actual_readonly_recovery:found.map(x=>({state:x.state,outcome:x.outcome,request_sha256:x.request_sha256})),each_native_dispatch_count:1,before,after,root_receipts:after.map(x=>x.root_receipts),no_auto_replay:true};
 });
}
const storedHostCode=String.raw`
import hashlib,json,sqlite3,sys
id,token_hash=sys.argv[1:]
with sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True)as db:
 db.execute('PRAGMA query_only=ON');r=db.execute('SELECT id,url,token,created_at FROM app_platform_hosts WHERE id=?',(id,)).fetchone()
 if r is None:print(json.dumps({'absent':True}))
 else:
  data=r[2];assert isinstance(data,bytes)and len(data)>64 and hashlib.sha256(data).hexdigest()!=token_hash
  print(json.dumps({'id':r[0],'url':r[1],'ciphertext_bytes':len(data),'ciphertext_sha256':hashlib.sha256(data).hexdigest(),'created_at':r[3],'plaintext_not_stored':True}))
`;
async function exerciseHealth(source,target,address){
 const base='/api/app-modules/platform-ops',id='c612-owned-health-peer';const initial=snapshot(target);let revoked=false;const issued=await api(target,base+'/issue-token',{});assert(/^[a-f0-9]{64}$/.test(issued.token)&&sha(issued.token)===issued.token_id&&issued.scope==='health-read-only');cleanups.push(async()=>{if(!revoked){await api(target,base+'/revoke-token',{token_id:issued.token_id});revoked=true}issued.token=''});
 const list=await api(target,base+'/token-list',{});assert(list.tokens.some(x=>x.token_id===issued.token_id));
 await api(source,base+'/add',{resource_id:id,url:address.replace('https:','http:'),token:issued.token},409);assert(remote(source,storedHostCode,[id,issued.token_id]).absent);
 const added=await api(source,base+'/add',{resource_id:id,url:address,token:issued.token});assert(/^[a-f0-9]{64}$/.test(added.expected_sha));const saved=remote(source,storedHostCode,[id,issued.token_id]);const inboundStart=target.inbound.length;const untrusted=await api(source,base+'/run',{});assert.equal(untrusted.hosts.length,1);assert.equal(untrusted.hosts[0].healthy,false);assert.equal(target.inbound.length,inboundStart);source.qaUntrustedVerified=true;
 return withTrust(source,async()=>{
  const healthy=await api(source,base+'/run',{});saves('original-real-trusted-health-response',healthy);assert.equal(healthy.hosts.length,1);assert(healthy.hosts[0].healthy&&healthy.hosts[0].report.health.nginx_active===true);assert.equal(healthy.hosts[0].expected_sha,added.expected_sha);
  await api(source,base+'/add',{resource_id:id,url:address,token:issued.token,expected_sha:'0'.repeat(64)},409);assert.deepEqual(remote(source,storedHostCode,[id,issued.token_id]),saved);
  const changed=await api(source,base+'/add',{resource_id:id,url:address,token:issued.token,expected_sha:added.expected_sha});const updated=remote(source,storedHostCode,[id,issued.token_id]);assert.equal(updated.created_at,saved.created_at);assert.notEqual(updated.ciphertext_sha256,saved.ciphertext_sha256);assert.notEqual(changed.expected_sha,added.expected_sha);
  await api(source,base+'/remove',{resource_id:id,expected_sha:added.expected_sha},409);assert.deepEqual(remote(source,storedHostCode,[id,issued.token_id]),updated);await api(source,base+'/remove',{resource_id:id,expected_sha:changed.expected_sha});assert(remote(source,storedHostCode,[id,issued.token_id]).absent);const empty=await api(source,base+'/run',{});assert.deepEqual(empty.hosts,[]);
  const retained=await api(source,base+'/add',{resource_id:id,url:address,token:issued.token});assert((await api(source,base+'/run',{})).hosts[0].healthy);const encrypted=remote(source,storedHostCode,[id,issued.token_id]);assert(encrypted.plaintext_not_stored);
  assert.equal((await api(target,base+'/revoke-token',{token_id:issued.token_id})).revoked,true);revoked=true;const denied=await api(source,base+'/run',{});assert.equal(denied.hosts[0].healthy,false);assert.equal(denied.hosts[0].status,401);const endlist=await api(target,base+'/token-list',{});assert(!endlist.tokens.some(x=>x.token_id===issued.token_id));const after=snapshot(target);for(const key of ['pid','start','workers','configuration','data'])assert.deepEqual(after[key],initial[key]);const tls=target.inbound.slice(inboundStart);assert(tls.some(x=>x.route==='/api/platform/agent'&&x.status===200)&&tls.some(x=>x.route==='/api/platform/agent'&&x.status===401)&&tls.every(x=>['TLSv1.2','TLSv1.3'].includes(x.tls)));issued.token='';
  return{ok:true,health_only_token_id:issued.token_id,trusted_real_TLS_health:true,untrusted_certificate_and_HTTP_refused:true,actual_readonly_health_revoke_HTTP401:true,stale_host_CAS_refused:true,actual_host_add_update_remove_and_readd:true,encrypted_host_secret_and_created_at_verified:true,retained_host:{id,expected_sha:retained.expected_sha,...encrypted},nginx_original_master_workers_config_and_business_preserved:true,tls};
 });
}

try {
  cert(['req','-x509','-new','-newkey','rsa:2048','-nodes','-sha256','-days','1','-subj','/CN=Owned platform ops QA CA',
    '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign','-keyout','ca.key','-out','ca.pem']);
  cert(['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=127.0.0.1','-keyout','server.key','-out','server.csr']);
  writeFileSync(path.join(out,'server.ext'),'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n',{flag:'wx'});
  cert(['x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1',
    '-sha256','-extfile','server.ext','-out','server.pem']);
  saves('intent',{ operation, maximum_dispatches_per_target:1, host_cas_changed:false, vm_authority_runtime_only:true,
    catalog_receipts:installed.originals, Main_changed:false });
  const first=await connect(plan.peers[0].id),second=await connect(plan.peers[1].id);assert.notEqual(first.prior.installation_id,second.prior.installation_id);
  proof.health=await exerciseHealth(first,second,await reverse(first,second));
  for(const cmd of ['nginx-check','nginx-reload']){operation=cmd;proof.targets[first.arch+'-to-'+second.arch+'-'+cmd]=await exercise(first,second,await reverse(first,second));proof.targets[second.arch+'-to-'+first.arch+'-'+cmd]=await exercise(second,first,await reverse(second,first));}
  proof.fleet=await exerciseFleet(first,[first,second],[await reverse(first,first),await reverse(first,second)]);
  assert(proof.fleet.ok&&proof.health.ok);
  proof.ok = true;
} catch (error) {
  proof.failure = { message: String(error.message).split('\n')[0], location:String(error.stack).split('\n').filter(line=>/^\s*at /.test(line)).slice(0,5) };
} finally {
  for (const cleanup of cleanups.reverse()) {
    try { await cleanup(); } catch (cleanupError) { proof.cleanup_unverified=true;proof.cleanup_failures??=[];proof.cleanup_failures.push({message:String(cleanupError.message).split('\n')[0],location:String(cleanupError.stack).split('\n').slice(1,3)});proof.ok=false; }
  }
  saves('original-proof',proof);
}
console.log(JSON.stringify({...proof,out,native_architecture:plan.peers[0].architecture,Main_changes:0,all40_commercial:false}));
process.exitCode=proof.ok?0:1;
