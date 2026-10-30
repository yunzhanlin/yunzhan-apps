import test from'node:test';import assert from'node:assert/strict';import fs from'node:fs';
import {createHash} from 'node:crypto';
import {beforeLoadBalanceStreamBuild} from './release-build-baseline.mjs';
const main=fs.readFileSync(new URL('../cmd/executor/main.go',import.meta.url),'utf8'),unit=fs.readFileSync(new URL('../dev/panel-lbstream-account-create@.service',import.meta.url),'utf8');
test('build baseline cannot hide removed gates, missing source binding or unknown changes',()=>{
 const text=fs.readFileSync(new URL('../packaging/build-release.sh',import.meta.url),'utf8');
 const digest=v=>createHash('sha256').update(v).digest('hex');
 const baseline=beforeLoadBalanceStreamBuild(text);
 assert.equal(digest(baseline),'af902f50fc54ec540a221761930cecadd721fad248e31de3de456955a9c7e681');
 for(const required of ['APP_CHANNEL="${3:-stable}"', 'APP_CHANNEL" != stable && "$APP_CHANNEL" != candidate', '"$VERSION" != *candidate*', 'PROGRAMME_INPUTS_SHA=', 'PANEL_LDFLAGS=', 'scripts/test-load-balance-stream.mjs', 'scripts/test-load-balance-stream-account-entry.mjs', 'go test -c -ldflags="$EXECUTOR_LDFLAGS"', 'go build -trimpath -ldflags="$EXECUTOR_LDFLAGS"', 'go build -trimpath -ldflags="$PANEL_LDFLAGS"']){
  assert.throws(()=>beforeLoadBalanceStreamBuild(text.replace(required,'REMOVED')));
 }
 assert.notEqual(digest(beforeLoadBalanceStreamBuild(text.replace('go vet ./...','true'))),digest(baseline));
 for (const required of ['"$BUILD_ROOT/packaging/fresh-ssh-policy.py"', 'first-install.py fresh-ssh-policy.py waf-state-directory.py', "<<'PY_CHECK_INSTALLER_HELPERS'", 'value.st_nlink != 1', "print('packaged installer helpers verified: '"]) {
  assert.throws(()=>beforeLoadBalanceStreamBuild(text.replace(required,'REMOVED')));
 }
 for (const required of ['./internal/upgraderead', '$NAME.upgraderead-tests.sha256', '$STAGE/upgraderead-tests']) {
  assert.throws(()=>beforeLoadBalanceStreamBuild(text.replace(required,'REMOVED')));
 }
});
test('fixed account CLI rejects aliases and mixed arguments before dispatch',()=>{
 assert(main.includes('flag.String("load-balance-stream-account-job", ""'));
 const begin=main.indexOf('if lbStreamAccountEntry {'),end=main.indexOf('memcachedUnixAccountEntry := false');assert(begin>0&&end>begin);const entry=main.slice(begin,end);
 assert(entry.includes('len(os.Args) != 2 || os.Args[1] != "--load-balance-stream-account-job="+*lbStreamAccountJob'));
 assert(entry.includes('executor.RunLoadBalanceStreamAccountJob(*lbStreamAccountJob)'));assert(!entry.includes('exec.Command')&&!entry.includes('os.Getenv'));
});
test('fixed child unit has a live parent dependency and no boot/restart activation',()=>{
 for(const line of['BindsTo=panel-lbstream-install@%i.service','After=panel-lbstream-install@%i.service','Type=exec','Slice=system.slice','User=root','Group=root','ExecStart=/opt/panel/bin/panel-executor --load-balance-stream-account-job=%i','Restart=no','RemainAfterExit=no','KillMode=control-group','RuntimeMaxSec=35s','NoNewPrivileges=yes','ProtectSystem=strict','PrivateNetwork=yes','RestrictAddressFamilies=AF_UNIX','MemoryHigh=256M','MemoryMax=256M','MemorySwapMax=0','TasksMax=32'])assert(unit.split('\n').includes(line),line);
 assert(!unit.includes('[Install]')&&!unit.includes('WantedBy=')&&!unit.includes('CAP_SYS_ADMIN')&&!unit.includes('CAP_SYS_PTRACE')&&!unit.includes('sudo '));
 const effects=unit.split('\n').filter(v=>v.startsWith('Exec'));assert.deepEqual(effects,['ExecStart=/opt/panel/bin/panel-executor --load-balance-stream-account-job=%i']);
 assert.equal(unit.split('\n').filter(v=>v.startsWith('ReadWritePaths=')).join(''),'ReadWritePaths=/etc /var/lib/panel-executor/load-balance-stream-identity');
});
test('production worker retains independent authority and create-once checks',()=>{
 const job=fs.readFileSync(new URL('../internal/executor/load_balance_stream_account_job_linux.go',import.meta.url),'utf8'),create=fs.readFileSync(new URL('../internal/executor/load_balance_stream_account_create_linux.go',import.meta.url),'utf8');
 for(const text of['readLoadBalanceStreamAccountPermit(job)','holdLoadBalanceStreamAccountParent(ctx, record.value, j)','parent.permitRecord = record','checkLoadBalanceStreamAccountChildKernel(ctx, parent)','prepareLoadBalanceStreamSystemAccount(ctx, parent)'])assert(job.includes(text),text);
 for(const text of['parent.permitRecord.current()','source.checkInstall(check, grant)','parent.j.officialAuthority(check)','configuration.current()','prepareLoadBalanceStreamAccountAt(active, store, intent, ops)','validateLoadBalanceStreamAccountCreationDelta(before, after)'])assert(create.includes(text),text);
 assert(!job.includes('os.Remove')&&!create.includes('os.Remove')&&!create.includes('/bin/sh'));
});
test('original parent entry and unit cannot be a generic Root command or boot hook',()=>{
 const parent=fs.readFileSync(new URL('../dev/panel-lbstream-install@.service',import.meta.url),'utf8');
 assert(main.includes('flag.String("load-balance-stream-install-job", ""'));
 assert(main.indexOf('if flag.NArg() != 0 {')>main.indexOf('flag.Parse()')&&main.indexOf('if flag.NArg() != 0 {')<main.indexOf('if lbStreamInstallEntry {'));
 const begin=main.indexOf('if lbStreamInstallEntry {'),end=main.indexOf('lbStreamAccountEntry := false');assert(begin>0&&end>begin);
 const entry=main.slice(begin,end);assert(entry.includes('len(os.Args) != 2 || os.Args[1] != "--load-balance-stream-install-job="+*lbStreamInstallJob'));assert(entry.includes('executor.RunLoadBalanceStreamInstallJob(*lbStreamInstallJob)'));
 for(const line of['BindsTo=panel.service','After=panel.service','Type=exec','Slice=system.slice','ExecStart=/opt/panel/bin/panel-executor --load-balance-stream-install-job=%i','Restart=no','RemainAfterExit=no','KillMode=control-group','RuntimeMaxSec=95s','NoNewPrivileges=yes','ProtectSystem=strict','PrivateNetwork=yes','RestrictAddressFamilies=AF_UNIX','ReadWritePaths=/etc/panel/security-apps /var/lib/panel-executor','MemoryMax=256M','MemorySwapMax=0','TasksMax=32'])assert(parent.split('\n').includes(line),line);
 assert.equal(parent.split('\n').find(x=>x.startsWith('CapabilityBoundingSet=')),unit.split('\n').find(x=>x.startsWith('CapabilityBoundingSet=')));
 assert(!parent.includes('[Install]')&&!parent.includes('WantedBy=')&&!parent.includes('CAP_SYS_PTRACE')&&!parent.includes('CAP_SYS_ADMIN')&&!parent.includes(' /etc\n'));
 const controller=fs.readFileSync(new URL('../internal/executor/load_balance_stream_install_controller_linux.go',import.meta.url),'utf8');
 for(const value of['checkLoadBalanceStreamInstallParentKernel(ctx, job)','appcatalog.VerifyLoadBalanceStreamReleaseEnvelope','createLoadBalanceStreamInstallationJournalAt','bindLoadBalanceStreamInstallationGate','w.accountChild(ctx)','prepareLoadBalanceStreamModulePublicationAt','publication.publish(active, authorize)','writeStreamInstallationReceipt','--wait','InvocationID'])assert(controller.includes(value),value);
 assert(!controller.includes('reset-failed')&&!controller.includes('os.Remove')&&!controller.includes('/bin/sh')&&!controller.includes('daemon-reload')&&!controller.includes('"--no-block", unit'));
});
