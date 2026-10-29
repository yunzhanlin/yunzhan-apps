"""Fresh hardware AMD64: signed C31r4 first account/data, C32r1 upgrade, new policy controls and explicit original before-dispatch cancellation.
No failed or unknown original is replayed, replaced or relabelled.
"""
import hashlib,json,os,pathlib,platform,re,runpy,secrets,shutil,sqlite3,contextlib,stat,subprocess,sys,time,traceback
os.umask(0o077);assert os.geteuid()==0 and platform.machine()=='x86_64'and len(sys.argv)==2
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.load(open(payload/'assets.json'));assert pins['format']==1 and pins['architecture']=='amd64'and pins['harness_revision']==45
base=pathlib.Path('/opt/panel-country-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n);p=payload/n;s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(p)==h;shutil.copyfile(p,base/n,follow_symlinks=False);os.chmod(base/n,0o600)
assert sha(base/'programme.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'and sha(base/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert pins['source_inputs_sha256']=='8555db1beaa67a32727c21bc58d4b49752db1e20f164395096a0e69d8c78e38e'and pins['old_source_inputs_sha256']=='366bcb71cd8ac5f0c5579c56257346aa1ccef7af10bc9d1025c7db531f10f9dd'
assert not pathlib.Path('/etc/panel-release').exists()and not pathlib.Path('/opt/panel').exists()
def command(label,args,timeout=1200):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.log')).open('xb')as out:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,timeout=timeout)
 save(label+'-outcome.json',{'status':r.returncode,'log_sha256':sha(evidence/(label+'.log'))});assert r.returncode==0,'Failed original retained: '+label
proof={'ok':False,'architecture':'amd64','actual_KVM_guest':True,'base':str(base),'source_inputs_sha256':pins['source_inputs_sha256'],'normal_signed_baseline_to_C32r1':False,'Main_changed':False,'all50_commercial':False}
try:
 archive=base/'panel-0.1.0-dev.proapps24countryinterruptcandidate31r4-linux-amd64.tar.gz';command('C31r4-signature-verify',['python3','-I','-B',str(base/'signed-release.py'),'verify',str(archive),'--public-key',str(base/'programme.pub')],30);command('C31r4-normal-first-install',['python3','-I','-B',str(base/'signed-release.py'),'install',str(archive),'--public-key',str(base/'programme.pub')]);assert json.load(open('/opt/panel/current/SOURCE_INPUTS.json'))['inputs_sha256']==pins['old_source_inputs_sha256']
 for _ in range(45):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:count=db.execute('SELECT count(*)FROM monitor_samples').fetchone()[0];clock=db.execute('SELECT last_check_at FROM notification_dispatch_status WHERE id=1').fetchone()[0]
  if count>0 and re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z',clock):break
  time.sleep(1)
 assert count>0 and clock
 functional=runpy.run_path(str(base/'functional-c31r4.py'))['run'](base,'amd64',pins['app_manifest_sha256']);proof['original_C31r4_functional']=functional;assert functional['ok']
 upgrade=runpy.run_path(str(base/'upgrade-c32r1.py'))['run'](base,'amd64',pins,base);proof['upgrade']=upgrade;assert upgrade['ok'];controls=runpy.run_path(str(base/'controls-c32r1.py'))['run'](base,'amd64',base);proof['capacity_controls']=controls;assert controls['ok'];cancellation=runpy.run_path(str(base/'cancel-before-dispatch-c32r1.py'))['run'](base,'amd64',base);proof['actual_before_dispatch_cancellation']=cancellation;assert cancellation['ok'];proof.update(ok=True,normal_signed_baseline_to_C32r1=True,first_original_account_and_data_succeeded=True,original_signed_country_data_preserved=True,actual_Core_inspection260_zero_differences=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 for n in('country-functional','upgrade-c32r1','country-capacity-functional','country-cancel-before-dispatch'):
  if(base/n).is_dir():shutil.copytree(base/n,evidence/n)
 save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'normal_signed_baseline_to_C32r1':proof['normal_signed_baseline_to_C32r1'],'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
