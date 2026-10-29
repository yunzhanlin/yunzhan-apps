"""Fresh hardware AMD64: signed C33r1 first country account/data, C34r1 upgrade, signed Stats260 app/database installation.
No failed or unknown original is replayed, replaced or relabelled.
"""
import hashlib,json,os,pathlib,platform,re,runpy,secrets,shutil,sqlite3,contextlib,stat,subprocess,sys,time,traceback
os.umask(0o077);assert os.geteuid()==0 and platform.machine()=='x86_64'and len(sys.argv)==2
payload=pathlib.Path(sys.argv[1]).resolve(strict=True);pins=json.load(open(payload/'assets.json'));assert pins['format']==1 and pins['architecture']=='amd64'and pins['harness_revision']==48
base=pathlib.Path('/opt/panel-country-native-qa-'+secrets.token_hex(16));base.mkdir(mode=0o700);evidence=base/'evidence';evidence.mkdir(mode=0o700)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def save(n,v):
 with(evidence/n).open('x')as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
for n,h in pins['files'].items():
 assert re.fullmatch('[A-Za-z0-9._-]+',n);p=payload/n;s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and sha(p)==h;shutil.copyfile(p,base/n,follow_symlinks=False);os.chmod(base/n,0o600)
assert sha(base/'programme.pub')=='4ccfcc861d56a41e3ba7f7ace7e2432c815f366c58448d783df92c6632f01339'and sha(base/'signed-release.py')=='fe128e82b4e11345b320cd782134768bfe1a4df14947c425d7494873a7a7b7b5'
assert pins['source_inputs_sha256']=='3d4cd988b0b226691c9da1a359d6875f4c415800f2e2a5e62538c9c1bb5aa730'and pins['old_source_inputs_sha256']=='92bbbcc520abf60c367d168e650fae07f1a07dcf9127c74d5f32a16d57c776d7'
assert pathlib.Path('/etc/hostname').read_text().strip()=='yunzhan-native-kvm-c34'
assert not pathlib.Path('/etc/panel-release').exists()and not pathlib.Path('/opt/panel').exists()
def command(label,args,timeout=1200):
 save(label+'-once-intent.json',{'args':args,'maximum_submissions':1,'unknown_outcome_observe_only':True})
 with(evidence/(label+'.log')).open('xb')as out:r=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT,timeout=timeout)
 save(label+'-outcome.json',{'status':r.returncode,'log_sha256':sha(evidence/(label+'.log'))});assert r.returncode==0,'Failed original retained: '+label
app_case=None;data_case=None
def statistics_case(helper,original=None):
 case=pathlib.Path('/opt/panel-statistics-native-qa-'+secrets.token_hex(16));case.mkdir(mode=0o700);files={}
 for name in('business.py','observations.py',helper):
  shutil.copyfile(base/name,case/name,follow_symlinks=False);os.chmod(case/name,0o600);files[name]=sha(case/name)
 intent={'format':1,'base':str(case),'boot':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'architecture':'amd64','source_inputs_sha256':pins['source_inputs_sha256'],'files':files,'Main_changed':False,'all50_commercial':False}
 if original is not None:intent.update(original_app_install_case=str(original),original_app_install_proof_sha256=sha(original/'proof.json'))
 with(case/'intent.json').open('x')as out:json.dump(intent,out);out.flush();os.fsync(out.fileno())
 return case
def execute_statistics_case(case,helper):
 before_argv=sys.argv[:]
 try:
  sys.argv=[str(case/helper),str(case)];runpy.run_path(str(case/helper),run_name='__main__')
 finally:sys.argv=before_argv
 result=json.loads((case/'proof.json').read_bytes());assert result['ok'];return result
proof={'ok':False,'architecture':'amd64','actual_KVM_guest':True,'base':str(base),'source_inputs_sha256':pins['source_inputs_sha256'],'normal_signed_baseline_to_C34r1':False,'Main_changed':False,'all50_commercial':False}
try:
 archive=base/'panel-0.1.0-dev.proapps24countrydownloadcancelcandidate33r1-linux-amd64.tar.gz';command('C33r1-signature-verify',['python3','-I','-B',str(base/'signed-release.py'),'verify',str(archive),'--public-key',str(base/'programme.pub')],30);command('C33r1-normal-first-install',['python3','-I','-B',str(base/'signed-release.py'),'install',str(archive),'--public-key',str(base/'programme.pub')]);assert json.load(open('/opt/panel/current/SOURCE_INPUTS.json'))['inputs_sha256']==pins['old_source_inputs_sha256']
 for _ in range(45):
  with contextlib.closing(sqlite3.connect('file:/var/lib/panel/panel.db?mode=ro',uri=True))as db:count=db.execute('SELECT count(*)FROM monitor_samples').fetchone()[0];clock=db.execute('SELECT last_check_at FROM notification_dispatch_status WHERE id=1').fetchone()[0]
  if count>0 and re.fullmatch(r'20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z',clock):break
  time.sleep(1)
 assert count>0 and clock
 functional=runpy.run_path(str(base/'functional-c33r1.py'))['run'](base,'amd64',pins['app_manifest_sha256']);proof['original_C33r1_functional']=functional;assert functional['ok']
 upgrade=runpy.run_path(str(base/'upgrade-c34r1.py'))['run'](base,'amd64',pins,base);proof['upgrade']=upgrade;assert upgrade['ok']
 app_case=statistics_case('install-stats260.py');proof['original_app_install_case']=str(app_case);proof['statistics_installation']=execute_statistics_case(app_case,'install-stats260.py')
 data_case=statistics_case('geodata-stats260.py',app_case);proof['original_data_install_case']=str(data_case);proof['statistics_data_installation']=execute_statistics_case(data_case,'geodata-stats260.py')
 proof.update(ok=True,normal_signed_baseline_to_C34r1=True,first_original_account_and_data_succeeded=True,original_signed_country_data_preserved=True,actual_Core_inspection260_zero_differences=True,normal_signed_Stats260_installed=True,actual_signed_October_database_loaded=True)
except BaseException:save('failure.json',{'traceback':traceback.format_exc()})
finally:
 for n in('country-functional','upgrade-c34r1'):
  if(base/n).is_dir():shutil.copytree(base/n,evidence/n)
 for name,case in [('statistics-app-install',app_case),('statistics-data-install',data_case)]:
  if case is not None:shutil.copytree(case,evidence/name)
 try:
  final={'core':runpy.run_path(str(base/'business.py'))['capture_core'](),'full_guard':subprocess.run(['/opt/panel/current/bin/panel-executor','--check-program-upgrade-queues'],capture_output=True,timeout=35).returncode,'units':subprocess.check_output(['systemctl','list-units','--all','--no-pager','--no-legend','panel-*'],text=True,timeout=20)}
  save('actual-final-Core-guard-and-units.json',final)
 except BaseException:save('final-diagnostic-failure.json',{'traceback':traceback.format_exc()})
 save('proof.json',proof);print(json.dumps({'ok':proof['ok'],'base':str(base),'proof_sha256':sha(evidence/'proof.json'),'normal_signed_baseline_to_C34r1':proof['normal_signed_baseline_to_C34r1'],'source_inputs_sha256':pins['source_inputs_sha256'],'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
