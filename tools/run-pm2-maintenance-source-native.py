"""Run exact native Root source fixtures; this does not install a programme."""
import hashlib,json,os,pathlib,platform,shutil,subprocess,sys,time,traceback
os.umask(0o077)
repo=pathlib.Path(__file__).resolve().parent.parent
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700)
proof={'ok':False,'source_fixture_only_not_installed_PM2':True,'actual_existing_business_service_actions':0,'all50_commercial':False}
def save(n,v):
 with(out/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def run(label,args,cwd,env,timeout):
 save(label+'-intent.json',{'args':args,'cwd':str(cwd),'maximum_submissions':1,'at':time.time()})
 with(out/(label+'.stdout')).open('xb')as a,(out/(label+'.stderr')).open('xb')as b:r=subprocess.run(args,cwd=cwd,env=env,stdout=a,stderr=b,timeout=timeout)
 save(label+'-outcome.json',{'exit':r.returncode,'stdout_sha256':sha(out/(label+'.stdout')),'stderr_sha256':sha(out/(label+'.stderr'))})
 assert r.returncode==0,label+' original failure retained without retry'
 return [json.loads(line)for line in (out/(label+'.stdout')).read_text().splitlines()if line]
try:
 assert os.geteuid()==0 and platform.system()=='Linux'and platform.machine()in('x86_64','aarch64')
 assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
 spec=json.loads((repo/'tools/pm2-maintenance-native-execution.json').read_bytes());sdk=repo/'candidate/panel-integration-pm2-maintenance'
 index=json.loads((sdk/'source-sha256.json').read_bytes())
 assert spec['source_inputs_sha256']==index['release']['frozen_inputs_sha256']=='9983bbf3986af49b75aba6e06f94a6f43f2e66eb18b2b013895453017cff681e'
 assert spec['source_index_sha256']==sha(sdk/'source-sha256.json')and len(index['files'])==spec['source_sdk_files']==2478
 assert spec['expected_strict_native_tests']==sum(len(v)for v in spec['expected_tests'].values())==55 and not index.get('test_overrides')
 def check():
  for n,h in index['files'].items():
   p=sdk/n;s=p.lstat();assert p.is_file()and not p.is_symlink()and s.st_nlink==1 and p.resolve()==p and sha(p)==h,n
 check()
 go=pathlib.Path(shutil.which('go')).resolve(strict=True)
 env=dict(os.environ,CGO_ENABLED='0',GOMAXPROCS='2',GOFLAGS='-p=1',GOTOOLCHAIN='local')
 assert subprocess.check_output([str(go),'env','GOOS','GOARCH'],env=env,text=True).splitlines()==['linux',{'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]]
 full=run('original-complete-Root-Go',[str(go),'test','-json','-count=1','-p','1','-ldflags=-X=local/panel/internal/appcatalog.officialCatalogChannel=candidate','./...'],sdk,env,1200)
 assert not any(v.get('Action')=='fail'for v in full)
 assert any(v.get('Action')=='pass'and v.get('Package')=='local/panel/internal/executor'and not v.get('Test')for v in full)
 selected=run('original-strict-PM255',[str(go),'test','-json','-count=1','-p','1','-ldflags=-X=local/panel/internal/appcatalog.officialCatalogChannel=candidate','./internal/appcatalog','./internal/core','./internal/executor','-run','^(TestPM2Stop|TestPM2ProjectsGET|TestPM2ProjectReadQuery)'],sdk,env,240)
 assert not any(v.get('Action')in('fail','skip')for v in selected)
 for pkg,wanted in spec['expected_tests'].items():
  for action in ['run','pass']:
   got=[v['Test']for v in selected if v.get('Package')==pkg and v.get('Action')==action and v.get('Test')]
   assert len(got)==len(set(got))==len(wanted)and set(got)==set(wanted),(pkg,action,len(got),set(got)^set(wanted))
  assert sum(v.get('Action')=='pass'and v.get('Package')==pkg and not v.get('Test')for v in selected)==1
 assert all(v.get('Package')in spec['expected_tests']for v in selected)
 text=(out/'original-strict-PM255.stdout').read_text()
 for mode in spec['kernel_modes']:assert 'PM2_STOP_KERNEL_ACCEPTED '+mode+'\\n' in text
 check()
 proof.update(ok=True,architecture=platform.machine(),source_inputs_sha256=spec['source_inputs_sha256'],source_sdk_files=2478,all_source_bytes_unchanged_after_both_processes=True,actual_strict_Root_passed=55,strict_skips=0,complete_Go_passed=sum(v.get('Action')=='pass'and bool(v.get('Test'))for v in full),complete_Go_explicit_skips=[{'package':v.get('Package'),'test':v.get('Test')}for v in full if v.get('Action')=='skip'],actual_private_kernel_modes=spec['kernel_modes'],fixed_mocked_systemctl_only=True)
except BaseException:
 proof['failure']=traceback.format_exc()
finally:
 save('original-proof.json',proof)
 print(json.dumps({'ok':proof['ok'],'actual_strict_Root_passed':proof.get('actual_strict_Root_passed',0),'out':str(out),'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)

