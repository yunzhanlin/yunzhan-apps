"""Compare actual native Root PM2 regressions on exact baseline and explicit development patch."""
import hashlib,json,os,platform,re,shutil,stat,subprocess,sys,tempfile,time,traceback
from pathlib import Path
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
private=Path(sys.argv[1]);private.mkdir(mode=0o700);out=private/'business-phase1';out.mkdir(mode=0o700)
source=Path(__file__).resolve().parent;repo=source.parents[1];plan=json.loads((source/'cohort.json').read_bytes());arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
go=Path(sys.argv[2]);assert go.is_absolute()and go.name=='go'and go.parent.name=='bin'and go.is_file()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(name,value):
 with(out/(name+'.json')).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
def git(*args):return subprocess.check_output(['git',*args],cwd=repo,text=True,timeout=30).strip()
def inventory(root):
 rows={}
 for p in root.rglob('*'):
  if p.is_dir():continue
  s=p.lstat();assert stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<16<<20
  rows[str(p.relative_to(root))]={'bytes':s.st_size,'sha256':sha(p)}
 return rows
proof={'ok':False,'scope':'Actual native Root kernel locking and complete journal inventory and comparative existing PM2 Go regressions for an unpublished development patch','architecture':arch,'base_programme_source_inputs_sha256':plan['source_inputs_sha256'],'development_patch_sha256':plan['patch_sha256'],'Main_changed':False,'signed_programme_or_app_installs':0,'all40_commercial':False}
try:
 assert git('rev-parse','HEAD^')==plan['native_fixture_parent']
 changes=set(git('diff','--name-only','HEAD^','HEAD').splitlines());assert changes==set(plan.get('changed_payload_files',plan['payload_files']))|{str((source/'cohort.json').relative_to(repo))}
 for n,h in plan['payload_files'].items():assert sha(repo/n)==h,n
 sdk_path='candidate/panel-integration-compose-signed-image';assert git('rev-parse','HEAD:'+sdk_path)==plan['source_sdk_tree']and not git('status','--porcelain','--',sdk_path)
 version=subprocess.check_output([str(go),'version'],text=True,timeout=15).strip();assert ' go1.27.2 linux/'in version;save('actual-native-toolchain',{'version':version,'euid':os.geteuid(),'architecture':arch,'kernel':platform.release(),'SDK_tree':plan['source_sdk_tree']})
 work=Path(tempfile.mkdtemp(prefix='c231-pm2-development-',dir='/var/lib'));before=work/'baseline';after=work/'patched';shutil.copytree(repo/sdk_path,before);shutil.copytree(repo/sdk_path,after)
 baseline_index=inventory(before);assert baseline_index==inventory(after)and len(baseline_index)>=2600;save('original-baseline-source-index',baseline_index)
 patch=source/'development.patch';assert sha(patch)==plan['patch_sha256']
 for args in(['git','apply','--unidiff-zero','--check',str(patch)],['git','apply','--unidiff-zero',str(patch)]):subprocess.run(args,cwd=after,check=True,stdin=subprocess.DEVNULL,capture_output=True,timeout=30)
 patched_index=inventory(after);changed={n for n in set(baseline_index)|set(patched_index)if baseline_index.get(n)!=patched_index.get(n)};assert changed==set(plan['changed_source_files']);save('actual-patched-source-index',patched_index)
 env={'PATH':str(go.parent)+':/usr/bin:/bin','HOME':str(work),'LANG':'C.UTF-8','GOTOOLCHAIN':'local','GOMAXPROCS':'2','GOFLAGS':'-p=2','CGO_ENABLED':'0','GOCACHE':str(work/'go-cache'),'GOPATH':str(work/'go-path')}
 results={}
 for label,tree in [('baseline',before),('patched',after)]:
  args=[str(go),'test','-json','-count=1','-parallel=2','-timeout=12m','./internal/executor','-run','PM2'];started=time.monotonic()
  with(out/(label+'-original-test.stdout')).open('xb')as stdout,(out/(label+'-original-test.stderr')).open('xb')as stderr:r=subprocess.run(args,cwd=tree,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=780,preexec_fn=lambda:os.umask(0o022))
  events=[json.loads(line)for line in(out/(label+'-original-test.stdout')).read_text().splitlines()if line.strip()];terminal={x['Test']:x['Action']for x in events if x.get('Test')and x['Action']in('pass','skip','fail')};result={'exit':r.returncode,'elapsed_seconds':time.monotonic()-started,'terminal_tests':terminal,'passes':sum(x=='pass'for x in terminal.values()),'skips':sum(x=='skip'for x in terminal.values()),'fails':sum(x=='fail'for x in terminal.values()),'arguments':args,'native_test_process_umask':'0022','evidence_parent_and_files_remain_private':True,'CGO_ENABLED':'0'};save(label+'-original-outcome',result);results[label]=result
  assert r.returncode==0 and len(terminal)>=25 and not any(x['Action']=='fail'for x in events),label+' original test failure retained'
  assert inventory(tree)==(baseline_index if label=='baseline'else patched_index),'tests changed source inputs'
 a=results['baseline']['terminal_tests'];b=results['patched']['terminal_tests'];assert all(b.get(n)==state for n,state in a.items()),'an original PM2 regression changed state'
 new={n:state for n,state in b.items()if n not in a};assert new and all(n.startswith('TestPM2Journal')and state=='pass'for n,state in new.items())
 for n in plan['required_new_top_level_tests']:assert new.get(n)=='pass',n
 assert len(new)==plan['expected_new_test_rows']
 save('actual-native-regression-comparison',{'original_test_statuses_retained':True,'new_real_kernel_tests':new,'before':{'pass':results['baseline']['passes'],'skip':results['baseline']['skips']},'after':{'pass':results['patched']['passes'],'skip':results['patched']['skips']},'new_skips':0,'exact_changed_source_files':sorted(changed),'patched_source_index_sha256':sha(out/'actual-patched-source-index.json')})
 package_comparisons={}
 for pkg in ['core','appcatalog']:
  package_results={}
  for label,tree in [('baseline',before),('patched',after)]:
   args=[str(go),'test','-json','-count=1','-parallel=2','-timeout=6m','./internal/'+pkg,'-run','PM2|ModuleWorkspace'if pkg=='core'else'PM2'];started=time.monotonic()
   with(out/(label+'-'+pkg+'-original-test.stdout')).open('xb')as stdout,(out/(label+'-'+pkg+'-original-test.stderr')).open('xb')as stderr:r=subprocess.run(args,cwd=tree,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=420,preexec_fn=lambda:os.umask(0o022))
   events=[json.loads(line)for line in(out/(label+'-'+pkg+'-original-test.stdout')).read_text().splitlines()if line.strip()];terminal={x['Test']:x['Action']for x in events if x.get('Test')and x['Action']in('pass','skip','fail')};result={'exit':r.returncode,'elapsed_seconds':time.monotonic()-started,'terminal_tests':terminal,'passes':sum(x=='pass'for x in terminal.values()),'skips':sum(x=='skip'for x in terminal.values()),'fails':sum(x=='fail'for x in terminal.values()),'arguments':args};save(label+'-'+pkg+'-original-outcome',result);package_results[label]=result
   assert r.returncode==0 and len(terminal)>=2 and not any(x['Action']=='fail'for x in events),pkg+' original native failure retained'
   assert inventory(tree)==(baseline_index if label=='baseline'else patched_index)
  original=package_results['baseline']['terminal_tests'];patched=package_results['patched']['terminal_tests'];assert all(patched.get(n)==state for n,state in original.items()),pkg+' original test state changed'
  added={n:state for n,state in patched.items()if n not in original};assert len(added)==plan['expected_additional_package_tests'][pkg]and all(n.startswith('TestPM2Journal')and state=='pass'for n,state in added.items())
  package_comparisons[pkg]={'original_statuses_retained':True,'new_test_rows':added,'before':{'pass':package_results['baseline']['passes'],'skip':package_results['baseline']['skips']},'after':{'pass':package_results['patched']['passes'],'skip':package_results['patched']['skips']}}
 save('actual-native-Core-catalogue-comparison',package_comparisons)
 proof.update(ok=True,actual_euid=os.geteuid(),new_real_kernel_tests=len(new),original_passes=results['baseline']['passes'],original_skips=results['baseline']['skips'],all_original_statuses_retained=True,new_tests_skipped=0,source_inputs_unchanged_after_execution=True,signed_delivery_and_actual_UI_acceptance_pending=True,additional_Core_and_catalogue_native_comparisons=True)
except BaseException:proof['failure']=traceback.format_exc()
finally:save('original-proof',proof)
sys.exit(0 if proof['ok']else 1)
