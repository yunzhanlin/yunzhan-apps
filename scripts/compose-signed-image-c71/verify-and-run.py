"""Exercise and retain actual native Go output from the exact C71 source inputs."""
import hashlib,json,os,pathlib,platform,stat,subprocess,sys,traceback
os.umask(0o077)
assert len(sys.argv)==2 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700)
repo=pathlib.Path.cwd();where=pathlib.Path(__file__).resolve().parent
d=json.loads((where/'dispatch.json').read_bytes())
sdk=repo/d['sdk'];arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
sha=lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
proof={'ok':False,'architecture':arch,'source_inputs_sha256':d['source_inputs_sha256'],'release_source_head':d['release_source_head'],'installed_business_qualified':False,'Main_changed':False,'all50_commercial':False}
def git(*args):return subprocess.check_output(['git',*args],text=True,timeout=50).strip()
try:
 assert git('rev-parse','HEAD')==os.environ['GITHUB_SHA'] and git('rev-parse','HEAD^')==d['original_served_head']
 assert sha(sdk/'source-sha256.json')==d['source_index_sha256']
 data=json.loads((sdk/'source-sha256.json').read_bytes())
 assert data['release']==d['original_amd64_archive']and data['release']['frozen_inputs_sha256']==d['source_inputs_sha256']and len(data['files'])==2491
 tracked={os.fsdecode(n)for n in subprocess.check_output(['git','ls-files','-z',d['sdk']]).split(b'\0')if n}
 assert tracked=={d['sdk']+'/'+n for n in data['files'].keys()|{'release-source-inputs.json','source-sha256.json'}}
 for n,h in data['files'].items():
  p=sdk/n;st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and sha(p)==h,n
 for n,tree in d['retained_signed_and_sdk_trees'].items():assert git('rev-parse','HEAD:'+n)==tree
 assert subprocess.check_output(['go','version'],text=True).strip()=='go version go1.27.2 linux/'+arch
 env={**os.environ,'GOMAXPROCS':'2','GOFLAGS':'-p=2','GOTOOLCHAIN':'local'}
 args=['go','test','-buildvcs=false','-json','-count=1','-timeout=15m','./internal/core','./internal/appcatalog']
 with(out/'original-go.stdout').open('xb')as a,(out/'original-go.stderr').open('xb')as b:r=subprocess.run(args,cwd=sdk,env=env,stdout=a,stderr=b,timeout=1000)
 assert r.returncode==0
 events=[json.loads(v)for v in(out/'original-go.stdout').read_text().splitlines()]
 assert not any(x['Action']=='fail'for x in events)
 targets=('TestRegistryComposeDeliveryMatchesPublishedRecipes','TestRegistryInstallSignedRabbitMQImageBindsActualSubmission')
 matches=[v for v in events if v.get('Package')=='local/panel/internal/core'and v.get('Test','').split('/',1)[0]in targets]
 expected=set(d['required_cases'])
 for action in('run','pass'):
  result=[v['Test']for v in matches if v['Action']==action];assert len(result)==len(expected)and set(result)==expected
 assert not any(v['Action']in('skip','fail')for v in matches)
 proof.update(ok=True,actual_original_test_cases=len(expected),required_case_names=sorted(expected),actual_Go_pass=sum(v['Action']=='pass'and bool(v.get('Test'))for v in events),original_go_stdout_sha256=sha(out/'original-go.stdout'),original_go_stderr_sha256=sha(out/'original-go.stderr'),source_sdk_files=2491,actual_original_Go_exit=0,all_original_signed_catalogue_and_client_trees_unchanged=True)
except BaseException:
 proof['failure']=traceback.format_exc()
finally:
 with(out/'original-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 print(json.dumps({'ok':proof['ok'],'architecture':arch,'actual_original_test_cases':proof.get('actual_original_test_cases',0),'Main_changed':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
