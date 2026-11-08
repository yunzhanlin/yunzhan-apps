import hashlib,json,os,pathlib,platform,subprocess,sys,traceback
os.umask(0o077);assert os.geteuid()==0 and len(sys.argv)==2
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700);repo=pathlib.Path.cwd();fixture=repo/'qa/pm2-vendor-copy-source';binding=json.loads((repo/'qa/pm2-vendor-copy-source-binding.json').read_bytes());sha=lambda f:hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest()
proof={'ok':False,'Main_changed':False,'all50_commercial':False,'production_installer_integration':False,'normal_release_or_Main_acceptance':False,'Root_uid':os.geteuid()}
try:
 assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
 arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()];assert pathlib.Path('/etc/os-release').read_text().find('VERSION_ID="24.04"')>=0
 assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==binding['original_source_sdk_head']
 actual={f.relative_to(fixture).as_posix()for f in fixture.rglob('*')if f.is_file()or f.is_symlink()};assert actual==set(binding['files'])
 for n,h in binding['files'].items():assert not(fixture/n).is_symlink()and sha(fixture/n)==h['sha256']
 assert subprocess.check_output(['go','env','GOARCH'],text=True).strip()==arch
 args=['go','test','-json','-count=1','-p=2','-parallel=1','-buildvcs=false','-run','^TestPM2RootVendorKernel','./internal/executor']
 env={**os.environ,'GOMAXPROCS':'2','GOFLAGS':'-mod=readonly','CGO_ENABLED':'0'}
 with(out/'original-go.stdout.jsonl').open('xb')as a,(out/'original-go.stderr.log').open('xb')as b:r=subprocess.run(args,cwd=fixture,env=env,stdout=a,stderr=b,timeout=900,umask=0o022)
 proof.update(original_exit=r.returncode,architecture=arch,original_go_args=args)
 rows=[json.loads(v)for v in(out/'original-go.stdout.jsonl').read_text().splitlines()];tests={r['Test']for r in rows if r.get('Action')=='run'and r.get('Test')};passed={r['Test']for r in rows if r.get('Action')=='pass'and r.get('Test')};skipped=[r.get('Test')for r in rows if r.get('Action')=='skip'];failed=[r.get('Test')for r in rows if r.get('Action')=='fail'];top={v for v in tests if'/'not in v}
 assert r.returncode==0 and len(top)==6 and len(tests)==21 and tests==passed and skipped==failed==[]
 assert any('actual UID65534 original writable FD truncated/pwrote retained original; new Root-owned public bytes unchanged'in r.get('Output','')for r in rows)
 for n,h in binding['files'].items():assert sha(fixture/n)==h['sha256']
 proof.update(ok=True,actual_native_architecture=arch,original_source_sdk_tree=binding['original_source_sdk_tree'],actual_Root_PASS_cases=sorted(passed),actual_unprivileged_original_writer_UID=65534,original_test_skips=0,original_failures=0,source_files_unchanged=len(binding['files']),source_overlays=0,new_local_VM_or_service_or_Main_submissions=0)
except BaseException:proof['failure']=traceback.format_exc()
finally:
 for n in('original-go.stdout.jsonl','original-go.stderr.log'):
  if not(out/n).exists():(out/n).open('xb').close()
 with(out/'original-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 print(json.dumps({'ok':proof['ok'],'architecture':proof.get('architecture'),'Root_cases':len(proof.get('actual_Root_PASS_cases',[])),'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
