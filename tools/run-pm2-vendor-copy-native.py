import base64,errno,hashlib,io,json,os,pathlib,platform,re,secrets,stat,subprocess,sys,tarfile,traceback
os.umask(0o077)
assert os.geteuid()==0 and os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def identity(f):
 s=f.lstat()
 return {'dev':s.st_dev,'ino':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode,'ctime_ns':s.st_ctime_ns}
def acl(f):
 values={}
 for key in ('system.posix_acl_access','system.posix_acl_default'):
  try: values[key]=os.getxattr(f,key).hex()
  except OSError as e:
   assert e.errno in (errno.ENODATA,errno.ENOTSUP);values[key]=None
 return values
def record(f):
 assert f.parent.is_dir() and not f.is_symlink()
 s=f.lstat();assert stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and s.st_size<=8<<20
 raw=f.read_bytes();assert len(raw)==s.st_size and identity(f)['ino']==s.st_ino
 return {'identity':identity(f),'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode()}
assert len(sys.argv)==2
out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700);repo=pathlib.Path.cwd();fixture=repo/'qa/pm2-vendor-copy-source'
binding=json.loads((repo/'qa/pm2-vendor-copy-source-binding.json').read_bytes())
proof={'ok':False,'Root_uid':os.geteuid(),'Main_changed':False,'all50_commercial':False,'normal_signed_panel_or_Main_acceptance':False}
records={}
try:
 arch={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
 proof['architecture']=arch
 assert 'VERSION_ID="24.04"' in pathlib.Path('/etc/os-release').read_text()
 assert subprocess.check_output(['git','rev-parse','HEAD^'],text=True).strip()==binding['original_source_sdk_head']
 assert subprocess.check_output(['go','env','GOARCH'],text=True).strip()==arch
 def check_sources():
  actual={f.relative_to(fixture).as_posix()for f in fixture.rglob('*')if f.is_file()or f.is_symlink()};assert actual==set(binding['files'])
  for n,v in binding['files'].items():assert not(fixture/n).is_symlink()and sha((fixture/n).read_bytes())==v['sha256'],n
 check_sources()
 hostopt=pathlib.Path('/opt');opt_before=identity(hostopt);acl_before=acl(hostopt)
 namespace=os.readlink('/proc/self/ns/mnt')
 pins=json.loads((repo/'qa/c70-ubuntu24-native-image-pins.json').read_bytes());ref=pins['registry']+'@'+pins['platform_digests'][arch];assert pins['registry']=='docker.io/library/ubuntu'and re.fullmatch(r'docker.io/library/ubuntu@sha256:[a-f0-9]{64}',ref)
 docker='/usr/bin/docker';name='c70-real-pm2-'+arch+'-'+secrets.token_hex(8)
 backing=out/'owned-opt';backing.mkdir(mode=0o755);os.chown(backing,0,0);backing.chmod(0o755)
 for key in ('system.posix_acl_access','system.posix_acl_default'):
  try:os.removexattr(backing,key)
  except OSError as e:assert e.errno in (errno.ENODATA,errno.ENOTSUP)
 binary=str(out/'native-fixed-builder.test')
 env={**os.environ,'GOMAXPROCS':'2','GOFLAGS':'-mod=readonly','CGO_ENABLED':'0','C70_ORIGINAL_MOUNT_NAMESPACE':namespace}
 with(out/'original-go.stdout.jsonl').open('xb')as stdout,(out/'original-go.stderr.log').open('xb')as stderr:
  build=subprocess.run(['go','test','-c','-buildvcs=false','-p=2','-o',binary,'./internal/executor'],cwd=fixture,env=env,stdout=stderr,stderr=stderr,timeout=480,umask=0o022)
  proof['original_native_compile_exit']=build.returncode;assert build.returncode==0
  pull=subprocess.run([docker,'pull','--platform','linux/'+arch,ref],stdout=stderr,stderr=stderr,timeout=240);assert pull.returncode==0
  image=json.loads(subprocess.check_output([docker,'image','inspect',ref],timeout=30))[0];assert image['Architecture']==arch and image['Os']=='linux'and any(v.split('@')[0]in('ubuntu','library/ubuntu','docker.io/library/ubuntu')and v.rsplit('@',1)[-1]==pins['platform_digests'][arch]for v in image['RepoDigests'])
  proof.update(image_platform_digest=ref,image_ID=image['Id'],container_name=name,container_retained=True)
  command=[docker,'run','--name',name,'--platform','linux/'+arch,'--user','0:0','--memory=640m','--memory-swap=640m','--pids-limit=128','--cpus=1','--mount','type=bind,source='+str(backing)+',target=/opt','--mount','type=bind,source='+binary+',target=/usr/local/bin/c70-native-test,readonly','--env','GITHUB_ACTIONS=true','--env','GITHUB_REPOSITORY=yunzhanlin/yunzhan-apps','--env','PANEL_PM2_VENDOR_INSTALLER_QA=1',ref,'/usr/local/bin/c70-native-test','-test.run=^TestPM2RootVendorNativeRealFixedDependencyBuilder$','-test.v=test2json','-test.count=1','-test.timeout=11m']
  r=subprocess.run(['go','tool','test2json','-t','-p','local/panel/internal/executor',*command],cwd=fixture,env=env,stdout=stdout,stderr=stderr,timeout=720,umask=0o022)
 proof.update(original_exit=r.returncode,original_host_opt_before=opt_before,original_host_opt_after=identity(hostopt),original_host_opt_ACL_before=acl_before,original_host_opt_ACL_after=acl(hostopt))
 assert proof['original_host_opt_after']==opt_before and proof['original_host_opt_ACL_after']==acl_before and os.readlink('/proc/self/ns/mnt')==namespace
 modules=out/'owned-opt/panel/app-modules'
 if modules.is_dir():
  private=[p for p in modules.iterdir()if re.fullmatch(r'\.pm2-vendor-[a-f0-9]{32}',p.name)]
  assert len(private)<=1
  for p in private:
   ident=identity(p);assert stat.S_ISDIR(ident['mode'])and stat.S_IMODE(ident['mode'])==0o700 and ident['uid']==ident['gid']==0
   for name in ('original-build-intent.json','empty-global-npmrc','vendor-anchor.json','original-pointer-identity.json','original-publication-prepared.json','original-publication-completed.json','original-build-outcome.json'):
    if (p/name).exists():records[name]=record(p/name)
  for name in ('package.json','package-lock.json','.root-owned-pm2-vendor.json','node_modules/pm2/package.json'):
   if (modules/'pm2'/name).exists():records['public/'+name]=record(modules/'pm2'/name)
 result=subprocess.run([docker,'cp',name+':/etc/panel/security-apps/modules/pm2-manager/dependency-result.json','-'],capture_output=True,timeout=30)
 if result.returncode==0:
  assert len(result.stdout)<1<<20
  with tarfile.open(fileobj=io.BytesIO(result.stdout))as tar:
   members=tar.getmembers();assert len(members)==1 and members[0].name=='dependency-result.json' and members[0].isfile()and members[0].uid==members[0].gid==0 and members[0].mode==0o600
   raw=tar.extractfile(members[0]).read();records['fixed-dependency-result.json']={'identity':{'uid':0,'gid':0,'mode':0o100600},'bytes':len(raw),'sha256':sha(raw),'base64':base64.b64encode(raw).decode()}
 state=json.loads(subprocess.check_output([docker,'container','inspect',name],timeout=30))[0]['State'];proof['actual_container_state']={k:state[k]for k in ('Status','ExitCode','OOMKilled','StartedAt','FinishedAt')}
 assert state['Status']=='exited'and not state['OOMKilled']
 rows=[json.loads(v)for v in(out/'original-go.stdout.jsonl').read_text().splitlines()]
 expected='TestPM2RootVendorNativeRealFixedDependencyBuilder'
 assert r.returncode==0 and {row['Test']for row in rows if row.get('Action')=='pass'and row.get('Test')}=={expected} and not any(row.get('Action')in('skip','fail')for row in rows)
 accepted=[row['Output'].strip()for row in rows if 'PM2_REAL_FIXED_NPM_BUILDER_ACCEPTED' in row.get('Output','')];assert len(accepted)==1
 assert len(records)==12 and json.loads(base64.b64decode(records['original-publication-completed.json']['base64']))['published']
 check_sources()
 proof.update(ok=True,actual_native_architecture=arch,actual_Root_PASS_cases=[expected],original_test_skips=0,original_failures=0,source_files_unchanged=len(binding['files']),source_overlays=0,original_host_opt_unchanged=True,original_mount_namespace_retained=True,clean_distribution_image=True,private_conventional_opt_mount=True,actual_memory_limit_bytes=640<<20,actual_npm_builder=True,unprivileged_PM2_CLI_UID=65534,unprivileged_PM2_CLI_version='7.0.4',normal_installed_store_acceptance=False,original_output=accepted[0],retained_original_failures=[42625378666,42626415347])
except BaseException:
 proof['failure']=traceback.format_exc()
finally:
 for n in ('original-go.stdout.jsonl','original-go.stderr.log'):
  if not(out/n).exists():(out/n).open('xb').close()
 with(out/'original-real-builder-files.json').open('x')as f:json.dump(records,f,indent=2);f.write('\n')
 with(out/'original-proof.json').open('x')as f:json.dump(proof,f,indent=2);f.write('\n')
 print(json.dumps({'ok':proof['ok'],'arch':proof.get('architecture'),'original_host_opt_unchanged':proof.get('original_host_opt_unchanged',False),'Main_changed':False,'all50_commercial':False}),flush=True)
sys.exit(0 if proof['ok']else 1)
