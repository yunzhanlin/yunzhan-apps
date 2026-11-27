from pathlib import Path
import hashlib,json,os,pwd,secrets,shutil,subprocess,sys
os.umask(0o077);base=Path(__file__).resolve().parent;pins=json.loads((base/'pins.json').read_bytes());assets=Path(sys.argv[1]).resolve(strict=True);private=Path(sys.argv[2]).resolve(strict=True);owner=private.stat();assert os.geteuid()==0 and pwd.getpwuid(owner.st_uid).pw_name=='runner'and owner.st_mode&0o777==0o700;assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
def sha(f):return hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v,readable=False):
 with(private/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
 if readable:os.chown(private/n,owner.st_uid,owner.st_gid)
def once(label,args,timeout=1500):
 save(label+'-intent.json',{'args':args,'maximum_submissions':1})
 with(private/(label+'.stdout')).open('xb')as o,(private/(label+'.stderr')).open('xb')as e:r=subprocess.run(args,stdout=o,stderr=e,timeout=timeout)
 save(label+'-outcome.json',{'returncode':r.returncode,'stdout_sha256':sha(private/(label+'.stdout')),'stderr_sha256':sha(private/(label+'.stderr'))});assert r.returncode==0,(label,r.returncode)
once('old-normal-fresh-signed-install',['python3','-I','-B',str(base/'base/prepare-real-panel.py'),str(assets/'old'),str(private)])
original=json.loads((private/'real-panel-setup.json').read_bytes());role=Path('/var/lib/panel-executor')/('c766-local-only-'+secrets.token_hex(16));role.mkdir(mode=0o700);shutil.copyfile(base/'role-root.py',role/'case.py');plan={'source_inputs_sha256':pins['old']['programme_source_inputs_sha256'],'expected_hostname':Path('/etc/hostname').read_text().strip(),'expected_boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'original_marker':original['filename']};(role/'plan.json').open('x').write(json.dumps(plan));once('normal-old-mobile133-user132-and-scoped-MFA-fixture',['python3','-I','-B',str(role/'case.py'),str(role)])
upgrade=Path('/var/lib/panel-executor')/('c766-web-upgrade-'+secrets.token_hex(16));upgrade.mkdir(mode=0o700);new=pins['new'];filepins={}
for name,pin in new['programme_assets'].items():
 f=assets/'new'/name;assert f.stat().st_nlink==1 and not f.stat().st_mode&0o022 and sha(f)==pin['sha256'];target=upgrade/name;target.open('xb').write(f.read_bytes());assert sha(target)==pin['sha256'];filepins[name]=pin['sha256']
helper=base/'base/original-signed-release.py';assert sha(helper)==new['original_verifier_sha256'];shutil.copyfile(helper,upgrade/'trusted-signed-release.py');filepins['trusted-signed-release.py']=sha(helper);shutil.copyfile(base/'upgrade-root.py',upgrade/'upgrade.py');p={'archive':new['programme_archive'],'pins':filepins,'source':new['programme_source_inputs_sha256'],'version':new['programme_version'],'old_remote_case':str(role),'hostname':plan['expected_hostname'],'boot':plan['expected_boot']};(upgrade/'plan.json').open('x').write(json.dumps(p));once('normal-current-signed-upgrade',['python3','-I','-B',str(upgrade/'upgrade.py'),str(upgrade)])
for name,source in [('root-credentials.json',Path('/etc/panel/first-login.json')),('viewer-credentials.json',role/'local-viewer-device-credentials.json')]:
 target=private/name;target.open('xb').write(source.read_bytes());os.chown(target,owner.st_uid,owner.st_gid)
setup=json.loads((role/'owned-local-server-setup.json').read_bytes());save('owned-root-setup.json',{'ok':True,'role_root':str(role),'upgrade_root':str(upgrade),'site':setup['site'],'site_name':'C766 owned local native MFA','source_inputs_sha256':new['programme_source_inputs_sha256'],'normal_old133_then_current_SDK':True},True)
print(json.dumps({'ok':True,'architecture':'amd64','normal_old133_install_then_signed_SDK_upgrade':True,'native_App_runs':0}))
