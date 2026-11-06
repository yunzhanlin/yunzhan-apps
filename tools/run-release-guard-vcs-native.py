"""Preserve real compiler/VCS fixture outputs; this is not installed acceptance."""
import ast,hashlib,json,os,pathlib,platform,pwd,re,shlex,shutil,stat,subprocess,sys
os.umask(0o077)
ROOT=pathlib.Path(__file__).resolve().parents[1]
SDK=ROOT/'candidate/panel-integration-load-balance'
SPEC=json.loads((ROOT/'tools/release-guard-vcs-execution.json').read_bytes())
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def sources():
    index=json.loads((SDK/'source-sha256.json').read_bytes())
    assert index['release']['frozen_inputs_sha256']==SPEC['source_inputs_sha256']
    assert len(index['files'])==SPEC['source_sdk_files']==2467 and not index.get('test_overrides')
    actual={n:sha(SDK/n)for n in SPEC['source_files']}
    assert actual==SPEC['source_files'] and all(index['files'][n]==v for n,v in actual.items())
    module=ast.parse((SDK/'packaging/test_release_guard_vcs.py').read_bytes())
    methods=sorted(c.name+'.'+f.name for c in module.body if isinstance(c,ast.ClassDef)for f in c.body if isinstance(f,ast.FunctionDef)and f.name.startswith('test_'))
    assert methods==SPEC['python_methods'] and len(methods)==1
    return actual

def main():
    assert len(sys.argv)==2 and os.geteuid()==os.getegid()==0
    assert os.environ.get('GITHUB_ACTIONS')=='true'and os.environ.get('GITHUB_REPOSITORY')=='yunzhanlin/yunzhan-apps'
    assert platform.system()=='Linux'and platform.machine()in('x86_64','aarch64')
    owner=ROOT.stat();assert owner.st_uid!=0 and pwd.getpwuid(owner.st_uid).pw_name=='runner'
    before=sources();out=pathlib.Path(sys.argv[1]);out.mkdir(mode=0o700);created=[]
    def save(name,value):
        p=out/name
        with p.open('x')as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
        created.append(p)
    def once(label,args,env=None):
        save(label+'-intent.json',{'args':args,'maximum_submissions':1})
        a,b=out/(label+'.stdout'),out/(label+'.stderr')
        with a.open('xb')as stdout,b.open('xb')as stderr:
            created.extend((a,b));r=subprocess.run(args,cwd=SDK,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=180)
        save(label+'-exit.json',{'exit':r.returncode,'stdout_sha256':sha(a),'stderr_sha256':sha(b)})
        assert r.returncode==0,(label,r.returncode)
        return a.read_bytes(),b.read_text()
    try:
        save('original-source-intent.json',{'source_inputs_sha256':SPEC['source_inputs_sha256'],'source_files':before,'actual_native_systemd_install_acceptance':False})
        _,raw=once('original-fixture',[sys.executable,'-I','-B','-m','unittest','discover','-s',str(SDK/'packaging'),'-p','test_release_guard_vcs.py','-v'])
        passed=[]
        for line in raw.splitlines():
            m=re.fullmatch(r'(test_\w+) \(test_release_guard_vcs\.(\w+)(?:\.(test_\w+))?\) \.\.\. ok',line)
            if m:
                method,cls,repeated=m.groups();assert repeated is None or repeated==method;passed.append(cls+'.'+method)
        assert passed==SPEC['python_methods'] and re.search(r'\nRan 1 test in [0-9.]+s\n\nOK\n?\Z',raw)
        assert not re.search(r'(?:skipped|FAIL|ERROR|expected failure|unexpected success)',raw)
        lines=[s for s in(SDK/'packaging/build-release.sh').read_text().splitlines()if s.startswith('(cd "$BUILD_ROOT" && ')and'"$STAGE/$NAME/bin/panel-start-guard"'in s]
        assert len(lines)==1
        tokens=shlex.split(lines[0][len('(cd "$BUILD_ROOT" && '):-1]);split=tokens.index('go');assert tokens[split+1]=='build'
        architecture={'x86_64':'amd64','aarch64':'arm64'}[platform.machine()]
        env=dict(os.environ,GOFLAGS='-buildvcs=true -p=1',GOTOOLCHAIN='local')
        env.update({k:v.replace('$ARCH',architecture)for k,v in(token.split('=',1)for token in tokens[:split])})
        go=shutil.which('go');assert go
        args=[go,*tokens[split+1:]];target=out/'actual-native-startguard'
        slot=args.index('-o');assert args[slot+1]=='$STAGE/$NAME/bin/panel-start-guard';args[slot+1]=str(target)
        once('original-native-compiler',args,env);created.append(target)
        metadata,_=once('original-native-metadata',[go,'version','-m',str(target)])
        assert b'vcs='not in metadata and b'go1.27.2'in metadata
        assert sha(target)==SPEC['previous_signed_C67_v4_sha256'][architecture]
        assert sources()==before
        proof={'ok':True,'uid':os.geteuid(),'architecture':platform.machine(),'source_inputs_sha256':SPEC['source_inputs_sha256'],'source_files':before,'actual_PASS':1,'passed':passed,'skips':0,'original_exit':0,'actual_native_compiler_v4_matches_previous_signed_C67':True,'actual_native_v4_sha256':sha(target),'inherited_vcs_enabled_but_real_release_command_refuses_stamping':True,'actual_native_systemd_install_acceptance':False,'all50_commercial':False}
        save('qualified.json',proof);print(json.dumps(proof,sort_keys=True))
    finally:
        for p in created:
            st=p.lstat();assert stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==0
            os.chown(p,owner.st_uid,owner.st_gid)
        os.chown(out,owner.st_uid,owner.st_gid)

if __name__=='__main__':main()
