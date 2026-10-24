#!/usr/bin/env python3
"""Root Linux filesystem/SQLite/flock regressions; NOT host panel installation."""
import json,os,pathlib,subprocess,sys,unittest
assert os.geteuid()==0 and sys.platform.startswith('linux')and os.uname().machine=='x86_64'
if len(sys.argv)==1:
    result=subprocess.run(['/usr/bin/unshare','--mount','--propagation','private','/usr/bin/python3','-I','-B',str(pathlib.Path(__file__).resolve()),'--inside'],timeout=230)
    sys.exit(result.returncode)
assert sys.argv[1:]==['--inside']and os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt')
for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines():
    fields=line.split();assert not any(x.startswith('shared:')for x in fields[6:fields.index('-')])
os.umask(0o022)
repo=pathlib.Path(__file__).resolve().parents[1];source=repo/'panel-integration-geodata-admission'
suite=unittest.TestLoader().discover(str(source/'packaging'),pattern='test_*.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
value={'ok':result.wasSuccessful()and result.testsRun==264 and not result.skipped,
       'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
       'skips':len(result.skipped),'actual_Root_Linux_filesystem_SQLite_and_flock_fixtures':True,
       'normal_installed_programme_or_application_acceptance':False,'all50_commercial':False}
print(json.dumps(value,sort_keys=True),flush=True)
sys.exit(0 if value['ok']else 1)
