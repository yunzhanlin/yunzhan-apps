"""Execute the actual installer dependency block with isolated command stubs."""
import os,pathlib,subprocess,tempfile,unittest
SOURCE=pathlib.Path(__file__).with_name('install.sh').read_text()
START=SOURCE.index('check_upgrade_dependencies(){')
END=SOURCE.index('  getent group panel',START)
BLOCK=SOURCE[START:END]+"fi\n"
STUBS="""dpkg-query(){
 printf '%s\\n' "$3" >> "$DEPS_LOG"
 if [[ "$3" == "${MISSING_PACKAGE:-}" ]]; then printf 'unpacked'; return 0; fi
 if [[ "$3" == "${UNKNOWN_PACKAGE:-}" ]]; then return 1; fi
 printf installed
}
apt-get(){
 printf '%s mode=%s\\n' "$*" "${NEEDRESTART_MODE:-unset}" >> "$APT_LOG"
 case "${FAIL_APT_PHASE:-}:$*" in
  update:update*|download:*--download-only*|install:*--no-download*)
   APT_FAILS=$((${APT_FAILS:-0}+1))
   if ((APT_FAILS<=${FAIL_APT_COUNT:-3})); then return "${FAIL_APT_STATUS:-100}"; fi;;
 esac
 return 0
}
sleep(){ printf '%s\\n' "$*" >> "$SLEEP_LOG"; }
"""
class InstallDependencyPolicyTest(unittest.TestCase):
 def run_block(self,platform='ubuntu-24.04',fresh=0,services=0,preflight=0,**extra):
  with tempfile.TemporaryDirectory() as directory:
   env=os.environ.copy();env.update(PANEL_PLATFORM=platform,ID=platform.split('-')[0],PANEL_VERSION='0.1.0-dev.fixture',FRESH=str(fresh),NO_SERVICES=str(services),PREFLIGHT_ONLY=str(preflight),APT_LOG=directory+'/apt',DEPS_LOG=directory+'/deps',SLEEP_LOG=directory+'/sleep',**extra)
   result=subprocess.run(['bash','-eu','-c',STUBS+BLOCK],env=env,capture_output=True,text=True)
   logs={name:pathlib.Path(directory,name).read_text().splitlines() if pathlib.Path(directory,name).exists() else [] for name in ('apt','deps','sleep')}
   return result,logs
 def test_upgrade_never_runs_apt_for_supported_platforms(self):
  for platform in ('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04'):
   with self.subTest(platform=platform):
    result,logs=self.run_block(platform);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(logs['apt'],[]);self.assertIn('nginx',logs['deps']);self.assertIn('libpng-dev',logs['deps'])
    self.assertIn('libaio1' if platform in ('debian-12','ubuntu-22.04') else 'libaio1t64',logs['deps'])
    self.assertIn('libfreetype6-dev' if platform in ('debian-12','ubuntu-22.04') else 'libfreetype-dev',logs['deps'])
 def test_missing_or_not_fully_installed_dependency_rejects_before_apt(self):
  for variable in ('MISSING_PACKAGE','UNKNOWN_PACKAGE'):
   result,logs=self.run_block(**{variable:'libpng-dev'});self.assertNotEqual(result.returncode,0);self.assertIn('libpng-dev',result.stderr);self.assertIn('no APT or service changes made',result.stderr);self.assertEqual(logs['apt'],[])
 def test_upgrade_preflight_checks_missing_dependencies(self):
  result,logs=self.run_block(preflight=1,MISSING_PACKAGE='nginx');self.assertNotEqual(result.returncode,0);self.assertNotIn('preflight passed',result.stdout);self.assertEqual(logs['apt'],[])
  result,logs=self.run_block(preflight=1);self.assertEqual(result.returncode,0);self.assertIn('preflight passed without changes',result.stdout);self.assertEqual(logs['apt'],[])
 def test_first_install_does_not_upgrade_existing_packages_or_restart_unrelated_services(self):
  for platform in ('debian-12','debian-13','ubuntu-22.04','ubuntu-24.04','ubuntu-26.04'):
   with self.subTest(platform=platform):
    result,logs=self.run_block(platform,fresh=1)
    self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(logs['deps'],[])
    self.assertEqual(len(logs['apt']),3)
    self.assertTrue(logs['apt'][0].startswith('update --error-on=any '))
    for line in logs['apt']:
     self.assertIn('-o Acquire::Retries=0',line)
     self.assertIn('-o Acquire::http::Timeout=30',line)
     self.assertIn('-o Acquire::https::Timeout=30',line)
     self.assertTrue(line.endswith('mode=l'))
    self.assertIn('install -y --no-upgrade --no-install-recommends --download-only',logs['apt'][1])
    self.assertIn('install -y --no-upgrade --no-install-recommends --no-download',logs['apt'][2])
    self.assertEqual(logs['apt'][1].replace('--download-only','--no-download'),logs['apt'][2])
    for forbidden in ('--ignore-missing','--fix-missing','--allow-unauthenticated','--allow-insecure','Verify-Peer','Verify-Host','Sandbox::User','ForceIPv','-qq'):
     self.assertTrue(all(forbidden not in line for line in logs['apt']),forbidden)
 def test_fresh_update_or_download_failure_never_attempts_package_install(self):
  for phase,count in (('update',3),('download',4),('install',3)):
   with self.subTest(phase=phase):
    result,logs=self.run_block(fresh=1,FAIL_APT_PHASE=phase)
    self.assertEqual(result.returncode,100,result.stderr)
    self.assertEqual(len(logs['apt']),count)
    if phase!='install': self.assertTrue(all('--no-download' not in line for line in logs['apt']))
    self.assertEqual(logs['sleep'],['2','4'] if phase!='install' else [])
 def test_transient_acquisition_recovers_but_package_install_runs_once(self):
  for phase in ('update','download'):
   for failures in (1,2):
    with self.subTest(phase=phase,failures=failures):
     result,logs=self.run_block(fresh=1,FAIL_APT_PHASE=phase,FAIL_APT_COUNT=str(failures))
     self.assertEqual(result.returncode,0,result.stderr)
     self.assertEqual(len(logs['apt']),3+failures)
     self.assertEqual(sum('--no-download' in line for line in logs['apt']),1)
     self.assertEqual(logs['sleep'],['2','4'][:failures])
 def test_crashed_acquisition_is_not_retried(self):
  for phase,count in (('update',1),('download',2)):
   result,logs=self.run_block(fresh=1,FAIL_APT_PHASE=phase,FAIL_APT_STATUS='137')
   self.assertEqual(result.returncode,137,result.stderr);self.assertEqual(len(logs['apt']),count);self.assertEqual(logs['sleep'],[])
 def test_acquisition_helper_refuses_install_mutation_or_other_commands(self):
  start=SOURCE.index('fresh_apt_acquire(){');end=SOURCE.index('\nif ((NO_SERVICES==0));',start)
  for command in ('fresh_apt_acquire apt-get install -y nginx','fresh_apt_acquire apt-get install --download-only --no-download nginx','fresh_apt_acquire apt-get remove nginx','fresh_apt_acquire systemctl restart nginx'):
   result=subprocess.run(['bash','-eu','-c',SOURCE[start:end]+command],capture_output=True,text=True)
   self.assertEqual(result.returncode,2,result.stderr)
 def test_no_services_and_first_install_preflight_are_read_only(self):
  for flags in ({'services':1},{'fresh':1,'preflight':1}):
   result,logs=self.run_block(**flags);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(logs['apt'],[]);self.assertEqual(logs['deps'],[])
 def test_upgrade_preserves_private_executor_child_ownership(self):
  lines=[line.strip() for line in SOURCE.splitlines() if 'chown' in line and '/var/lib/panel-executor' in line]
  self.assertIn('chown root:panel /var/lib/panel-executor',lines)
  self.assertTrue(all('-R' not in line and '--recursive' not in line for line in lines))
  command='chown(){ printf "%s\\n" "$*"; };'+next(line for line in lines if line=='chown root:panel /var/lib/panel-executor')
  result=subprocess.run(['bash','-eu','-c',command],capture_output=True,text=True)
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertEqual(result.stdout,'root:panel /var/lib/panel-executor\n')
if __name__=='__main__':unittest.main()
