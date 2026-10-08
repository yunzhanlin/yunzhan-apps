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
apt-get(){ printf '%s mode=%s\\n' "$*" "${NEEDRESTART_MODE:-unset}" >> "$APT_LOG"; }
"""
class InstallDependencyPolicyTest(unittest.TestCase):
 def run_block(self,platform='ubuntu-24.04',fresh=0,services=0,preflight=0,**extra):
  with tempfile.TemporaryDirectory() as directory:
   env=os.environ.copy();env.update(PANEL_PLATFORM=platform,ID=platform.split('-')[0],PANEL_VERSION='0.1.0-dev.fixture',FRESH=str(fresh),NO_SERVICES=str(services),PREFLIGHT_ONLY=str(preflight),APT_LOG=directory+'/apt',DEPS_LOG=directory+'/deps',**extra)
   result=subprocess.run(['bash','-eu','-c',STUBS+BLOCK],env=env,capture_output=True,text=True)
   logs={name:pathlib.Path(directory,name).read_text().splitlines() if pathlib.Path(directory,name).exists() else [] for name in ('apt','deps')}
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
  result,logs=self.run_block(fresh=1);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(logs['deps'],[]);self.assertEqual(len(logs['apt']),2);self.assertEqual(logs['apt'][0],'update mode=l');self.assertIn('install -y --no-upgrade --no-install-recommends',logs['apt'][1]);self.assertTrue(logs['apt'][1].endswith('mode=l'))
 def test_no_services_and_first_install_preflight_are_read_only(self):
  for flags in ({'services':1},{'fresh':1,'preflight':1}):
   result,logs=self.run_block(**flags);self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(logs['apt'],[]);self.assertEqual(logs['deps'],[])
if __name__=='__main__':unittest.main()
