// Go's -exec wrapper gives EACH test binary a fresh real Linux PID namespace.
// Compiler/cache/runner locks stay outside its /proc/locks view. No test code,
// lease parser, 100ms/8-read/4MiB budget, assertions or exit status is changed.
// PID1 waits for PID2+ so real owner identities never become the reserved PID1.
export function privatePIDNamespaceTestExecutor() {
 return Buffer.from(String.raw`#!/usr/bin/python3 -I
import os, sys
sys.dont_write_bytecode = True
if os.geteuid() != 0 or len(sys.argv) < 2 or not os.path.isabs(sys.argv[1]):
    raise SystemExit("Root and the actual absolute Go test binary are required")
child = r'''import os, subprocess, sys
if os.getpid() != 1 or os.getppid() != 0 or os.readlink('/proc/self') != '1':
    raise SystemExit("fresh PID1 and private real procfs are required")
result = subprocess.run(sys.argv[1:], check=False)
raise SystemExit(result.returncode if result.returncode >= 0 else 128 - result.returncode)
'''
os.execv('/usr/bin/unshare', ['/usr/bin/unshare', '--mount', '--pid', '--fork',
    '--mount-proc', '--propagation', 'private', '--kill-child=KILL',
    '/usr/bin/python3', '-I', '-B', '-c', child, *sys.argv[1:]])
`, 'utf8');
}
