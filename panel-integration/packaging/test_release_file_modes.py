import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest

spec=importlib.util.spec_from_file_location("release_file_modes",pathlib.Path(__file__).with_name("release-file-modes.py"))
modes=importlib.util.module_from_spec(spec)
spec.loader.exec_module(modes)

class ReleaseFileModesTests(unittest.TestCase):
    def test_strict_umask_public_programs_do_not_widen_private_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            private=pathlib.Path(temporary)
            root=private/"panel-release";root.mkdir(mode=0o700)
            (root/"bin").mkdir(mode=0o700);(root/"web/assets").mkdir(parents=True,mode=0o700)
            files={"bin/panel":b"program","bin/panel-executor":b"executor","web/assets/app.js":b"web","install.sh":b"installer","verify-release.sh":b"verifier","prune-releases.sh":b"pruner","SHA256SUMS":b"checksums"}
            for name,body in files.items():
                path=root/name;path.write_bytes(body);path.chmod(0o600)
            evidence=private/"proof.json";evidence.write_bytes(b"private evidence");evidence.chmod(0o600)
            before={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files}
            with self.assertRaises(ValueError):modes.payload_modes(root)
            modes.payload_modes(root,True);modes.payload_modes(root)
            self.assertEqual(before,{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in files})
            self.assertEqual(private.stat().st_mode&0o777,0o700)
            self.assertEqual(evidence.stat().st_mode&0o777,0o600)
            for name in files:
                self.assertEqual((root/name).stat().st_mode&0o777,0o755 if name in modes.EXECUTABLES else 0o644)
    def test_linked_payload_fails_before_any_permission_change(self):
        for kind in ["symlink","hardlink","root-link"]:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temporary:
                base=pathlib.Path(temporary);root=base/"release";root.mkdir(mode=0o700)
                target=base/"private.key";target.write_bytes(b"do not disclose");target.chmod(0o600)
                ordinary=root/"ordinary";ordinary.write_bytes(b"ordinary");ordinary.chmod(0o600)
                if kind=="root-link":
                    alias=base/"alias";alias.symlink_to(root,target_is_directory=True);checked=alias
                else:
                    checked=root
                    if kind=="symlink":(root/"linked").symlink_to(target)
                    else:os.link(target,root/"linked")
                with self.assertRaises(ValueError):modes.payload_modes(checked,True)
                self.assertEqual(target.read_bytes(),b"do not disclose")
                self.assertEqual(target.stat().st_mode&0o777,0o600)
                self.assertEqual(ordinary.stat().st_mode&0o777,0o600)
                self.assertEqual(root.stat().st_mode&0o777,0o700)

if __name__=="__main__":
    unittest.main()
