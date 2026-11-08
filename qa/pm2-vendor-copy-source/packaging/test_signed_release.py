import importlib.util
import io
import os
import pathlib
import subprocess
import tarfile
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("signed-release.py")
OPENSSL = os.environ.get("PANEL_OPENSSL") or ("/opt/homebrew/bin/openssl" if pathlib.Path("/opt/homebrew/bin/openssl").exists() else "openssl")
SPEC = importlib.util.spec_from_file_location("signed_release", SCRIPT)
signed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(signed)


class SignedReleaseTest(unittest.TestCase):
    def test_signature_archive_binding_and_unsafe_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            archive = root / "panel-0.1.0-dev.999-linux-amd64.tar.gz"
            prefix = "panel-0.1.0-dev.999-linux-amd64"
            with tarfile.open(archive, "w:gz") as tar:
                data = b"release-content"
                member = tarfile.TarInfo(prefix + "/RELEASE")
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            key = root / "private.pem"
            public = root / "public.pem"
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True, stdout=subprocess.DEVNULL)
            key.chmod(0o600)
            subprocess.run([OPENSSL, "pkey", "-in", str(key), "-pubout", "-out", str(public)], check=True, stdout=subprocess.DEVNULL)
            self.assertEqual(subprocess.run(["python3", str(SCRIPT), "--openssl", OPENSSL, "sign", str(archive), "--private-key", str(key)], capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(["python3", str(SCRIPT), "--openssl", OPENSSL, "verify", str(archive), "--public-key", str(public)], capture_output=True).returncode, 0)
            other_key = root / "other-private.pem"
            other_public = root / "other-public.pem"
            subprocess.run([OPENSSL, "genpkey", "-algorithm", "ED25519", "-out", str(other_key)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run([OPENSSL, "pkey", "-in", str(other_key), "-pubout", "-out", str(other_public)], check=True, stdout=subprocess.DEVNULL)
            self.assertNotEqual(subprocess.run(["python3", str(SCRIPT), "--openssl", OPENSSL, "verify", str(archive), "--public-key", str(other_public)], capture_output=True).returncode, 0)
            archive.write_bytes(archive.read_bytes() + b"tampered")
            self.assertNotEqual(subprocess.run(["python3", str(SCRIPT), "--openssl", OPENSSL, "verify", str(archive), "--public-key", str(public)], capture_output=True).returncode, 0)

            unsafe = root / "panel-0.1.0-dev.998-linux-amd64.tar.gz"
            with tarfile.open(unsafe, "w:gz") as tar:
                data = b"escape"
                member = tarfile.TarInfo("panel-0.1.0-dev.998-linux-amd64/../../escape")
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
            with self.assertRaises(ValueError):
                signed.extract_verified(unsafe, "0.1.0-dev.998", "amd64", root / "out")
            self.assertFalse((root / "escape").exists())


if __name__ == "__main__":
    unittest.main()
