import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("freeze_source", pathlib.Path(__file__).with_name("freeze-source.py"))
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class SourceSnapshotTest(unittest.TestCase):
    def fixture(self, root):
        for name in snapshot.DIRECTORIES:
            (root / name).mkdir(parents=True, exist_ok=True)
        for name, content in {"go.mod": "module local/panel\n", "go.sum": "", "cmd/main.go": "package main\n", "web/package-lock.json": "{}", "web/node_modules/tool/bin.js": "old dependency", "packaging/install.sh": "#!/bin/sh\nexit 0\n"}.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (root / "packaging/install.sh").chmod(0o755)
        (root / "web/node_modules/.bin").mkdir()
        (root / "web/node_modules/.bin/tool").symlink_to("../tool/bin.js")

    def test_later_source_and_dependency_edits_cannot_change_frozen_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, dest = pathlib.Path(temporary) / "live", pathlib.Path(temporary) / "snapshot"
            self.fixture(root)
            result = snapshot.freeze(root, dest)
            (root / "cmd/main.go").write_text("broken later edit")
            (root / "web/node_modules/tool/bin.js").write_text("new dependency")
            self.assertEqual((dest / "cmd/main.go").read_text(), "package main\n")
            self.assertEqual((dest / "web/node_modules/.bin/tool").read_text(), "old dependency")
            self.assertEqual((dest / "packaging/install.sh").stat().st_mode & 0o777, 0o755)
            self.assertEqual(len(result["inputs_sha256"]), 64)
            self.assertEqual(os.readlink(dest / "web/node_modules/.bin/tool"), "../tool/bin.js")

    def test_edit_or_new_file_during_capture_aborts_and_removes_copy(self):
        for add in (False, True):
            with self.subTest(add=add), tempfile.TemporaryDirectory() as temporary:
                root, dest = pathlib.Path(temporary) / "live", pathlib.Path(temporary) / "snapshot"
                self.fixture(root)
                original_copy = snapshot.shutil.copy2
                changed = False

                def interrupted_copy(source, target):
                    nonlocal changed
                    result = original_copy(source, target)
                    if not changed:
                        changed = True
                        (root / ("internal/new.go" if add else "cmd/main.go")).write_text("changed during capture")
                    return result

                with patch.object(snapshot.shutil, "copy2", interrupted_copy), self.assertRaisesRegex(ValueError, "changed during snapshot"):
                    snapshot.freeze(root, dest)
                self.assertFalse(dest.exists())

    def test_external_dependency_link_rejected_without_copying_secret(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, dest = pathlib.Path(temporary) / "live", pathlib.Path(temporary) / "snapshot"
            self.fixture(root)
            secret = pathlib.Path(temporary) / "secret"
            secret.write_text("not a build input")
            (root / "web/node_modules/escape").symlink_to(secret)
            with self.assertRaises(ValueError):
                snapshot.freeze(root, dest)
            self.assertFalse(dest.exists())

    def test_existing_snapshot_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, dest = pathlib.Path(temporary) / "live", pathlib.Path(temporary) / "snapshot"
            self.fixture(root)
            snapshot.freeze(root, dest)
            with self.assertRaisesRegex(ValueError, "must not exist"):
                snapshot.freeze(root, dest)
            self.assertEqual((dest / "cmd/main.go").read_text(), "package main\n")


if __name__ == "__main__":
    unittest.main()
