"""Real strict checksum parsing, original escaped names and fail-closed file reads."""
import hashlib
import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("release_checksum_policy",HERE/"release-file-modes.py")
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)

def line(name,data,binary=False):
    raw=os.fsencode(name);escaped=any(c in raw for c in (b"\\",b"\n",b"\r"))
    raw=raw.replace(b"\\",b"\\\\").replace(b"\n",b"\\n").replace(b"\r",b"\\r")
    return (b"\\" if escaped else b"")+hashlib.sha256(data).hexdigest().encode()+(b" *" if binary else b"  ")+raw+b"\n"

class ReleaseChecksumTests(unittest.TestCase):
    def fixture(self,root):
        values={"bin/program":b"original executable\n",r"systemd/var-cache-panel\x2dapache\x2dbody.mount":b"original mount\n",
                "web/space ' quote":b"public page", "web/new\nline":b"real newline",r"web/new\nline":b"literal backslash n",
                "web/carriage\rreturn":b"real carriage return", "web/empty":b""}
        for name,data in values.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        sums=b"".join(line(name,data,i%2==0)for i,(name,data)in enumerate(values.items()))
        (root/"SHA256SUMS").write_bytes(sums)
        return values,sums
    def snapshot(self,root):
        return {str(p.relative_to(root)):(policy._identity(p.lstat()),hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink()else None)for p in [root,*root.rglob("*")]}
    def test_escaped_mount_newline_carriage_and_literal_backslash_are_distinct_and_read_only(self):
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);values,_=self.fixture(root);before=self.snapshot(root)
            self.assertEqual(policy.payload_checksums(root),len(values));self.assertEqual(self.snapshot(root),before)
    def test_every_line_and_entire_payload_are_required(self):
        for mutation in ("malformed","blank","duplicate","unknown-escape","trailing-escape","absolute","parent","dot","double-separator","self","missing","additional","bad-digest","NUL","CRLF"):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory()as directory:
                root=pathlib.Path(directory);values,sums=self.fixture(root);name="bin/program";data=values[name]
                bad={"malformed":sums+b"not a checksum\n","blank":sums+b"\n","duplicate":sums+line(name,data),
                     "unknown-escape":sums+b"\\"+b"0"*64+b"  bad\\q\n","trailing-escape":sums+b"\\"+b"0"*64+b"  bad\\\n",
                     "absolute":sums+line("/etc/passwd",b""),"parent":sums+line("../outside",b""),"dot":sums+line("./bin/program",data),
                     "double-separator":sums+line("bin//program",data),"self":sums+line("SHA256SUMS",sums),
                     "missing":sums[len(line(name,data,True)):],"bad-digest":sums.replace(hashlib.sha256(data).hexdigest().encode(),b"0"*64,1),
                     "NUL":sums+b"\0","CRLF":sums.replace(b"\n",b"\r\n")}
                if mutation=="additional":(root/"web/unlisted").write_bytes(b"not in signed checksum manifest")
                else:(root/"SHA256SUMS").write_bytes(bad[mutation])
                before=self.snapshot(root)
                with self.assertRaises(ValueError):policy.payload_checksums(root)
                self.assertEqual(self.snapshot(root),before)
    def test_links_and_special_files_never_redirect_hashing(self):
        for kind in ("symlink-file","symlink-directory","hardlink","fifo","root-link"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as directory:
                base=pathlib.Path(directory);root=base/"release";root.mkdir();self.fixture(root);target=root/"bin/program"
                if kind=="root-link":
                    link=base/"linked";link.symlink_to(root,target_is_directory=True)
                    with self.assertRaises(OSError):policy.payload_checksums(link)
                    continue
                if kind=="symlink-directory":
                    (root/"bin").rename(base/"outside");(root/"bin").symlink_to(base/"outside",target_is_directory=True)
                else:
                    target.unlink()
                    if kind=="symlink-file":target.symlink_to(root/"web/empty")
                    elif kind=="hardlink":os.link(root/"web/empty",target)
                    else:os.mkfifo(target)
                with self.assertRaises((ValueError,OSError)):policy.payload_checksums(root)
    def test_content_change_after_inventory_and_after_hash_is_refused(self):
        for moment in ("before-open","after-hash"):
            with self.subTest(moment=moment),tempfile.TemporaryDirectory()as directory:
                root=pathlib.Path(directory);self.fixture(root);target=root/"bin/program"
                if moment=="before-open":
                    original=policy._open_release_file
                    def change(fd,name,records):
                        if name=="bin/program":target.write_bytes(b"replacement after inventory")
                        return original(fd,name,records)
                    patch=mock.patch.object(policy,"_open_release_file",side_effect=change)
                else:
                    original=policy._release_tree;calls=[]
                    def change(fd):
                        calls.append(1)
                        if len(calls)==2:target.write_bytes(b"replacement after hashing")
                        return original(fd)
                    patch=mock.patch.object(policy,"_release_tree",side_effect=change)
                with patch,self.assertRaises(ValueError):policy.payload_checksums(root)
    def test_unescaped_literal_backslashes_and_uppercase_binary_digest_are_supported(self):
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);name=r"literal\n";data=b"literal";(root/name).write_bytes(data)
            (root/"SHA256SUMS").write_bytes(hashlib.sha256(data).hexdigest().upper().encode()+b" *"+name.encode())
            self.assertEqual(policy.payload_checksums(root),1)

    def test_manifest_and_sparse_payload_budgets_refuse_before_hashing(self):
        for kind in ("empty","oversized-manifest","too-many-lines","sparse-payload"):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory()as directory:
                root=pathlib.Path(directory);self.fixture(root)
                if kind=="empty":(root/"SHA256SUMS").write_bytes(b"")
                elif kind=="oversized-manifest":(root/"SHA256SUMS").write_bytes(b"x"*((2<<20)+1))
                elif kind=="too-many-lines":(root/"SHA256SUMS").write_bytes(line("same",b"")*10000)
                else:
                    with(root/"bin/program").open("r+b")as stream:stream.truncate((2<<30)+1)
                with self.assertRaises(ValueError):policy.payload_checksums(root)

    def test_growing_file_is_bounded_by_its_original_size(self):
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);self.fixture(root);target=root/"bin/program"
            original=hashlib.sha256;changed=[]
            class GrowingDigest:
                def __init__(self):self.digest=original()
                def update(self,block):
                    self.digest.update(block)
                    if not changed:
                        changed.append(True)
                        with target.open("ab")as stream:stream.write(b"new bytes after first read")
                def hexdigest(self):return self.digest.hexdigest()
            with mock.patch.object(policy.hashlib,"sha256",side_effect=GrowingDigest),self.assertRaisesRegex(ValueError,"grew beyond"):
                policy.payload_checksums(root)

if __name__=="__main__":unittest.main()
