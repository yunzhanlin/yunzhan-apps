#!/usr/bin/env python3
"""Detached Ed25519 release signing and out-of-band verification.

Keep this verifier and the trusted public key outside the release archive.
"""

import argparse
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import tempfile


ARCHIVE_NAME = re.compile(r"panel-([0-9]+\.[0-9]+\.[0-9]+(?:[.-][a-z0-9]+)*)-linux-(amd64|arm64)\.tar\.gz")
MAX_MEMBERS = 5000
MAX_UNPACKED_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_BYTES = 500 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def copy_bounded(source, destination, limit):
    copied = 0
    with source.open("rb") as original, destination.open("xb") as stable:
        while block := original.read(min(1024 * 1024, limit - copied + 1)):
            copied += len(block)
            if copied > limit:
                raise ValueError("signed release input exceeds limits")
            stable.write(block)


def copy_root_private_condition(source, destination):
    """Preserve one explicit Root condition; never follow a caller link."""
    source = pathlib.Path(source)
    if not source.is_absolute() or '..' in source.parts or str(source).startswith('//'):
        raise ValueError('recovery condition must be a canonical absolute Root-private file')
    for parent in reversed(source.parents):
        info = parent.lstat()
        if parent == pathlib.Path('/tmp'):
            relative = source.relative_to(parent)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777 or len(relative.parts) < 2:
                raise ValueError('unsafe temporary recovery condition parent')
            private = (parent/relative.parts[0]).lstat()
            if not stat.S_ISDIR(private.st_mode) or private.st_uid != 0 or stat.S_IMODE(private.st_mode) != 0o700:
                raise ValueError('recovery condition temporary scope is not Root-private')
        elif not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('recovery condition has an unsafe or linked parent')
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600 or not 1 <= before.st_size <= 2048:
            raise ValueError('recovery condition must be a bounded Root0600 independent file')
        raw = os.read(descriptor, 2049)
        identity = lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(os.fstat(descriptor)) or identity(before) != identity(source.lstat()):
            raise ValueError('original recovery condition changed during its one bounded copy')
    finally:
        os.close(descriptor)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stable:
        stable.write(raw)
        stable.flush()
        os.fsync(stable.fileno())


def archive_identity(archive):
    match = ARCHIVE_NAME.fullmatch(archive.name)
    if match is None:
        raise ValueError("invalid release archive name")
    return match.group(1), match.group(2)


def manifest_bytes(archive, digest):
    return ("PANEL_SIGNED_FORMAT=1\n" + f"PANEL_ARCHIVE={archive.name}\n" + f"PANEL_SHA256={digest}\n").encode("ascii")


def sign(args):
    archive = args.archive.resolve(strict=True)
    archive_identity(archive)
    key = args.private_key.resolve(strict=True)
    if key.stat().st_mode & 0o077:
        raise ValueError("private key must be readable only by its owner")
    description = subprocess.check_output([args.openssl, "pkey", "-in", str(key), "-text_pub", "-noout"], stderr=subprocess.DEVNULL)
    if not description.startswith(b"ED25519 Public-Key:"):
        raise ValueError("release signing key must be Ed25519")
    manifest = pathlib.Path(str(archive) + ".manifest")
    signature = pathlib.Path(str(archive) + ".sig")
    if manifest.exists() or signature.exists():
        raise ValueError("signature output already exists")
    data = manifest_bytes(archive, sha256(archive))
    with tempfile.TemporaryDirectory(prefix="panel-sign-") as temporary:
        input_path = pathlib.Path(temporary) / "manifest"
        output_path = pathlib.Path(temporary) / "signature"
        input_path.write_bytes(data)
        subprocess.run([args.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(input_path), "-out", str(output_path)], check=True, stdout=subprocess.DEVNULL)
        with manifest.open("xb") as target:
            target.write(data)
        with signature.open("xb") as target:
            target.write(output_path.read_bytes())
    print(f"signed {archive.name} sha256={sha256(archive)}")


def verify(args):
    archive = args.archive.resolve(strict=True)
    version, arch = archive_identity(archive)
    manifest = args.manifest or pathlib.Path(str(archive) + ".manifest")
    signature = args.signature or pathlib.Path(str(archive) + ".sig")
    public_key = args.public_key.resolve(strict=True)
    description = subprocess.check_output([args.openssl, "pkey", "-pubin", "-in", str(public_key), "-text_pub", "-noout"], stderr=subprocess.DEVNULL)
    if not description.startswith(b"ED25519 Public-Key:"):
        raise ValueError("release trust key must be Ed25519")
    if args.action in ("install", "recover-filesync"):
        key_info = args.public_key.lstat()
        if not stat.S_ISREG(key_info.st_mode) or key_info.st_uid != 0 or key_info.st_mode & 0o022:
            raise ValueError("installer trust key must be a root-owned regular file without group/other write")
    manifest = manifest.resolve(strict=True)
    signature = signature.resolve(strict=True)
    if manifest.stat().st_size > 512 or signature.stat().st_size != 64 or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("signed release input exceeds limits")
    subprocess.run([args.openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key), "-in", str(manifest), "-sigfile", str(signature)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    actual = sha256(archive)
    expected = manifest_bytes(archive, actual)
    if manifest.read_bytes() != expected:
        raise ValueError("signed manifest does not match archive name or SHA-256")
    return archive, version, arch, actual


def extract_verified(archive, version, arch, target):
    prefix = f"panel-{version}-linux-{arch}"
    count = 0
    total = 0
    seen = set()
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        for member in members:
            count += 1
            total += member.size if member.isfile() else 0
            path = pathlib.PurePosixPath(member.name)
            if count > MAX_MEMBERS or total > MAX_UNPACKED_BYTES:
                raise ValueError("release archive exceeds extraction limits")
            canonical = str(path)
            if canonical in seen or not path.parts or path.is_absolute() or ".." in path.parts or path.parts[0] != prefix or not (member.isdir() or member.isfile()):
                raise ValueError(f"unsafe release archive member: {member.name}")
            seen.add(canonical)
        for member in members:
            destination = target.joinpath(*pathlib.PurePosixPath(member.name).parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                destination.chmod(member.mode & 0o755)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("release archive member cannot be read")
            with destination.open("xb") as output:
                while block := stream.read(1024 * 1024):
                    output.write(block)
            destination.chmod(member.mode & 0o755)
    return target / prefix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3 executable")
    actions = parser.add_subparsers(dest="action", required=True)
    signer = actions.add_parser("sign")
    signer.add_argument("archive", type=pathlib.Path)
    signer.add_argument("--private-key", type=pathlib.Path, required=True)
    for action in ("verify", "install", "recover-filesync"):
        sub = actions.add_parser(action)
        sub.add_argument("archive", type=pathlib.Path)
        sub.add_argument("--public-key", type=pathlib.Path, required=True)
        sub.add_argument("--manifest", type=pathlib.Path)
        sub.add_argument("--signature", type=pathlib.Path)
        if action == "install":
            sub.add_argument("--root", type=pathlib.Path)
            sub.add_argument("--no-services", action="store_true")
            sub.add_argument("--preflight-only", action="store_true")
        elif action == "recover-filesync":
            sub.add_argument("--condition", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "sign":
            sign(args)
            return 0
        if args.action == "verify":
            archive, version, arch, digest = verify(args)
            print(f"trusted signature and archive verified: {archive.name} sha256={digest}")
            return 0
        if os.geteuid() != 0:
            raise ValueError("signed installer must run as root")
        with tempfile.TemporaryDirectory(prefix="panel-signed-install-") as temporary:
            staging = pathlib.Path(temporary)
            source_archive = args.archive.resolve(strict=True)
            archive_identity(source_archive)
            source_manifest = (args.manifest or pathlib.Path(str(source_archive) + ".manifest")).resolve(strict=True)
            source_signature = (args.signature or pathlib.Path(str(source_archive) + ".sig")).resolve(strict=True)
            args.archive = staging / source_archive.name
            args.manifest = staging / "manifest"
            args.signature = staging / "signature"
            copy_bounded(source_archive, args.archive, MAX_ARCHIVE_BYTES)
            copy_bounded(source_manifest, args.manifest, 512)
            copy_bounded(source_signature, args.signature, 64)
            archive, version, arch, digest = verify(args)
            release = extract_verified(archive, version, arch, pathlib.Path(temporary))
            expected_release = f"PANEL_FORMAT=1\nPANEL_VERSION={version}\nPANEL_OS=linux\nPANEL_ARCH={arch}\n"
            if (release / "RELEASE").read_text(encoding="ascii") != expected_release:
                raise ValueError("archive metadata does not match signed archive name")
            subprocess.run(["bash", str(release / "verify-release.sh"), str(release)], check=True)
            if args.action == "recover-filesync":
                if not sys.platform.startswith('linux'):
                    raise ValueError('signed filesync recovery requires the actual Linux host')
                condition = staging / "filesync-original-condition.json"
                copy_root_private_condition(args.condition, condition)
                recovered = subprocess.run(["/usr/bin/python3", "-I", "-B", str(release / "upgrade-release.py"),
                                            "recover-filesync", str(release), "--condition", str(condition)], check=False)
                return recovered.returncode
            installer_args = []
            if args.root:
                installer_args.extend(["--root", str(args.root)])
            if args.no_services:
                installer_args.append("--no-services")
            if args.preflight_only:
                installer_args.append("--preflight-only")
            installed = subprocess.run(["bash", str(release / "install.sh"), *installer_args], check=False)
            return installed.returncode
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"signed release rejected: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
