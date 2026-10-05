#!/usr/bin/env python3
"""Capture checked build inputs before compiling; never follow external links."""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat


DIRECTORIES = ("cmd", "internal", "dev", "packaging", "scripts", "web/src", "web/public", "web/node_modules")
GENERATED_DIRECTORIES = {"__pycache__", ".vite", ".vite-temp", ".cache"}


def input_paths(root):
    paths = [root / "go.mod", root / "go.sum"]
    paths.extend(p for p in (root / "web").iterdir() if p.is_file() and not p.name.startswith("."))
    for name in DIRECTORIES:
        base = root / name
        if not base.is_dir() or base.is_symlink():
            raise ValueError(f"missing or linked input directory: {name}")
        paths.extend(p for p in base.rglob("*") if (p.is_file() or p.is_symlink()) and not GENERATED_DIRECTORIES.intersection(p.parts) and p.name != ".DS_Store")
    return sorted(set(paths))


def describe(root, path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        relative = path.relative_to(root).as_posix()
        if not relative.startswith("web/node_modules/"):
            raise ValueError(f"linked source input: {relative}")
        # npm's .bin links are copied unchanged and must stay in this snapshot.
        path.resolve(strict=True).relative_to((root / "web/node_modules").resolve())
        return {"link": os.readlink(path)}
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("build input is not an ordinary file")
    sha = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            sha.update(block)
    return {"sha256": sha.hexdigest(), "mode": stat.S_IMODE(info.st_mode), "bytes": info.st_size}


def describe_inputs(root):
    return {p.relative_to(root).as_posix(): describe(root, p) for p in input_paths(root)}


def freeze(root, destination):
    root = root.resolve(strict=True)
    if destination.is_symlink() or destination.exists():
        raise ValueError("snapshot destination must not exist")
    # Hash before copying, hash the copy, then hash the live inputs again.
    # Any edit or added/deleted file during capture aborts before compilation.
    before = describe_inputs(root)
    destination.mkdir(mode=0o700)
    try:
        for name in DIRECTORIES:
            (destination / name).mkdir(parents=True, exist_ok=True)
        for name, item in before.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if "link" in item:
                target.symlink_to(item["link"])
            else:
                shutil.copy2(root / name, target)
        if describe_inputs(destination) != before or describe_inputs(root) != before:
            raise ValueError("build inputs changed during snapshot; retry with a new capture")
        encoded = json.dumps(before, sort_keys=True, separators=(",", ":")).encode()
        result = {"format": 1, "inputs_sha256": hashlib.sha256(encoded).hexdigest(), "files": before}
        (destination / "SOURCE_INPUTS.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        return result
    except BaseException:
        # Cleanup errors must never hide the reason this capture was rejected.
        shutil.rmtree(destination, ignore_errors=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("destination", type=pathlib.Path)
    args = parser.parse_args()
    try:
        result = freeze(args.root, args.destination)
        print(f"frozen build inputs: {len(result['files'])} files sha256={result['inputs_sha256']}")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"source snapshot rejected: {exc}\n")


if __name__ == "__main__":
    main()
