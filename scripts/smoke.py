#!/usr/bin/env python3
"""Live apt smoke: fetch a real package through the plugin, the way
the core does. Requires apt on PATH and network access to the
configured mirrors. Exercises:

  1. unpinned fetch of `hello` — resolves latest, stages bin/hello
  2. pinned fetch of that exact version — identical tree (reproducible)
  3. locked fetch with a bogus sha256 — must fail loudly (A04)

Usage: python3 scripts/smoke.py [path-to-binary] [package]
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_PACKAGE = "hello"


def exchange(binary: str, dest: Path, args: dict, locked: dict | None = None):
    request = {"op": "fetch", "args": args, "dest_dir": str(dest)}
    if locked is not None:
        request["locked"] = locked
    child = subprocess.run(
        [binary],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        timeout=300,
    )
    messages = [
        json.loads(line)
        for line in child.stdout.splitlines()
        if line.strip() and line.lstrip().startswith("{")
    ]
    responses = [m for m in messages if m.get("type") == "response"]
    diagnostics = [
        m["diagnostic"] for m in messages if m.get("type") == "diagnostic"
    ]
    return child, responses, diagnostics


def tree_hash(dest: Path) -> str:
    entries = []
    for path in sorted(dest.rglob("*")):
        rel = path.relative_to(dest).as_posix()
        if path.is_symlink():
            entries.append(f"L{rel}\0{path.readlink()}")
        elif path.is_file():
            entries.append(f"F{rel}\0{hashlib.sha256(path.read_bytes()).hexdigest()}")
        else:
            entries.append(f"D{rel}\0")
    return hashlib.sha256("\n".join(entries).encode()).hexdigest()


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "target/debug/gripfetch-apt"
    package = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PACKAGE
    binary = str(Path(binary).resolve())

    # 1. unpinned: resolve latest and stage it
    with tempfile.TemporaryDirectory() as first:
        dest = Path(first)
        child, responses, diagnostics = exchange(binary, dest, {"package": package})
        errors = [d for d in diagnostics if d.get("severity") == "error"]
        assert child.returncode == 0, f"unpinned fetch exited {child.returncode}: {errors}"
        assert len(responses) == 1, f"expected one response, got {len(responses)}"
        result = responses[0]["result"]
        version = result["version"]
        # result.sha256 = canonical tree hash (what the core pins);
        # provenance.sha256 = the .deb transport hash
        tree_reported = result["sha256"]
        provenance = result["provenance"]
        assert provenance["package"] == package
        assert provenance["version"] == version
        assert provenance["sha256"] and provenance["sha256"] != tree_reported, (
            "provenance carries the .deb sha256, distinct from the tree hash"
        )
        assert provenance["mirror"], "provenance must name the mirror"
        assert provenance["apt_version"], "provenance must name the apt version"
        staged_bin = dest / "bin" / package
        assert staged_bin.is_file(), f"expected bin/{package} staged"
        assert staged_bin.stat().st_mode & 0o111, "staged binary must be executable"
        resolved_latest = any(d["code"] == "W01" for d in diagnostics)
        assert resolved_latest, "an unpinned fetch must warn that it resolved latest"
        hash_one = tree_hash(dest)
        assert tree_reported == hash_one, "response sha256 must BE the staged tree hash"
        print(f"  1. unpinned fetch ok: {package} {version} from {provenance['mirror']}")
        print(
            f"     deb sha256 {provenance['sha256'][:16]}…  "
            f"tree {hash_one[:12]}…  bin/{package} executable"
        )

    # capture what the core would pin: url + version + tree hash
    # (the core records url/version from the response; locked.sha256
    # is its canonical tree hash of the staged payload)
    pin_url = result["url"]

    # 2. pinned to exactly that version: byte-identical tree
    with tempfile.TemporaryDirectory() as second:
        dest = Path(second)
        child, responses, diagnostics = exchange(
            binary, dest, {"package": package, "version": version}
        )
        errors = [d for d in diagnostics if d.get("severity") == "error"]
        assert child.returncode == 0, f"pinned fetch exited {child.returncode}: {errors}"
        assert responses[0]["result"]["version"] == version
        assert not any(d["code"] == "W01" for d in diagnostics), "pinned fetch must not re-resolve"
        hash_two = tree_hash(dest)
        assert hash_one == hash_two, "same pin must stage a byte-identical tree"
        # the advisory response sha256 must BE the canonical tree hash
        assert responses[0]["result"]["sha256"] == hash_two
        print(f"  2. pinned fetch ok: same tree hash {hash_two[:12]}… (reproducible)")

    # 3. locked with the pin the core recorded (tree hash): reproduces
    with tempfile.TemporaryDirectory() as third:
        dest = Path(third)
        child, responses, diagnostics = exchange(
            binary,
            dest,
            {"package": package, "version": version},
            locked={"url": pin_url, "version": version, "sha256": hash_one},
        )
        errors = [d for d in diagnostics if d.get("severity") == "error"]
        assert child.returncode == 0, f"locked reproduce fetch exited {child.returncode}: {errors}"
        assert not any(d.get("severity") == "error" for d in diagnostics)
        assert tree_hash(dest) == hash_one, "locked fetch must reproduce the exact tree"
        print("  3. locked reproduce ok: tree hash matches the pin")

    # 4. locked with a tampered sha256: loud A04 after staging
    with tempfile.TemporaryDirectory() as fourth:
        dest = Path(fourth)
        child, responses, diagnostics = exchange(
            binary,
            dest,
            {"package": package, "version": version},
            locked={
                "url": pin_url,
                "version": version,
                "sha256": "0" * 64,
            },
        )
        errors = [d for d in diagnostics if d.get("severity") == "error"]
        assert child.returncode != 0, "a hash mismatch must fail the exchange"
        assert any(d["code"] == "A04" for d in errors), f"expected A04, got: {errors}"
        assert any("tree sha256" in d["message"] for d in errors), "A04 names the staged tree hash"
        print("  4. tampered lock rejected: A04 tree-hash mismatch, nonzero exit")

    print("live smoke: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
