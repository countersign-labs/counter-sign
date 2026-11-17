# Copyright 2026 Haridarman Kumaresan
# SPDX-License-Identifier: Apache-2.0
"""
Shared test helpers: make the package importable from any pytest invocation
directory, load the committed vectors, and run the TypeScript reference through
tsx for the interop tests (skipped with a clear message when Node or the repo's
node_modules are not there).
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PACKAGE_ROOT = TESTS_DIR.parent
REPO_ROOT = TESTS_DIR.parents[2]
VECTORS_PATH = REPO_ROOT / "vectors" / "countersign-vectors.json"
TS_BRIDGE = TESTS_DIR / "support" / "ts_interop.ts"
TSX = REPO_ROOT / "node_modules" / ".bin" / "tsx"

sys.path.insert(0, str(PACKAGE_ROOT))


def load_vectors():
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def vector_key(name):
    """The secret/public pair the vectors file names ``name`` (agent, authority, ceo, ...)."""
    for k in load_vectors()["keys"]:
        if k["name"] == name:
            return k
    raise KeyError(name)


def _tsx_unavailable_reason():
    if shutil.which("node") is None:
        return "node is not on PATH; the TypeScript interop tests need Node 20+"
    if not TSX.exists():
        return f"{TSX} is missing; run `npm install` at the repository root for the interop tests"
    if not (REPO_ROOT / "src" / "receipt-log.ts").exists():
        return "the TypeScript reference source (src/) is not next to this client"
    return None


def _native_prefix():
    """
    On an Apple-silicon Mac, a Python running under Rosetta starts child
    processes as x86_64 too, and a universal ``node`` then cannot load the
    arm64-only esbuild that tsx uses. Run Node natively in that case.
    """
    if sys.platform != "darwin" or shutil.which("arch") is None:
        return []
    try:
        translated = subprocess.run(
            ["sysctl", "-in", "sysctl.proc_translated"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except Exception:
        return []
    return ["arch", "-arm64"] if translated == "1" else []


@pytest.fixture
def ts():
    """Run one command of tests/support/ts_interop.ts and return its JSON result."""
    reason = _tsx_unavailable_reason()
    if reason:
        pytest.skip(reason)
    prefix = _native_prefix()

    def run(command, request=None, *args):
        proc = subprocess.run(
            [*prefix, str(TSX), str(TS_BRIDGE), command, *[str(a) for a in args]],
            input=json.dumps(request or {}),
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=120,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"ts_interop {command} failed: {proc.stderr.strip()}")
        return json.loads(proc.stdout)

    return run
