#!/usr/bin/env python3
"""
Generate a small CycloneDX JSON SBOM for OpenCV bundled (vendored) deps under 3rdparty/.

Important constraint:
- No curated allow-list of library names. This script *discovers* candidates by scanning the
  3rdparty directory tree and extracting version-like identifiers from common metadata files.

Limitations:
- Vendored C/C++ sources often do not include a single authoritative version string; this uses
  heuristics and therefore may miss some libraries or pick a less-than-perfect version string.
"""

import argparse
import json
import re
from pathlib import Path
from typing import Optional, Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def first_match(text: str, patterns: list[str]) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, text, flags=re.MULTILINE)
        if m:
            return m.group(1)
    return None


VERSION_PATTERNS = [
    # C preprocessor macros: "#define FOO_VERSION "1.2.3""
    r'^\s*#define\s+\w*VERSION\w*\s+"([0-9]+(?:\.[0-9]+){1,3})"\s*$',
    # Generic comment header patterns: "version 1.2.3" or "v1.2.3 released"
    r'\bversion\s+v?([0-9]+(?:\.[0-9]+){1,3})\b',
    r'\bv([0-9]+(?:\.[0-9]+){1,3})\s+released\b',
    # CMake: set(VERSION 1.2.3) / project(... VERSION 1.2.3)
    r'^\s*set\s*\(\s*\w*VERSION\w*\s+"?([0-9]+(?:\.[0-9]+){1,3})"?\s*\)\s*$',
    r'^\s*project\s*\(.*\bVERSION\s+([0-9]+(?:\.[0-9]+){1,3})\b.*\)\s*$',
]


def int_version_to_semver(n: int) -> Optional[str]:
    # Heuristic for packed integer versions like protobuf:
    # major * 10^6 + minor * 10^3 + micro
    if n < 1_000_000 or n > 9_999_999:
        return None
    major = n // 1_000_000
    minor = (n // 1_000) % 1_000
    micro = n % 1_000
    return f"{major}.{minor}.{micro}"


def extract_versions_from_text(text: str) -> list[str]:
    found: list[str] = []
    for pat in VERSION_PATTERNS:
        for m in re.finditer(pat, text, flags=re.IGNORECASE | re.MULTILINE):
            v = m.group(1)
            if v and v not in found:
                found.append(v)
    # Packed integer version macro: "#define ..._VERSION 3019001"
    for m in re.finditer(r"^\s*#define\s+\w*VERSION\w*\s+(\d{7})\s*$", text, flags=re.MULTILINE):
        sv = int_version_to_semver(int(m.group(1)))
        if sv and sv not in found:
            found.append(sv)
    return found


def candidate_files(root: Path) -> Iterable[Path]:
    # Deterministic selection of "likely to contain version" files, to avoid scanning everything.
    patterns = [
        "CMakeLists.txt",
        "configure.ac",
        "configure.in",
        "VERSION",
        "version",
        "version.txt",
        "ChangeLog",
        "CHANGES",
        "NEWS",
        "README",
        "README.md",
        "README.txt",
    ]
    picked: list[Path] = []
    # 1) exact-ish filename hits at shallow depth
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.stat().st_size > 256 * 1024:
            continue
        name = p.name
        if name in patterns or "version" in name.lower() or "changelog" in name.lower():
            picked.append(p)
    # Prefer closer files, then lexicographic for determinism; cap to keep runtime bounded.
    picked.sort(key=lambda x: (len(x.relative_to(root).parts), str(x)))
    return picked[:200]


def infer_version_for_dir(d: Path) -> Optional[str]:
    versions: list[str] = []
    for p in candidate_files(d):
        try:
            text = read_text(p)
        except Exception:
            continue
        for v in extract_versions_from_text(text):
            versions.append(v)
    if not versions:
        return None
    # Heuristic: prefer semver-like with 3 dots, then 2 dots, then 1 dot; stable by first appearance.
    versions.sort(key=lambda v: (-v.count("."), -len(v)))
    return versions[0]


def component(name: str, version: Optional[str], purl: Optional[str] = None) -> dict:
    c = {"type": "library", "name": name}
    if version:
        c["version"] = version
    if purl:
        c["purl"] = purl
    return c


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True, help="Output CycloneDX JSON file path")
    args = ap.parse_args()

    thirdparty = REPO_ROOT / "3rdparty"
    comps: list[dict] = []
    for child in sorted([p for p in thirdparty.iterdir() if p.is_dir()]):
        name = child.name
        version = infer_version_for_dir(child)
        if not version:
            continue
        comps.append(component(name, version, f"pkg:generic/{name}"))

    # Drop components with no version only if we couldn't determine anything useful.
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "file", "name": "3rdparty"},
            "tools": {"components": [{"type": "application", "name": "generate_3rdparty_sbom.py"}]},
        },
        "components": comps,
    }

    out = Path(args.output)
    out.write_text(json.dumps(bom, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {out} with {len(comps)} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


