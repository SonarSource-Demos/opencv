#!/usr/bin/env python3
"""
Generate a small CycloneDX JSON SBOM for OpenCV bundled (vendored) deps under 3rdparty/.

Rationale:
- Tools like Syft often can't infer "packages" from C/C++ source-only vendor trees.
- ScanCode can emit SPDX inventories, but those are typically file-centric and too noisy for dependency SBOM import.

So we extract versions from upstream headers / CMake metadata in the vendored sources and emit a
package-oriented CycloneDX 1.6 SBOM with a small set of components.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parents[2]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def first_match(text: str, patterns: list[str]) -> Optional[str]:
    for pat in patterns:
        m = re.search(pat, text, flags=re.MULTILINE)
        if m:
            return m.group(1)
    return None


def zlib_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/zlib/zlib.h"
    if not p.exists():
        return None
    t = read_text(p)
    return first_match(t, [r'^\s*#define\s+ZLIB_VERSION\s+"([^"]+)"\s*$'])


def libpng_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/libpng/png.h"
    if not p.exists():
        return None
    t = read_text(p)
    # Prefer macro; fallback to the comment header.
    return first_match(
        t,
        [
            r'^\s*#define\s+PNG_LIBPNG_VER_STRING\s+"([^"]+)"\s*$',
            r"^\s*\*\s*libpng version\s+([0-9]+\.[0-9]+\.[0-9]+)\s*$",
        ],
    )


def libjpeg_turbo_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/libjpeg-turbo/CMakeLists.txt"
    if not p.exists():
        return None
    t = read_text(p)
    maj = first_match(t, [r'^\s*set\s*\(\s*VERSION_MAJOR\s+(\d+)\s*\)\s*$'])
    min_ = first_match(t, [r'^\s*set\s*\(\s*VERSION_MINOR\s+(\d+)\s*\)\s*$'])
    rev = first_match(t, [r'^\s*set\s*\(\s*VERSION_REVISION\s+(\d+)\s*\)\s*$'])
    if maj and min_ and rev:
        return f"{maj}.{min_}.{rev}"
    return None


def openexr_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/openexr/CMakeLists.txt"
    if not p.exists():
        return None
    t = read_text(p)
    maj = first_match(t, [r'^\s*set\s*\(\s*OPENEXR_VERSION_MAJOR\s+"?(\d+)"?\s*\)\s*$'])
    min_ = first_match(t, [r'^\s*set\s*\(\s*OPENEXR_VERSION_MINOR\s+"?(\d+)"?\s*\)\s*$'])
    pat = first_match(t, [r'^\s*set\s*\(\s*OPENEXR_VERSION_PATCH\s+"?(\d+)"?\s*\)\s*$'])
    if maj and min_ and pat:
        return f"{maj}.{min_}.{pat}"
    return None


def protobuf_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/protobuf/src/google/protobuf/stubs/common.h"
    if not p.exists():
        return None
    t = read_text(p)
    v = first_match(t, [r'^\s*#define\s+GOOGLE_PROTOBUF_VERSION\s+(\d+)\s*$'])
    if not v:
        return None
    n = int(v)
    major = n // 1_000_000
    minor = (n // 1_000) % 1_000
    micro = n % 1_000
    return f"{major}.{minor}.{micro}"


def libtiff_version() -> Optional[str]:
    # The vendored libtiff uses configure_file() templates; easiest reliable hint is ChangeLog header.
    p = REPO_ROOT / "3rdparty/libtiff/ChangeLog"
    if not p.exists():
        return None
    t = read_text(p)
    # Example line: "libtiff v4.6.0 released"
    return first_match(t, [r"^\s*libtiff v([0-9]+\.[0-9]+\.[0-9]+)\s+released\s*$"])


def jasper_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/libjasper/jasper/jas_config.h"
    if not p.exists():
        return None
    t = read_text(p)
    # JasPer in OpenCV historically uses 1.900.1 style version.
    return first_match(t, [r'^\s*#define\s+JAS_VERSION\s+"([^"]+)"\s*$'])


def ippicv_version() -> Optional[str]:
    p = REPO_ROOT / "3rdparty/ippicv/ippicv.cmake"
    if not p.exists():
        return None
    t = read_text(p)
    # Extract first ippicv_<version>_* token in the package names.
    m = re.search(r'ippicv_([0-9]+\.[0-9]+\.[0-9]+)_', t)
    return m.group(1) if m else None


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

    comps = [
        component("zlib", zlib_version(), "pkg:generic/zlib"),
        component("libpng", libpng_version(), "pkg:generic/libpng"),
        component("libjpeg-turbo", libjpeg_turbo_version(), "pkg:generic/libjpeg-turbo"),
        component("libtiff", libtiff_version(), "pkg:generic/libtiff"),
        component("libwebp", None, "pkg:generic/libwebp"),
        component("jasper", jasper_version(), "pkg:generic/jasper"),
        component("openexr", openexr_version(), "pkg:generic/openexr"),
        component("protobuf", protobuf_version(), "pkg:generic/protobuf"),
        component("ippicv", ippicv_version(), "pkg:generic/ippicv"),
    ]

    # Drop components with no version only if we couldn't determine anything useful.
    # (We keep libwebp with no version as a marker, since OpenCV bundles it.)
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


