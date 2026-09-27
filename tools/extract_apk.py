#!/usr/bin/env python3
"""Prepare a user-owned GameNative APK for inspection on Switch.

This script does not modify the APK. It only extracts its contents into a
separate directory and prints the Android ARM64 native libraries it finds.
"""
from __future__ import annotations
import argparse
import pathlib
import zipfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("gamenative_apk"))
    args = parser.parse_args()

    if not args.apk.is_file():
        raise SystemExit(f"APK not found: {args.apk}")

    args.out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.apk) as zf:
        names = zf.namelist()
        zf.extractall(args.out)
        libs = [n for n in names if n.startswith("lib/arm64-v8a/") and n.endswith(".so")]

    print(f"Extracted {len(names)} archive entries to {args.out}")
    print("ARM64 Android native libraries:")
    for lib in libs:
        print(f"  {lib}")
    if not libs:
        print("  (none found)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
