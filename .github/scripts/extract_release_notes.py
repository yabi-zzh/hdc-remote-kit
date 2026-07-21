#!/usr/bin/env python3
"""从 CHANGELOG.md 提取指定版本的 Release notes。"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def extract_section(changelog: str, version: str) -> str:
    pattern = rf"^## \[{re.escape(version)}\]\s*\n(.*?)(?=^## \[|\Z)"
    match = re.search(pattern, changelog, flags=re.MULTILINE | re.DOTALL)
    if not match:
        raise SystemExit(f"CHANGELOG.md 中未找到版本 [{version}]")
    return match.group(1).strip()


def previous_version(changelog: str, version: str) -> str | None:
    versions = re.findall(r"^## \[([^\]]+)\]", changelog, flags=re.MULTILINE)
    try:
        index = versions.index(version)
    except ValueError:
        return None
    if index + 1 >= len(versions):
        return None
    return versions[index + 1]


def build_notes(changelog: str, version: str, repo: str) -> str:
    section = extract_section(changelog, version)
    prev = previous_version(changelog, version)
    lines = [section, ""]
    if prev:
        lines.append(
            f"**完整变更**：https://github.com/{repo}/compare/v{prev}...v{version}"
        )
    else:
        lines.append(
            f"**完整变更**：https://github.com/{repo}/releases/tag/v{version}"
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="语义化版本号，例如 0.1.0")
    parser.add_argument(
        "--changelog",
        type=Path,
        default=Path("CHANGELOG.md"),
        help="CHANGELOG 路径",
    )
    parser.add_argument(
        "--repo",
        default="yabi-zzh/hdc-remote-kit",
        help="GitHub owner/repo",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="输出文件；默认打印到 stdout",
    )
    args = parser.parse_args()

    changelog = args.changelog.read_text(encoding="utf-8")
    notes = build_notes(changelog, args.version.lstrip("v"), args.repo)
    if args.output:
        args.output.write_text(notes, encoding="utf-8")
    else:
        sys.stdout.write(notes)


if __name__ == "__main__":
    main()
