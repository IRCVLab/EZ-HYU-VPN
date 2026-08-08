#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from release_packaging import PackagingError, ReleaseBuilder, ReleaseToolchain, assemble_payload_from_repo  # noqa: E402


def git_commit(repo_root: Path) -> str:
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PackagingError("unable to determine git commit") from exc
    if completed.returncode != 0:
        raise PackagingError("unable to determine git commit")
    return completed.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build an offline HYU VPN internal-lab release payload/DMG.")
    parser.add_argument("--source-payload", type=Path, help="Strict staged payload root matching Task7 layout")
    parser.add_argument("--assemble-from-repo", action="store_true", help="Assemble canonical payload from repo plus explicit runtime inputs")
    parser.add_argument("--repo-root", type=Path, default=REPO)
    parser.add_argument("--openconnect", type=Path)
    parser.add_argument("--oathtool", type=Path)
    parser.add_argument("--vpnc-script", type=Path)
    parser.add_argument("--helper-executable", type=Path)
    parser.add_argument("--wrapperd-executable", type=Path)
    parser.add_argument("--menu-app", type=Path)
    parser.add_argument("--installer-app", type=Path)
    parser.add_argument("--source-compliance-bundle", type=Path)
    parser.add_argument(
        "--rebind-source-compliance-bundle",
        action="store_true",
        help="Rebind exact current bottle hashes after verifying source-bundle Homebrew keg provenance",
    )
    parser.add_argument("--build-root", required=True, type=Path, help="Fresh explicit build root")
    parser.add_argument("--output-root", required=True, type=Path, help="Fresh explicit output root")
    parser.add_argument("--version", required=True)
    parser.add_argument("--arch", required=True, choices=["arm64"])
    parser.add_argument("--fake-tools", action="store_true", help="Use fake codesign/hdiutil boundaries for unit tests only")
    args = parser.parse_args(argv)
    try:
        source_payload = args.source_payload
        if args.assemble_from_repo:
            missing = [name for name in ["openconnect", "oathtool", "vpnc_script", "helper_executable", "wrapperd_executable", "menu_app", "installer_app"] if getattr(args, name) is None]
            if missing:
                raise PackagingError(f"missing assemble inputs: {', '.join(missing)}")
            source_payload = assemble_payload_from_repo(
                repo_root=args.repo_root,
                payload_root=args.build_root / "canonical-source-payload",
                openconnect=args.openconnect,
                oathtool=args.oathtool,
                vpnc_script=args.vpnc_script,
                helper_executable=args.helper_executable,
                wrapperd_executable=args.wrapperd_executable,
                menu_app=args.menu_app,
                installer_app=args.installer_app,
                source_compliance_bundle=args.source_compliance_bundle,
                rebind_source_compliance=args.rebind_source_compliance_bundle,
            )
        if source_payload is None:
            raise PackagingError("--source-payload or --assemble-from-repo is required")
        commit = git_commit(args.repo_root)
        result = ReleaseBuilder(ReleaseToolchain(fake=args.fake_tools)).build(
            source_payload=source_payload,
            build_root=args.build_root,
            output_root=args.output_root,
            version=args.version,
            arch=args.arch,
            git_commit=commit,
        )
    except PackagingError as exc:
        print(f"package-release: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "stage": str(result.stage_dir),
        "dmg": str(result.dmg_path),
        "checksum": str(result.checksum_path),
        "architecture": result.metadata["architecture"],
        "notarized": result.metadata["notarized"],
        "git_commit": result.metadata["git_commit"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
