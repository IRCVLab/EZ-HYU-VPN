from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence


class PackagingError(RuntimeError):
    pass


REPO_ROOT = Path(__file__).resolve().parents[1]
SYSTEM_ROOTS = [Path("/"), Path("/Applications"), Path("/Library"), Path("/System"), Path("/usr")]
SYSTEM_DYLIB_PREFIXES = ("/usr/lib/", "/System/Library/")
MANIFEST_NAME = "manifest.json"
PYTHON_PREREQUISITE = "/usr/bin/python3"
HELPER_CONFIG_KEYS = {
    "openConnectExecutable",
    "vpncScript",
    "hipWrapper",
    "stateDirectory",
    "ledgerDirectory",
    "openConnectExecutableSHA256",
    "vpncScriptSHA256",
    "hipWrapperSHA256",
}
REQUIRED_SOURCE_MODULES = {
    "src/hyu_vpn/__init__.py",
    "src/hyu_vpn/connector.py",
    "src/hyu_vpn/control.py",
    "src/hyu_vpn/hip_cli.py",
    "src/hyu_vpn/hip_contract.py",
    "src/hyu_vpn/hip_xml.py",
    "src/hyu_vpn/macos_posture.py",
    "src/hyu_vpn/native_client.py",
    "src/hyu_vpn/network.py",
    "src/hyu_vpn/otp.py",
    "src/hyu_vpn/status.py",
    "src/hyu_vpn/supervisor.py",
}
SOURCE_COMPLIANCE_BUNDLE = "SOURCE-COMPLIANCE-BUNDLE.tar.gz"
FINAL_RUNTIME_BINDING = "FINAL-RUNTIME-BINDING.json"
SOURCE_COMPLIANCE_BUNDLE_SEMANTICS = "canonical-pre-rewrite-pre-sign"
SOURCE_COMPLIANCE_BUNDLE_SCOPE = "third-party-runtime-corresponding-source-only"
GIT_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

INSTALLER_APP_REL = "Install HYU VPN.app"
INSTALLER_EXEC_REL = "Install HYU VPN.app/Contents/MacOS/HYUVPNInstallerApp"

REQUIRED_PAYLOAD_FILES = {
    "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
    "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader",
    "HYU VPN.app/Contents/Info.plist",
    "HYU VPN.app/Contents/Resources/AppIcon.icns",
    INSTALLER_EXEC_REL,
    "Install HYU VPN.app/Contents/Info.plist",
    "Install HYU VPN.app/Contents/Resources/AppIcon.icns",
    "README-lab.md",
    "installer/root-admin.sh",
    "installer/manifest.py",
    "launchd/com.hyu.vpn.service.plist.in",
    "runtime/openconnect/bin/openconnect",
    "runtime/oathtool",
    "runtime/gp-hip-report",
    "runtime/vpnc/vpnc-script",
    "runtime/vpnc/hyu-vpnc-wrapper",
    "runtime/vpnc/hyu-vpnc-wrapperd",
    "com.hyu.vpn.helper",
    "hyu-vpn-service",
    "hyu-vpn-control",
    "hyu-vpn-connect",
    "hyu-vpn-native-client",
    "THIRD_PARTY_NOTICES.txt",
    "SOURCE-OFFER.txt",
} | REQUIRED_SOURCE_MODULES
APP_BUNDLE_REL = "HYU VPN.app"
APP_BUNDLE_RELS = [APP_BUNDLE_REL, INSTALLER_APP_REL]
OPTIONAL_APP_SIGNATURE_FILES = {
    "HYU VPN.app/Contents/_CodeSignature/CodeResources",
    "Install HYU VPN.app/Contents/_CodeSignature/CodeResources",
}
EXECUTABLE_RELATIVE_FILES = {
    "runtime/openconnect/bin/openconnect",
    "runtime/oathtool",
    "runtime/vpnc/hyu-vpnc-wrapperd",
    "com.hyu.vpn.helper",
    "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
    "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader",
}


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _allowed_system_symlink(path: Path) -> bool:
    allowed = {Path("/var"): Path("/private/var"), Path("/tmp"): Path("/private/tmp")}
    if path not in allowed:
        return False
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
        return False
    return path.resolve(strict=False) == allowed[path]


def _reject_symlink_ancestors(path: Path) -> None:
    original = Path(path)
    if not original.is_absolute():
        original = Path.cwd() / original
    probe = Path("/")
    for part in original.parts[1:-1]:
        probe = probe / part
        try:
            mode = os.lstat(probe).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) and not _allowed_system_symlink(probe):
            raise PackagingError(f"unsafe symlink ancestor: {probe}")


def _resolve_for_guard(path: Path) -> Path:
    path = Path(path)
    _reject_symlink_ancestors(path)
    if path.is_symlink():
        raise PackagingError(f"unsafe symlink path: {path}")
    return path.resolve(strict=False)


def guard_root(root: Path) -> Path:
    root = _resolve_for_guard(root)
    forbidden_exact = {Path("/"), Path("/Applications"), Path("/Library"), Path("/System"), Path("/usr"), REPO_ROOT.resolve()}
    if root in forbidden_exact or _is_under(root, REPO_ROOT.resolve()):
        raise PackagingError(f"unsafe root: {root}")
    for system_root in [Path("/Applications"), Path("/Library"), Path("/System"), Path("/usr")]:
        if _is_under(root, system_root):
            raise PackagingError(f"unsafe root under system location: {root}")
    if _is_under(root, Path("/private")) and not (_is_under(root, Path("/private/tmp")) or _is_under(root, Path("/private/var/folders"))):
        raise PackagingError(f"unsafe non-temp private root: {root}")
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise PackagingError(f"unsafe root not a directory: {root}")
    return root


def guard_destination(destination: Path, *, allowed_root: Path) -> Path:
    root = guard_root(allowed_root)
    dest = _resolve_for_guard(destination)
    if dest == root:
        raise PackagingError(f"unsafe destination is the allowed root itself: {dest}")
    try:
        dest.relative_to(root)
    except ValueError as exc:
        raise PackagingError(f"unsafe destination outside explicit root: {dest}") from exc
    if dest.exists():
        mode = dest.stat().st_mode
        if dest.is_symlink() or not dest.is_dir() or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
            raise PackagingError(f"unsafe destination special/non-directory: {dest}")
        if any(dest.iterdir()):
            raise PackagingError(f"unsafe destination existing non-empty directory: {dest}")
    return dest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_files(root: Path, *, exclude_manifest: bool = False) -> List[Path]:
    files: List[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise PackagingError(f"payload symlink rejected: {path.relative_to(root).as_posix()}")
        if path.is_file():
            if exclude_manifest and path.relative_to(root).as_posix() == MANIFEST_NAME:
                continue
            files.append(path)
    return files


def build_manifest(payload: Path) -> Dict[str, Any]:
    entries: Dict[str, Dict[str, Any]] = {}
    for path in _relative_files(payload, exclude_manifest=True):
        rel = path.relative_to(payload).as_posix()
        entries[rel] = {"sha256": _sha256(path), "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}", "size": path.stat().st_size}
    return {"schema": 1, "name": "HYU VPN internal lab payload", "manifest": MANIFEST_NAME, "files": entries}


def _valid_token(value: str) -> bool:
    return bool(value) and len(value) <= 64 and all(ch.isalnum() or ch in "._-" for ch in value)


def validate_third_party_notices(path: Path, components: Sequence[str]) -> None:
    text = path.read_text(encoding="utf-8")
    lowered = text.lower()
    for forbidden in ("template", "todo"):
        if forbidden in lowered:
            raise PackagingError(f"third-party notices still contain {forbidden}")
    for component in components:
        if component.lower() not in lowered:
            raise PackagingError(f"third-party notices missing component: {component}")
    for required in ("license:", "source:", "lgpl source offer", "gpl source offer"):
        if required not in lowered:
            raise PackagingError(f"third-party notices missing {required}")


def _json_no_duplicate_keys(data: bytes, label: str) -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PackagingError(f"duplicate key in {label}: {key}")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=hook)
    except UnicodeDecodeError as exc:
        raise PackagingError(f"{label} must be utf-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise PackagingError(f"{label} must be valid JSON") from exc


def validate_source_compliance_bundle(path: Path) -> None:
    path = _require_regular_file(Path(path))
    if path.name != SOURCE_COMPLIANCE_BUNDLE:
        raise PackagingError(f"source compliance bundle must be named {SOURCE_COMPLIANCE_BUNDLE}")
    if path.stat().st_size <= 0 or path.stat().st_size > 512 * 1024 * 1024:
        raise PackagingError("source compliance bundle size is out of bounds")
    try:
        with tarfile.open(path, "r:gz") as tf:
            members = tf.getmembers()
            seen: set[str] = set()
            regular: Dict[str, bytes] = {}
            dirs: set[str] = set()
            for member in members:
                raw_name = member.name
                member_path = Path(raw_name)
                normalized = raw_name.rstrip("/")
                if raw_name.startswith("/") or ".." in member_path.parts or normalized == "":
                    raise PackagingError(f"unsafe source bundle member: {raw_name}")
                if normalized in seen:
                    raise PackagingError(f"duplicate source bundle member: {normalized}")
                seen.add(normalized)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise PackagingError(f"unsafe source bundle member type: {raw_name}")
                if member.isdir():
                    dirs.add(normalized)
                    continue
                if not member.isfile():
                    raise PackagingError(f"unsupported source bundle member type: {raw_name}")
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise PackagingError(f"cannot read source bundle member: {raw_name}")
                regular[normalized] = extracted.read()
    except tarfile.TarError as exc:
        raise PackagingError(f"invalid source compliance bundle: {exc}") from exc

    required = {"inventory.json", "checksums.txt", "build-info.txt"}
    if not required <= set(regular):
        raise PackagingError(f"source compliance bundle missing required files: {sorted(required - set(regular))}")
    for top in required:
        if "/" in top or top not in regular:
            raise PackagingError(f"required source bundle file must be top-level regular: {top}")
    if len(regular["build-info.txt"]) == 0 or len(regular["build-info.txt"]) > 1024 * 1024:
        raise PackagingError("build-info.txt must be bounded and nonempty")

    checksum_text = regular["checksums.txt"].decode("utf-8")
    checksum_entries: Dict[str, str] = {}
    checksum_re = re.compile(r"^[0-9a-f]{64}  [^/\\][^\r\n]*$")
    for line in checksum_text.splitlines():
        if not line:
            continue
        if not checksum_re.match(line):
            raise PackagingError(f"invalid checksums.txt line: {line}")
        digest, rel = line.split("  ", 1)
        rel_path = Path(rel)
        if rel.startswith("/") or ".." in rel_path.parts or rel == "checksums.txt":
            raise PackagingError(f"unsafe checksum path: {rel}")
        if rel in checksum_entries:
            raise PackagingError(f"duplicate checksum path: {rel}")
        checksum_entries[rel] = digest
    expected_regular = set(regular) - {"checksums.txt"}
    if set(checksum_entries) != expected_regular:
        raise PackagingError(f"checksums.txt does not exactly cover regular members: extras={sorted(set(checksum_entries)-expected_regular)} missing={sorted(expected_regular-set(checksum_entries))}")
    for rel, digest in checksum_entries.items():
        actual = hashlib.sha256(regular[rel]).hexdigest()
        if actual != digest:
            raise PackagingError(f"source bundle checksum mismatch: {rel}")

    inventory = _json_no_duplicate_keys(regular["inventory.json"], "inventory.json")
    if not isinstance(inventory, dict) or inventory.get("schema") != 1:
        raise PackagingError("inventory.json schema mismatch")
    for key in ("sources", "runtime", "resource_sources"):
        if not isinstance(inventory.get(key), list) or not inventory[key]:
            raise PackagingError(f"inventory.json must contain nonempty {key}")
    allowed_keys = {"schema", "sources", "runtime", "resource_sources", "receipts", "patches"}
    if set(inventory) - allowed_keys:
        raise PackagingError(f"inventory.json contains unsupported keys: {sorted(set(inventory)-allowed_keys)}")

    runtime_closure_refs = [entry for entry in inventory.get("runtime", []) if isinstance(entry, dict) and "runtime_closure" in entry]
    if len(runtime_closure_refs) != 1:
        raise PackagingError("inventory runtime must contain exactly one runtime_closure entry")
    runtime_closure_ref = runtime_closure_refs[0]
    closure_file = runtime_closure_ref.get("runtime_closure")
    closure_digest = runtime_closure_ref.get("sha256")
    if not isinstance(closure_file, str) or closure_file not in regular or not isinstance(closure_digest, str):
        raise PackagingError("inventory runtime_closure entry missing file/sha256")
    if hashlib.sha256(regular[closure_file]).hexdigest() != closure_digest:
        raise PackagingError("inventory runtime_closure checksum mismatch")
    runtime_closure = _json_no_duplicate_keys(regular[closure_file], "runtime-closure.json")
    if not isinstance(runtime_closure, dict) or runtime_closure.get("schema") != 1 or not isinstance(runtime_closure.get("files"), list) or not runtime_closure["files"]:
        raise PackagingError("runtime-closure.json schema mismatch")
    closure_paths: set[str] = set()
    closure_packages: set[str] = set()
    for item in runtime_closure["files"]:
        if not isinstance(item, dict):
            raise PackagingError("runtime-closure entry must be object")
        rel = item.get("path"); digest = item.get("sha256"); size = item.get("size"); package = item.get("package"); source = item.get("source")
        if not isinstance(rel, str) or rel.startswith("/") or ".." in Path(rel).parts:
            raise PackagingError("runtime-closure path mismatch")
        if rel in closure_paths:
            raise PackagingError(f"duplicate runtime-closure path: {rel}")
        if not isinstance(digest, str) or not re.match(r"^[0-9a-f]{64}$", digest) or not isinstance(size, int) or size < 0:
            raise PackagingError(f"runtime-closure hash/size mismatch: {rel}")
        if not isinstance(package, str) or not package or not isinstance(source, str) or source not in regular:
            raise PackagingError(f"runtime-closure source reference mismatch: {rel}")
        closure_paths.add(rel); closure_packages.add(package)

    referenced: set[str] = {closure_file}
    package_refs: set[tuple[str, str]] = set()

    def check_entry(section: str, entry: object) -> None:
        if not isinstance(entry, dict):
            raise PackagingError(f"inventory {section} entry must be object")
        if section == "runtime" and "runtime_closure" in entry:
            return
        package = str(entry.get("package") or entry.get("name") or "")
        file_ref = entry.get("file") or entry.get("source") or entry.get("receipt") or entry.get("patch")
        digest = entry.get("sha256")
        if not package or not isinstance(file_ref, str) or not isinstance(digest, str):
            raise PackagingError(f"inventory {section} entry missing package/file/sha256")
        rel_path = Path(file_ref)
        if file_ref.startswith("/") or ".." in rel_path.parts or file_ref not in regular:
            raise PackagingError(f"inventory references missing/unsafe file: {file_ref}")
        if not re.match(r"^[0-9a-f]{64}$", digest):
            raise PackagingError(f"inventory checksum format mismatch: {file_ref}")
        if hashlib.sha256(regular[file_ref]).hexdigest() != digest:
            raise PackagingError(f"inventory checksum mismatch: {file_ref}")
        key = (section, package, file_ref)
        if key in package_refs or file_ref in referenced:
            raise PackagingError(f"duplicate inventory reference: {file_ref}")
        package_refs.add(key)
        referenced.add(file_ref)

    for section in ("runtime", "sources", "resource_sources", "receipts", "patches"):
        for entry in inventory.get(section, []):
            check_entry(section, entry)

    source_packages = {entry.get("package") for section in ("sources", "receipts") for entry in inventory.get(section, []) if isinstance(entry, dict)}
    resource_files = {entry.get("file") for entry in inventory.get("resource_sources", []) if isinstance(entry, dict)}
    for package in closure_packages - {"vpnc-script"}:
        if package not in source_packages:
            raise PackagingError(f"inventory lacks source/receipt coverage for runtime package: {package}")
    for item in runtime_closure["files"]:
        if item.get("package") == "vpnc-script" and item.get("source") not in resource_files:
            raise PackagingError("inventory lacks resource source coverage for vpnc-script")

    # Every payload regular file other than inventory/checksums/build-info must
    # be accounted for by an inventory entry, preventing arbitrary checked but
    # unrelated files from claiming compliance.
    inventory_control = {"inventory.json", "checksums.txt", "build-info.txt"}
    unreferenced = set(regular) - inventory_control - referenced
    if unreferenced:
        raise PackagingError(f"source bundle has unreferenced regular files: {sorted(unreferenced)}")


def _source_payload_runtime_files(payload: Path) -> Dict[str, Dict[str, Any]]:
    runtime_rels: set[str] = {"runtime/openconnect/bin/openconnect", "runtime/oathtool", "runtime/vpnc/vpnc-script"}
    lib_dir = payload / "runtime/openconnect/lib"
    if lib_dir.exists():
        for path in lib_dir.glob("*.dylib"):
            if path.is_file() and not path.is_symlink():
                runtime_rels.add(path.relative_to(payload).as_posix())
    result: Dict[str, Dict[str, Any]] = {}
    for rel in runtime_rels:
        path = payload / rel
        if not path.exists() or path.is_symlink() or not path.is_file():
            raise PackagingError(f"runtime closure mismatch missing payload file: {rel}")
        result[rel] = {"sha256": _sha256(path), "size": path.stat().st_size}
    return result


def _source_bundle_runtime_files(bundle: Path) -> Dict[str, Dict[str, Any]]:
    validate_source_compliance_bundle(bundle)
    with tarfile.open(bundle, "r:gz") as tf:
        regular = {m.name.rstrip("/"): tf.extractfile(m).read() for m in tf.getmembers() if m.isfile()}
    inventory = _json_no_duplicate_keys(regular["inventory.json"], "inventory.json")
    runtime_entry = next(entry for entry in inventory["runtime"] if isinstance(entry, dict) and "runtime_closure" in entry)
    closure = _json_no_duplicate_keys(regular[runtime_entry["runtime_closure"]], "runtime-closure.json")
    return {item["path"]: {"sha256": item["sha256"], "size": item["size"]} for item in closure["files"]}


def validate_source_bundle_matches_payload(bundle: Path, payload: Path) -> None:
    closure_files = _source_bundle_runtime_files(bundle)
    actual = _source_payload_runtime_files(payload)
    if closure_files != actual:
        raise PackagingError(f"runtime closure mismatch: extras={sorted(set(closure_files)-set(actual))} missing={sorted(set(actual)-set(closure_files))}")


def _final_runtime_binding_data(bundle: Path, payload: Path) -> Dict[str, Any]:
    canonical = _source_bundle_runtime_files(bundle)
    final = _source_payload_runtime_files(payload)
    if set(canonical) != set(final):
        raise PackagingError(
            "final runtime binding path mismatch: "
            f"extras={sorted(set(canonical)-set(final))} missing={sorted(set(final)-set(canonical))}"
        )
    files = []
    for rel in sorted(canonical):
        files.append({
            "path": rel,
            "canonical_sha256": canonical[rel]["sha256"],
            "canonical_size": canonical[rel]["size"],
            "final_sha256": final[rel]["sha256"],
            "final_size": final[rel]["size"],
        })
    return {
        "schema": 1,
        "source_compliance_bundle": {
            "path": SOURCE_COMPLIANCE_BUNDLE,
            "sha256": _sha256(bundle),
            "semantics": SOURCE_COMPLIANCE_BUNDLE_SEMANTICS,
            "scope": SOURCE_COMPLIANCE_BUNDLE_SCOPE,
        },
        "files": files,
    }


def write_final_runtime_binding(bundle: Path, payload: Path) -> Path:
    binding = Path(payload) / FINAL_RUNTIME_BINDING
    if binding.exists() or binding.is_symlink():
        raise PackagingError(f"refusing to overwrite final runtime binding: {binding}")
    data = _final_runtime_binding_data(bundle, payload)
    binding.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    binding.chmod(0o644)
    validate_final_runtime_binding(binding, bundle, payload)
    return binding


def validate_final_runtime_binding(binding: Path, bundle: Path, payload: Path) -> None:
    binding = _require_regular_file(Path(binding))
    if binding.name != FINAL_RUNTIME_BINDING or binding.stat().st_size > 2 * 1024 * 1024:
        raise PackagingError("final runtime binding file mismatch")
    actual = _json_no_duplicate_keys(binding.read_bytes(), FINAL_RUNTIME_BINDING)
    expected = _final_runtime_binding_data(bundle, payload)
    if actual != expected:
        raise PackagingError("final runtime binding mismatch")


def _validate_helper_config(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != HELPER_CONFIG_KEYS:
        raise PackagingError(f"helper config template must contain exact keys: {sorted(HELPER_CONFIG_KEYS)}")
    expected = {
        "openConnectExecutable": "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect",
        "vpncScript": "/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapper",
        "hipWrapper": "/Library/Application Support/HYU VPN/runtime/gp-hip-report",
        "stateDirectory": "/private/var/db/hyu-vpn",
        "ledgerDirectory": "/private/var/db/hyu-vpn/ledger",
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise PackagingError(f"helper config {key} mismatch")
    for key in ("openConnectExecutableSHA256", "vpncScriptSHA256", "hipWrapperSHA256"):
        if not re.match(r"^[0-9a-f]{64}$", data[key]):
            raise PackagingError(f"helper config {key} must be lowercase sha256")
    serialized = json.dumps(data, sort_keys=True)
    if "/opt/homebrew" in serialized or "/usr/local/Homebrew" in serialized:
        raise PackagingError("helper config contains Homebrew execution path")


def _validate_payload_contract(source: Path) -> None:
    source_files = {path.relative_to(source).as_posix() for path in _relative_files(source, exclude_manifest=True)}
    runtime_libs = {rel for rel in source_files if rel.startswith("runtime/openconnect/lib/") and rel.endswith(".dylib")}
    optional = {SOURCE_COMPLIANCE_BUNDLE} if SOURCE_COMPLIANCE_BUNDLE in source_files else set()
    allowed = REQUIRED_PAYLOAD_FILES | OPTIONAL_APP_SIGNATURE_FILES | runtime_libs | {"release-metadata.json"} | optional
    if not REQUIRED_PAYLOAD_FILES <= source_files or not source_files <= allowed:
        extras = sorted(source_files - allowed)
        missing = sorted(REQUIRED_PAYLOAD_FILES - source_files)
        detail = []
        if extras:
            detail.append(f"extras={extras}")
        if missing:
            detail.append(f"missing={missing}")
        raise PackagingError("source payload does not match Task7 contract: " + " ".join(detail))
    validate_third_party_notices(source / "THIRD_PARTY_NOTICES.txt", ["OpenConnect", "oath-toolkit", "vpnc-script"])
    if (source / SOURCE_COMPLIANCE_BUNDLE).exists():
        validate_source_compliance_bundle(source / SOURCE_COMPLIANCE_BUNDLE)
    readme = (source / "README-lab.md").read_text(encoding="utf-8")
    if PYTHON_PREREQUISITE not in readme:
        raise PackagingError("README must document fixed /usr/bin/python3 prerequisite")


def _copy_payload(source: Path, destination: Path) -> None:
    _validate_payload_contract(source)
    shutil.copytree(source, destination, symlinks=False, dirs_exist_ok=True)
    stale = destination / MANIFEST_NAME
    if stale.exists():
        stale.unlink()


@dataclasses.dataclass(frozen=True)
class DylibRef:
    install_name: str
    path: Path | None
    system: bool


class ToolRunner:
    def run(self, argv: Sequence[str]) -> str:
        completed = subprocess.run(list(argv), text=True, capture_output=True)
        if completed.returncode != 0:
            raise PackagingError(completed.stderr.strip() or f"command failed: {argv[0]}")
        return completed.stdout


class RuntimeClosurePlanner:
    def __init__(self, runner: ToolRunner | None = None) -> None:
        self.runner = runner or ToolRunner()

    def parse_otool(self, output: str) -> List[str]:
        deps: List[str] = []
        for line in output.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            deps.append(line.split(" ", 1)[0])
        return deps

    def dependencies(self, macho: Path) -> List[str]:
        return self.parse_otool(self.runner.run(["/usr/bin/otool", "-L", str(macho)]))

    def discover(self, roots: Sequence[Path]) -> List[Path]:
        queue = [Path(root).resolve(strict=True) for root in roots]
        seen: set[str] = set()
        ordered: List[Path] = []
        while queue:
            item = queue.pop(0)
            key = str(item)
            if key in seen:
                continue
            if not item.exists():
                raise PackagingError(f"missing closure dependency: {item}")
            seen.add(key)
            ordered.append(item)
            for dep in self.dependencies(item):
                if dep.startswith(SYSTEM_DYLIB_PREFIXES) or dep.startswith("@"):
                    continue
                dep_path = Path(dep)
                if str(dep_path) not in seen:
                    queue.append(dep_path)
        return ordered


def copied_runtime_rel(src: Path, roots: Sequence[Path]) -> str:
    name = src.name
    root_names = {Path(root).resolve(strict=False).name for root in roots}
    if name == "openconnect":
        return "runtime/openconnect/bin/openconnect"
    if name == "oathtool":
        return "runtime/oathtool"
    return f"runtime/openconnect/lib/{name}"


def copy_runtime_closure(files: Sequence[Path], roots: Sequence[Path], payload: Path) -> Dict[str, str]:
    copied: Dict[str, str] = {}
    basenames: Dict[str, Path] = {}
    rel_to_source: Dict[str, Path] = {}
    for src in files:
        src_path = Path(src)
        if not src_path.exists():
            raise PackagingError(f"missing runtime closure file: {src_path}")
        rel = copied_runtime_rel(src_path, roots)
        real_src = src_path.resolve(strict=True)
        if rel.startswith("runtime/openconnect/lib/"):
            previous = basenames.get(src_path.name)
            if previous is not None and previous.resolve(strict=True) != real_src:
                raise PackagingError(f"duplicate runtime library basename: {src_path.name}")
            basenames[src_path.name] = src_path
        previous_rel_source = rel_to_source.get(rel)
        if previous_rel_source is not None:
            if previous_rel_source.resolve(strict=True) != real_src:
                raise PackagingError(f"runtime closure alias collision: {rel}")
            copied[str(src_path)] = rel
            continue
        rel_to_source[rel] = src_path
        dst = payload / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst, follow_symlinks=True)
        copied[str(src_path)] = rel
    return copied


def _prewalk_regular_tree(root: Path, label: str) -> None:
    root = Path(root)
    if not root.exists() or root.is_symlink() or not root.is_dir():
        raise PackagingError(f"{label} must be a regular non-symlink directory: {root}")
    for item in root.rglob("*"):
        st = os.lstat(item)
        if stat.S_ISLNK(st.st_mode):
            raise PackagingError(f"symlink in {label}: {item}")
        if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise PackagingError(f"special file in {label}: {item}")


def _require_regular_file(path: Path) -> Path:
    path = Path(path)
    if not path.exists() or path.is_symlink() or not path.is_file():
        raise PackagingError(f"source input must be a regular non-symlink file: {path}")
    return path


def _validate_python_tree(root: Path) -> None:
    actual = {path.relative_to(root.parents[1]).as_posix() for path in root.rglob("*.py") if path.is_file()}
    if actual != REQUIRED_SOURCE_MODULES:
        raise PackagingError(f"unexpected Python module set: extras={sorted(actual - REQUIRED_SOURCE_MODULES)} missing={sorted(REQUIRED_SOURCE_MODULES - actual)}")
    if any(part == "__pycache__" for path in root.rglob("*") for part in path.parts):
        raise PackagingError("__pycache__ is not allowed in release payload source tree")


def assemble_payload_from_repo(
    *,
    repo_root: Path,
    payload_root: Path,
    openconnect: Path,
    oathtool: Path,
    helper_executable: Path,
    wrapperd_executable: Path,
    menu_app: Path,
    installer_app: Path,
    vpnc_script: Path,
    source_compliance_bundle: Path | None = None,
    closure_runner: ToolRunner | None = None,
) -> Path:
    repo_root = Path(repo_root).resolve(strict=True)
    if not _is_under(repo_root, REPO_ROOT.resolve()):
        raise PackagingError(f"untrusted repo root: {repo_root}")
    _validate_python_tree(repo_root / "src/hyu_vpn")
    payload_root = guard_destination(payload_root, allowed_root=payload_root.parent)
    payload_root.mkdir(parents=True)
    for required_input in [openconnect, oathtool, helper_executable, wrapperd_executable, vpnc_script]:
        _require_regular_file(required_input)
    _prewalk_regular_tree(Path(menu_app), "menu_app")
    _prewalk_regular_tree(Path(installer_app), "installer_app")
    _prewalk_regular_tree(repo_root / "src/hyu_vpn", "src/hyu_vpn")
    def copy_file_rel(src: Path, rel: str, mode: int) -> None:
        src = _require_regular_file(src)
        dst = payload_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        dst.chmod(mode)
    for rel in ["root-admin.sh", "manifest.py"]:
        copy_file_rel(repo_root / "installer" / rel, f"installer/{rel}", 0o755 if rel.endswith(".sh") else 0o644)
    for rel in ["com.hyu.vpn.service.plist.in"]:
        copy_file_rel(repo_root / "launchd" / rel, f"launchd/{rel}", 0o644)
    for rel in ["hyu-vpn-control", "hyu-vpn-service", "hyu-vpn-connect", "hyu-vpn-native-client"]:
        copy_file_rel(repo_root / "bin" / rel, rel, 0o755)
    copy_file_rel(repo_root / "bin/gp-hip-report", "runtime/gp-hip-report", 0o755)
    copy_file_rel(repo_root / "privileged/hyu-vpnc-wrapper", "runtime/vpnc/hyu-vpnc-wrapper", 0o755)
    copy_file_rel(wrapperd_executable, "runtime/vpnc/hyu-vpnc-wrapperd", 0o755)
    copy_file_rel(vpnc_script, "runtime/vpnc/vpnc-script", 0o755)
    copy_file_rel(helper_executable, "com.hyu.vpn.helper", 0o755)
    shutil.copytree(menu_app, payload_root / APP_BUNDLE_REL, symlinks=False)
    shutil.copytree(installer_app, payload_root / INSTALLER_APP_REL, symlinks=False)
    shutil.copytree(repo_root / "src/hyu_vpn", payload_root / "src/hyu_vpn", symlinks=False)
    for item in (payload_root / "src/hyu_vpn").rglob("*"):
        if item.is_file():
            item.chmod(0o644)
    closure = RuntimeClosurePlanner(closure_runner).discover([openconnect, oathtool])
    copy_runtime_closure(closure, [openconnect, oathtool], payload_root)
    copy_file_rel(repo_root / "packaging/README-lab.md", "README-lab.md", 0o644)
    copy_file_rel(repo_root / "packaging/THIRD_PARTY_NOTICES.txt", "THIRD_PARTY_NOTICES.txt", 0o644)
    copy_file_rel(repo_root / "packaging/SOURCE-OFFER.txt", "SOURCE-OFFER.txt", 0o644)
    if source_compliance_bundle is not None:
        validate_source_compliance_bundle(source_compliance_bundle)
        copy_file_rel(source_compliance_bundle, SOURCE_COMPLIANCE_BUNDLE, 0o644)
    return payload_root


@dataclasses.dataclass
class ReleaseResult:
    stage_dir: Path
    dmg_path: Path
    checksum_path: Path
    manifest_path: Path
    manifest: Dict[str, Any]
    metadata: Dict[str, Any]


def staged_runtime_rel(rel: str) -> str:
    if rel == "runtime/openconnect/bin/openconnect":
        return "runtime/bin/openconnect"
    if rel == "runtime/oathtool":
        return "runtime/bin/oathtool"
    if rel.startswith("runtime/openconnect/lib/"):
        return "runtime/lib/" + Path(rel).name
    return rel


def loader_replacement_for(rel: str, dep: str) -> str:
    staged = Path(staged_runtime_rel(rel))
    dep_name = Path(dep).name
    if staged.as_posix().startswith("runtime/lib/"):
        return f"@loader_path/{dep_name}"
    if staged.as_posix() in {"runtime/bin/openconnect", "runtime/bin/oathtool"}:
        return f"@loader_path/../lib/{dep_name}"
    raise PackagingError(f"non-runtime Mach-O must not link non-system dependency: {rel} -> {dep}")


def rewrite_target_source_rel(rel: str, dep: str) -> str:
    replacement = loader_replacement_for(rel, dep)
    dep_name = replacement.rsplit("/", 1)[-1]
    staged = Path(staged_runtime_rel(rel))
    if replacement.startswith("@loader_path/../lib/"):
        return "runtime/openconnect/lib/" + dep_name
    if replacement.startswith("@loader_path/") and staged.as_posix().startswith("runtime/lib/"):
        return "runtime/openconnect/lib/" + dep_name
    raise PackagingError(f"unsupported replacement target for {rel}: {replacement}")


def verify_rewrite_target_exists(payload: Path, rel: str, dep: str) -> None:
    target = payload / rewrite_target_source_rel(rel, dep)
    if not target.exists() or target.is_symlink() or not target.is_file():
        raise PackagingError(f"rewrite target missing from staged payload: {target.relative_to(payload).as_posix()}")


class ReleaseToolchain:
    def __init__(self, *, fake: bool = False, fail_mounted_validation: bool = False, tamper_mounted_file: str | None = None, attach_fails: bool = False, detach_fails: bool = False) -> None:
        self.fake = fake
        self.fail_mounted_validation = fail_mounted_validation
        self.tamper_mounted_file = tamper_mounted_file
        self.attach_fails = attach_fails
        self.detach_fails = detach_fails
        self.actions: List[str] = []

    def command_plan(self, action: str, target: Path, extra: Sequence[str] = ()) -> List[str]:
        target_s = str(target)
        plans = {
            "sign": ["/usr/bin/codesign", "--force", "--sign", "-", target_s],
            "verify_signature": ["/usr/bin/codesign", "--verify", "--strict", target_s],
            "verify_signature_deep": ["/usr/bin/codesign", "--verify", "--deep", "--strict", target_s],
            "verify_dmg": ["/usr/bin/hdiutil", "verify", target_s],
            "attach_readonly": ["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", *extra, target_s],
            "detach": ["/usr/bin/hdiutil", "detach", target_s],
            "create_dmg": ["/usr/bin/hdiutil", "create", "-format", "UDZO", "-srcfolder", *extra, target_s],
            "lipo_archs": ["/usr/bin/lipo", "-archs", target_s],
            "install_id": ["/usr/bin/install_name_tool", "-id", *extra, target_s],
            "install_change": ["/usr/bin/install_name_tool", "-change", *extra, target_s],
            "otool": ["/usr/bin/otool", "-L", target_s],
        }
        return plans[action]

    def _run(self, argv: Sequence[str]) -> str:
        if self.fake:
            return "arm64\n" if argv[:2] == ["/usr/bin/lipo", "-archs"] else ""
        completed = subprocess.run(list(argv), text=True, capture_output=True)
        if completed.returncode != 0:
            raise PackagingError(completed.stderr.strip() or f"command failed: {argv[0]}")
        return completed.stdout

    def validate_architecture(self, payload: Path, rel: str, arch: str) -> None:
        self.actions.append(f"arch:{rel}")
        if self.fake:
            return
        try:
            out = self._run(self.command_plan("lipo_archs", payload / rel)).strip()
        except PackagingError as exc:
            raise PackagingError(f"{rel} is not exactly {arch}: {exc}") from exc
        if out != arch:
            raise PackagingError(f"{rel} is not exactly {arch}: {out}")

    def rewrite_install_names(self, payload: Path, rel: str) -> None:
        self.actions.append(f"rewrite:{rel}")
        if self.fake:
            return
        target = payload / rel
        if rel.endswith(".dylib"):
            self._run(self.command_plan("install_id", target, [f"@rpath/{target.name}"]))
        otool_out = self._run(self.command_plan("otool", target))
        for line in otool_out.splitlines()[1:]:
            dep = line.strip().split(" ", 1)[0] if line.strip() else ""
            if not dep or dep.startswith(SYSTEM_DYLIB_PREFIXES) or dep.startswith("@"):
                continue
            verify_rewrite_target_exists(payload, rel, dep)
            replacement = loader_replacement_for(rel, dep)
            self._run(self.command_plan("install_change", target, [dep, replacement]))

    def assert_no_homebrew_load_paths(self, payload: Path, rel: str) -> None:
        self.actions.append(f"otool-clean:{rel}")
        if self.fake:
            return
        out = self._run(self.command_plan("otool", payload / rel))
        for line in out.splitlines()[1:]:
            dep = line.strip().split(" ", 1)[0] if line.strip() else ""
            if dep.startswith("/") and not dep.startswith(SYSTEM_DYLIB_PREFIXES):
                raise PackagingError(f"unresolved non-system absolute load path in {rel}: {dep}")

    def sign(self, payload: Path, rel: str) -> None:
        self.actions.append(f"sign:{rel}")
        self._run(self.command_plan("sign", payload / rel))

    def verify_signature(self, payload: Path, rel: str) -> None:
        self.actions.append(f"verify-signature:{rel}")
        action = "verify_signature_deep" if rel.endswith(":deep-strict") else "verify_signature"
        clean_rel = rel.replace(":deep-strict", "")
        self._run(self.command_plan(action, payload / clean_rel))

    def create_dmg(self, stage_dir: Path, dmg_path: Path) -> None:
        self.actions.append("create-dmg")
        if self.fake:
            dmg_path.write_bytes(json.dumps(build_manifest(stage_dir), sort_keys=True).encode() + b"\n")
            return
        self._run(self.command_plan("create_dmg", dmg_path, [str(stage_dir)]))

    def verify_dmg(self, dmg_path: Path) -> None:
        self.actions.append("verify-dmg")
        self._run(self.command_plan("verify_dmg", dmg_path))

    def attach_readonly(self, dmg_path: Path, mountpoint: Path, stage_dir: Path) -> bool:
        self.actions.append("attach-readonly")
        if self.attach_fails:
            raise PackagingError("injected attach failure")
        if self.fake:
            shutil.copytree(stage_dir, mountpoint, dirs_exist_ok=True)
            if self.tamper_mounted_file:
                with (mountpoint / self.tamper_mounted_file).open("a", encoding="utf-8") as fh:
                    fh.write("tampered")
            return True
        self._run(self.command_plan("attach_readonly", dmg_path, [str(mountpoint)]))
        return True

    def detach(self, mountpoint: Path) -> None:
        self.actions.append("detach")
        if self.fake:
            if self.detach_fails:
                raise PackagingError("injected detach failure")
            if mountpoint.exists():
                for child in sorted(mountpoint.rglob("*"), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                mountpoint.rmdir()
            return
        self._run(self.command_plan("detach", mountpoint))


def mach_o_payload_files(stage_dir: Path) -> List[str]:
    ordered: List[str] = []
    preferred = [
        "runtime/openconnect/bin/openconnect",
        "runtime/openconnect/lib/libopenconnect.5.dylib",
        "runtime/oathtool",
        "runtime/vpnc/hyu-vpnc-wrapperd",
        "com.hyu.vpn.helper",
        "HYU VPN.app/Contents/MacOS/HYUVPNMenuApp",
        "HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader",
        INSTALLER_EXEC_REL,
    ]
    seen: set[str] = set()
    for rel in preferred:
        if (stage_dir / rel).exists():
            ordered.append(rel); seen.add(rel)
    if (stage_dir / "runtime/openconnect/lib").exists():
        for path in sorted((stage_dir / "runtime/openconnect/lib").glob("*.dylib")):
            rel = path.relative_to(stage_dir).as_posix()
            if rel not in seen:
                ordered.append(rel); seen.add(rel)
    return ordered


class ReleaseBuilder:
    def __init__(self, toolchain: ReleaseToolchain | None = None) -> None:
        self.toolchain = toolchain or ReleaseToolchain(fake=False)

    def build(
        self,
        *,
        source_payload: Path,
        build_root: Path,
        output_root: Path,
        version: str,
        arch: str,
        git_commit: str | None = None,
    ) -> ReleaseResult:
        if arch != "arm64":
            raise PackagingError("internal lab release must be labeled arm64")
        if not _valid_token(version):
            raise PackagingError("unsafe release version token")
        if git_commit is not None and GIT_COMMIT_RE.fullmatch(git_commit) is None:
            raise PackagingError("git commit must be a 40-character lowercase hex SHA")
        build_root = guard_root(build_root)
        output_root = guard_root(output_root)
        output_root.mkdir(parents=True, exist_ok=True)
        output_root = guard_root(output_root)
        stage_dir = guard_destination(build_root / f"HYU-VPN-{version}-{arch}", allowed_root=build_root)
        stage_dir.mkdir(parents=True)
        _copy_payload(Path(source_payload), stage_dir)
        has_source_bundle = (stage_dir / SOURCE_COMPLIANCE_BUNDLE).is_file()
        if not self.toolchain.fake and not has_source_bundle:
            raise PackagingError("real release requires manifested SOURCE-COMPLIANCE-BUNDLE.tar.gz")
        if has_source_bundle:
            validate_source_compliance_bundle(stage_dir / SOURCE_COMPLIANCE_BUNDLE)
            # The source bundle records the canonical runtime before install-name
            # rewriting and ad-hoc signing.  A separate binding written below
            # ties those canonical files to the final shipped runtime.
            validate_source_bundle_matches_payload(stage_dir / SOURCE_COMPLIANCE_BUNDLE, stage_dir)

        metadata = {
            "schema": 1,
            "name": "HYU VPN",
            "version": version,
            "architecture": arch,
            "universal": False,
            "signing": "ad-hoc",
            "notarized": False,
            "distribution": "internal-lab",
            "installer_ux": "native-gui-no-terminal",
            "administrator_authorization": "macos-ui-once",
            "manifest": MANIFEST_NAME,
            "python_runtime_contract": "fixed-system-python-prerequisite",
            "prerequisites": {"python3": PYTHON_PREREQUISITE},
            "task7_pre_sudo_requirements": ["verify /usr/bin/python3 exists and is executable", "never use PATH or Homebrew python fallback"],
            "release_blockers": [] if has_source_bundle else ["bundle exact GPL/LGPL source archives or retained written-offer packet before real lab distribution"],
            "git_commit": git_commit,
            "source_compliance_bundle_scope": SOURCE_COMPLIANCE_BUNDLE_SCOPE if has_source_bundle else None,
            "source_compliance_bundle_semantics": SOURCE_COMPLIANCE_BUNDLE_SEMANTICS if has_source_bundle else None,
            "final_runtime_binding": FINAL_RUNTIME_BINDING if has_source_bundle else None,
            "bit_reproducible_dmg": False,
            "deterministic_manifest": True,
        }
        (stage_dir / "release-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        macho_rels = mach_o_payload_files(stage_dir)
        for rel in macho_rels:
            self.toolchain.validate_architecture(stage_dir, rel, arch)
        for rel in macho_rels:
            self.toolchain.rewrite_install_names(stage_dir, rel)
            self.toolchain.assert_no_homebrew_load_paths(stage_dir, rel)
        for rel in macho_rels:
            self.toolchain.sign(stage_dir, rel)
            self.toolchain.verify_signature(stage_dir, rel)
        for app_rel in APP_BUNDLE_RELS:
            self.toolchain.sign(stage_dir, app_rel)
            self.toolchain.verify_signature(stage_dir, app_rel)
            self.toolchain.verify_signature(stage_dir, app_rel + ":deep-strict")
        if has_source_bundle:
            write_final_runtime_binding(stage_dir / SOURCE_COMPLIANCE_BUNDLE, stage_dir)

        manifest = build_manifest(stage_dir)
        manifest_path = stage_dir / MANIFEST_NAME
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        dmg_path = output_root / f"HYU-VPN-{version}-{arch}.dmg"
        if dmg_path.exists() or dmg_path.is_symlink():
            raise PackagingError(f"refusing to overwrite existing DMG: {dmg_path}")
        self.toolchain.create_dmg(stage_dir, dmg_path)
        self.toolchain.verify_dmg(dmg_path)
        mountpoint = Path(tempfile.mkdtemp(prefix="hyu-vpn-dmg-", dir=str(output_root)))
        attached = False
        primary_error: BaseException | None = None
        try:
            attached = self.toolchain.attach_readonly(dmg_path, mountpoint, stage_dir)
            self._validate_mounted_payload(mountpoint, manifest)
            if self.toolchain.fail_mounted_validation:
                raise PackagingError("injected mounted validation failure")
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            detach_error: Exception | None = None
            try:
                if attached:
                    self.toolchain.detach(mountpoint)
            except Exception as exc:
                detach_error = exc
            if detach_error is None and mountpoint.exists():
                mountpoint.rmdir()
            if detach_error is not None and primary_error is None:
                raise detach_error
        checksum_path = dmg_path.with_suffix(dmg_path.suffix + ".sha256")
        checksum_path.write_text(f"{_sha256(dmg_path)}  {dmg_path.name}\n", encoding="utf-8")
        return ReleaseResult(stage_dir=stage_dir, dmg_path=dmg_path, checksum_path=checksum_path, manifest_path=manifest_path, manifest=manifest, metadata=metadata)

    def _validate_mounted_payload(self, mountpoint: Path, expected_manifest: Mapping[str, Any]) -> None:
        manifest_path = mountpoint / MANIFEST_NAME
        actual_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if actual_manifest != expected_manifest:
            raise PackagingError("mounted manifest content mismatch")
        actual = build_manifest(mountpoint)
        expected_files = set(expected_manifest["files"])
        actual_files = set(actual["files"])
        if actual_files != expected_files:
            raise PackagingError(f"mounted payload mismatch extras={sorted(actual_files - expected_files)} missing={sorted(expected_files - actual_files)}")
        for rel, expected in expected_manifest["files"].items():
            if actual["files"].get(rel) != expected:
                raise PackagingError(f"mounted payload hash/mode/size mismatch: {rel}")
        metadata = json.loads((mountpoint / "release-metadata.json").read_text(encoding="utf-8"))
        if metadata.get("architecture") != "arm64" or metadata.get("notarized") is not False:
            raise PackagingError("mounted metadata does not match internal arm64 lab release")
        source_bundle = mountpoint / SOURCE_COMPLIANCE_BUNDLE
        if source_bundle.exists():
            validate_final_runtime_binding(mountpoint / FINAL_RUNTIME_BINDING, source_bundle, mountpoint)
