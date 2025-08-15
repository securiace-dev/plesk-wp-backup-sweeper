#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plesk_wp_backup_sweeper.py (v1.2.0)

Safely scan a Plesk-managed server for web-exposed **and non-web** WordPress backup
archives and (optionally) quarantine or permanently delete them — with strict
safety-first defaults.

Python: 3.10.12
Dependencies: Standard library only
"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import dataclasses
import fnmatch
import getpass
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.2.0"

LOGGER = logging.getLogger("plesk_wp_backup_sweeper")

# ------------------------------ Data structures ------------------------------
@dataclasses.dataclass(frozen=True)
class Site:
    domain: str  # label (domain for web, NONWEB:<path> for non-web)
    docroot: Path


@dataclasses.dataclass
class Finding:
    site: Site
    path: Path
    rel_path: str
    size: int
    mtime: float
    ctime: float
    mode: int
    uid: int
    gid: int
    plugin: Optional[str]
    kind: str  # extension or category
    risk: int
    sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "site": self.site.domain,
            "docroot": str(self.site.docroot),
            "path": str(self.path),
            "rel_path": self.rel_path,
            "size": self.size,
            "mtime": datetime.fromtimestamp(self.mtime).isoformat(),
            "ctime": datetime.fromtimestamp(self.ctime).isoformat(),
            "mode": oct(self.mode),
            "uid": self.uid,
            "gid": self.gid,
            "plugin": self.plugin,
            "kind": self.kind,
            "risk": self.risk,
            "sha256": self.sha256,
        }


# ------------------------------ Utility helpers -----------------------------

def run_cmd(cmd: Sequence[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        LOGGER.debug("Running command: %s", " ".join(map(shlex.quote, cmd)))
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return cp.returncode, cp.stdout, cp.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout after {timeout}s running: {' '.join(cmd)}"


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# --------------------------- Plesk-aware discovery ---------------------------
PLESK_POSSIBLE_DOCROOTS = ("httpdocs", "httpsdocs", "htdocs", "public_html")
VHOSTS_BASE = Path("/var/www/vhosts")


def discover_sites_via_plesk_cli() -> List[Site]:
    rc, out, err = run_cmd(["plesk", "bin", "domain", "--list"], timeout=60)
    if rc != 0:
        LOGGER.debug("Plesk CLI domain list failed: rc=%s err=%s", rc, err.strip())
        return []
    domains = [d.strip() for d in out.splitlines() if d.strip()]
    sites: List[Site] = []
    for domain in domains:
        rc, info_out, _ = run_cmd(["plesk", "bin", "domain", "--info", domain], timeout=60)
        if rc != 0:
            continue
        m = re.search(r"Document\s+root:\s*(.+)", info_out)
        if m:
            docroot = Path(m.group(1).strip())
        else:
            docroot = VHOSTS_BASE / domain / "httpdocs"
        if docroot.exists():
            sites.append(Site(domain=domain, docroot=docroot))
    return sites


def discover_sites_via_psa_db() -> List[Site]:
    query = (
        "SELECT d.name, CONCAT('/var/www/vhosts/', d.name, '/', h.www_root) AS dr "
        "FROM domains d JOIN hosting h ON h.dom_id=d.id WHERE h.type='vrt_hst';"
    )
    rc, out, err = run_cmd(["plesk", "db", "-Ne", query], timeout=60)
    if rc != 0:
        LOGGER.debug("PSA DB discovery failed: rc=%s err=%s", rc, err.strip())
        return []
    sites: List[Site] = []
    for line in out.splitlines():
        parts = line.strip().split("\t") if line.strip() else []
        if not parts:
            continue
        if len(parts) == 1:
            parts = re.split(r"\s+", line.strip(), maxsplit=1)
        if len(parts) != 2:
            continue
        domain, dr = parts[0].strip(), parts[1].strip()
        p = Path(dr)
        if p.exists():
            sites.append(Site(domain=domain, docroot=p))
    return sites


def discover_sites_via_fs() -> List[Site]:
    sites: List[Site] = []
    if not VHOSTS_BASE.exists():
        return sites
    for domain_dir in VHOSTS_BASE.iterdir():
        if not domain_dir.is_dir():
            continue
        domain = domain_dir.name
        for candidate in PLESK_POSSIBLE_DOCROOTS:
            dr = domain_dir / candidate
            if dr.is_dir():
                sites.append(Site(domain=domain, docroot=dr))
        subdomains_dir = domain_dir / "subdomains"
        if subdomains_dir.is_dir():
            for sub in subdomains_dir.iterdir():
                if not sub.is_dir():
                    continue
                for candidate in PLESK_POSSIBLE_DOCROOTS:
                    dr = sub / candidate
                    if dr.is_dir():
                        sites.append(Site(domain=f"{sub.name}.{domain}", docroot=dr))
    return sites


# ------------------------------ WP verification ------------------------------
WP_MARKERS = ("wp-config.php", "wp-includes/version.php")


def is_wp_docroot(path: Path) -> bool:
    try:
        return all((path / m).exists() for m in WP_MARKERS)
    except Exception:
        return False


# ------------------------------ Patterns config ------------------------------
PLUGIN_PATTERNS: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "UpdraftPlus": (("wp-content/updraft",), ("*.zip", "*.tar", "*.tar.gz", "*.tgz")),
    "All-in-One WP Migration": (("wp-content/ai1wm-backups",), ("*.wpress",)),
    "Duplicator": (("wp-content/backups-dup-pro", "wp-snapshots", "wp-content/snapshots"), ("*.zip", "*.daf")),
    "WPvivid": (("wp-content/wpvividbackups",), ("*.zip", "*.tar", "*.tar.gz", "*.tgz")),
    "BackWPup": (("wp-content/uploads",), ("backwpup-*.zip",)),
    "BackupBuddy": (("wp-content/uploads/backupbuddy_backups",), ("*.zip", "*.backupbuddy", "*.solidbackup")),
    "WP Staging": (("wp-content/wp-staging",), ("*.zip", "*.tar", "*.tar.gz")),
    "XCloner": (("wp-content/backup-xcloner",), ("*.zip", "*.tar", "*.tar.gz")),
    "Total Upkeep": (("wp-content/boldgrid-backups",), ("*.zip", "*.tar", "*.tar.gz")),
    "WP-DBManager": (("wp-content/backup-db",), ("*.sql", "*.sql.gz")),
    "Backup Migration": (("wp-content/backup-migration",), ("*.zip",)),
    "All In One Security": (("wp-content/aios_backups",), ("*.zip",)),
    "WP Reset": (("wp-content/wp-reset-autosnapshots",), ("*.zip",)),
}

GENERIC_FILE_GLOBS = (
    "*.wpress",
    "*.zip",
    "*.tar",
    "*.tar.gz",
    "*.tgz",
    "*.bz2",
    "*.7z",
    "*.xz",
    "*.zst",
    "*.sql",
    "*.sql.gz",
    "*.dump",
    "*.bak",
    "*.backup",
    "*_backup.*",
    "backup_*.*",
    "*.jpa",
    "*.jps",
    "*.daf",
    "*.backupbuddy",
    "*.solidbackup",
)

GENERIC_DIR_HINTS = (
    "wp-content/backup",
    "wp-content/backups",
    "wp-content/uploads/backup",
    "wp-content/uploads/backups",
    "wp-content/*backup*",
)

SENSITIVE_EXCLUDES = ("/var/lib/psa/dumps/",)

# Non-web default roots (only scanned if --include-non-web)
DEFAULT_NONWEB_GLOBS = (
    "/var/backups",
    "/var/www/vhosts/*/private",
    "/var/www/vhosts/*/files",
    "/var/www/vhosts/system/*/backup",
)


# ------------------------------ Risk assessment ------------------------------
EXTENSION_WEIGHTS = {
    ".wpress": 30,
    ".sql": 35,
    ".gz": 10,
    ".zip": 20,
    ".tar": 20,
    ".tgz": 20,
    ".bz2": 20,
    ".7z": 25,
    ".xz": 20,
    ".zst": 20,
    ".dump": 25,
    ".bak": 15,
    ".jpa": 30,
    ".jps": 30,
    ".daf": 30,
    ".backupbuddy": 25,
    ".solidbackup": 25,
}


def world_readable(mode: int) -> bool:
    return bool(mode & stat.S_IROTH)


def path_depth(docroot: Path, path: Path) -> int:
    try:
        return len(path.relative_to(docroot).parts)
    except Exception:
        return 999


def compute_sha256(path: Path, bufsize: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(bufsize), b""):
            h.update(chunk)
    return h.hexdigest()


def score_risk(site: Site, fpath: Path, st: os.stat_result, plugin: Optional[str]) -> Tuple[int, str]:
    ext = ''.join(Path(fpath.name).suffixes).lower()
    base_weight = EXTENSION_WEIGHTS.get(ext, 10)
    depth = path_depth(site.docroot, fpath)
    loc_bonus = 20 if depth <= 3 else 5
    plugin_bonus = 25 if plugin else 0
    age_days = max(0, (time.time() - st.st_mtime) / 86400.0)
    age_bonus = 15 if age_days >= 30 else (8 if age_days >= 7 else 0)
    wr_bonus = 10 if world_readable(st.st_mode) else 0
    risk = min(100, base_weight + loc_bonus + plugin_bonus + age_bonus + wr_bonus)
    kind = ext or "unknown"
    return risk, kind


# ------------------------------- Scanning logic ------------------------------

def iter_files(dirpath: Path, *, max_depth: int, follow_symlinks: bool) -> Iterator[Path]:
    base_parts = len(dirpath.parts)
    stack = [dirpath]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if not follow_symlinks and entry.is_symlink():
                            continue
                        p = Path(entry.path)
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            if len(p.parts) - base_parts < max_depth:
                                stack.append(p)
                            continue
                        if entry.is_file(follow_symlinks=follow_symlinks):
                            yield p
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            continue


def match_any_glob(name: str, patterns: Sequence[str]) -> bool:
    lname = name.lower()
    return any(fnmatch.fnmatch(lname, pat.lower()) for pat in patterns)


def scan_site(site: Site, *, max_depth: int, min_size: int, age_days: int,
              plugin_only: bool, follow_symlinks: bool) -> List[Finding]:
    findings: List[Finding] = []

    def in_any_plugin_dir(p: Path) -> Optional[str]:
        rel = p.relative_to(site.docroot)
        rel_str = str(rel).replace('\\', '/')
        for plugin, (dirs, globs) in PLUGIN_PATTERNS.items():
            for d in dirs:
                d_norm = d.strip('/').lower()
                if rel_str.lower().startswith(d_norm + "/") or rel_str.lower() == d_norm:
                    if match_any_glob(p.name, globs):
                        return plugin
        return None

    now = time.time()

    for f in iter_files(site.docroot, max_depth=max_depth, follow_symlinks=follow_symlinks):
        try:
            st = f.stat(follow_symlinks=False)
        except (PermissionError, FileNotFoundError, OSError):
            continue
        if st.st_size < min_size:
            continue
        if any(part in {".git", ".svn", ".hg"} for part in f.parts):
            continue

        plugin = in_any_plugin_dir(f)
        matched = False
        if plugin:
            matched = True
        else:
            if not plugin_only:
                rel = f.relative_to(site.docroot)
                rel_str = str(rel).replace('\\', '/')
                if any(rel_str.lower().startswith(h.lower()) for h in GENERIC_DIR_HINTS):
                    if match_any_glob(f.name, GENERIC_FILE_GLOBS):
                        matched = True
                else:
                    if match_any_glob(f.name, GENERIC_FILE_GLOBS) and path_depth(site.docroot, f) <= 6:
                        matched = True
        if not matched:
            continue

        file_age_days = (now - st.st_mtime) / 86400.0
        if age_days > 0 and file_age_days < age_days:
            pass

        risk, kind = score_risk(site, f, st, plugin)
        findings.append(Finding(
            site=site,
            path=f,
            rel_path=str(f.relative_to(site.docroot)),
            size=st.st_size,
            mtime=st.st_mtime,
            ctime=st.st_ctime,
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
            plugin=plugin,
            kind=kind,
            risk=risk,
        ))

    return findings


# -------------------------- Non-web path collection --------------------------

def expand_glob_paths(patterns: Iterable[str]) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        # manual glob to avoid importing glob for simple use
        for p in Path('/').glob(pat.lstrip('/')) if pat.startswith('/') else Path('.').glob(pat):
            try:
                if p.exists() and p.is_dir():
                    out.append(p)
            except Exception:
                continue
    return out


def gather_nonweb_sites(args: argparse.Namespace) -> List[Site]:
    roots: List[Path] = []
    if args.include_non_web:
        roots.extend(expand_glob_paths(DEFAULT_NONWEB_GLOBS))
    if args.include_plesk_dumps:
        p = Path('/var/lib/psa/dumps')
        if p.exists() and p.is_dir():
            roots.append(p)
    for pth in args.extra_nonweb_path:
        p = Path(pth)
        if p.exists() and p.is_dir():
            roots.append(p)
    sites: List[Site] = []
    seen: set[str] = set()
    for r in roots:
        key = str(r.resolve())
        if key in seen:
            continue
        seen.add(key)
        label = f"NONWEB:{r}"
        sites.append(Site(domain=label, docroot=r))
    return sites


# ------------------------------- Quarantine ops ------------------------------

def ensure_quarantine_root(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except Exception:
        pass


def has_free_space(dest_dir: Path, required_bytes: int) -> bool:
    try:
        usage = shutil.disk_usage(dest_dir)
        return usage.free >= required_bytes
    except Exception:
        return True


def atomic_move(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src, dst)


def write_manifest(manifest_path: Path, records: List[Dict[str, object]]) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump({"version": __version__, "items": records}, f, indent=2)


# --------------------------- Space estimation utils --------------------------

def device_id(path: Path) -> int:
    try:
        return os.stat(path).st_dev
    except Exception:
        return -1


def disk_free(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except Exception:
        return 0


def estimate_space(findings: List[Finding], *, quarantine_root: Path, permanent: bool) -> Tuple[Dict[str, int], Dict[str, int]]:
    """Return (pre_free, est_post_free) per mount label.
    Labels are the mount root strings for readability (using the first file under that device).
    For quarantine: if src and dest devices differ, dest free decreases by size and src increases by size.
    If same device, free space unchanged by move.
    For permanent delete: src increases by size.
    """
    # Group by device using the first path seen as label
    dev_labels: Dict[int, str] = {}
    pre_free: Dict[int, int] = {}

    # Include quarantine device in the map
    q_dev = device_id(quarantine_root)
    dev_labels[q_dev] = f"DEST:{quarantine_root}"
    pre_free[q_dev] = disk_free(quarantine_root)

    for f in findings:
        d = device_id(f.path)
        if d not in dev_labels:
            dev_labels[d] = f"SRC:{f.path.anchor or f.site.docroot}"
            pre_free[d] = disk_free(f.path)

    # Initialize post with pre
    post_free = dict(pre_free)

    for f in findings:
        src_dev = device_id(f.path)
        size = f.size
        if permanent:
            post_free[src_dev] = post_free.get(src_dev, 0) + size
        else:
            # quarantine action
            if src_dev == q_dev:
                # rename within same device: no free change
                continue
            # cross-device copy -> src increases, dest decreases
            post_free[src_dev] = post_free.get(src_dev, 0) + size
            post_free[q_dev] = post_free.get(q_dev, 0) - size

    # Convert device-indexed dicts to label-indexed for printing
    pre_labeled = {dev_labels[d]: free for d, free in pre_free.items()}
    post_labeled = {dev_labels[d]: free for d, free in post_free.items()}
    return pre_labeled, post_labeled


# --------------------------------- CLI engine --------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Safely find and (optionally) quarantine/remove WP backup archives on Plesk (web + non-web).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    scope = p.add_argument_group("Scope & discovery")
    scope.add_argument("--auto-plesk", action="store_true", default=True, help="Discover via Plesk CLI if available")
    scope.add_argument("--allow-psa-db", action="store_true", help="Allow PSA DB query fallback via `plesk db`")
    scope.add_argument("--extra-path", action="append", default=[], help="Additional web docroot path to include (repeatable)")
    scope.add_argument("--include-plesk-dumps", action="store_true", help="Also scan /var/lib/psa/dumps (quarantine-first)")
    scope.add_argument("--include-non-web", action="store_true", help="Scan common non-web backup locations (e.g., /var/backups, vhosts private)")
    scope.add_argument("--extra-nonweb-path", action="append", default=[], help="Extra non-web base path to include (repeatable)")
    scope.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks during scan")
    scope.add_argument("--cross-filesystems", action="store_true", help="Allow crossing filesystems during scan (best-effort)")

    filt = p.add_argument_group("Filters & limits")
    filt.add_argument("--min-size", default="5M", help="Ignore files smaller than this (e.g., 5M, 200K, 1G)")
    filt.add_argument("--max-depth", type=int, default=12, help="Max directory depth under base path")
    filt.add_argument("--age-days", type=int, default=0, help="Only act on files older than N days (still report younger)")
    filt.add_argument("--plugin-only", action="store_true", help="Only act inside known plugin backup directories (web paths)")
    filt.add_argument("--exclude-glob", action="append", default=[], help="Exclude files/paths by glob (repeatable)")
    filt.add_argument("--exclude-regex", action="append", default=[], help="Exclude files/paths by regex (repeatable)")
    filt.add_argument("--exclude-site", action="append", default=[], help="Exclude entire site/domain label (repeatable)")

    act = p.add_argument_group("Actions & safety")
    act.add_argument("--dry-run", action="store_true", default=True, help="Report only; never modify anything")
    act.add_argument("--yes", action="store_true", help="Auto-approve quarantine for matches (still shows summary)")
    act.add_argument("--permanent", action="store_true", help="Permanently delete instead of quarantine (double-confirmation)")
    act.add_argument("--force-token", default=None, help="Token to bypass interactive delete confirmation in non-interactive runs")
    act.add_argument("--quarantine-root", default="/var/backup-quarantine", help="Quarantine base directory (non-web)")

    out = p.add_argument_group("Output & logging")
    out.add_argument("--report-json", default=None, help="Write detailed JSON report to this path")
    out.add_argument("--report-csv", default=None, help="Write CSV report to this path")
    out.add_argument("--log-file", default="/var/log/plesk-wp-backup-sweeper.log", help="Structured log file (JSON lines)")
    out.add_argument("--quiet", action="store_true", help="Minimal console output")
    out.add_argument("--verbose", action="store_true", help="Verbose console output")
    out.add_argument("--debug", action="store_true", help="Debug console output")

    perf = p.add_argument_group("Performance")
    perf.add_argument("--concurrency", type=int, default=8, help="Number of parallel workers for scanning")
    perf.add_argument("--timeout", type=int, default=600, help="Overall soft timeout in seconds (best-effort)")

    rest = p.add_argument_group("Restore")
    rest.add_argument("--restore", default=None, help="Restore files from a quarantine manifest.json")

    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def parse_size(size_str: str) -> int:
    m = re.match(r"^(\d+)([KMG]?)$", size_str.strip(), re.IGNORECASE)
    if not m:
        raise ValueError(f"Invalid size: {size_str}")
    num = int(m.group(1))
    unit = m.group(2).upper()
    mult = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[unit]
    return num * mult


def prepare_logging(args: argparse.Namespace) -> None:
    LOGGER.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    if args.debug:
        ch.setLevel(logging.DEBUG)
    elif args.verbose:
        ch.setLevel(logging.INFO)
    elif args.quiet:
        ch.setLevel(logging.WARNING)
    else:
        ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOGGER.addHandler(ch)
    try:
        fh = JsonLineFileHandler(args.log_file)
        fh.setLevel(logging.DEBUG)
        LOGGER.addHandler(fh)
    except Exception as e:
        LOGGER.warning("Could not open log file %s: %s", args.log_file, e)


class JsonLineFileHandler(logging.FileHandler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_entry = {"ts": datetime.utcnow().isoformat() + "Z", "level": record.levelname, "msg": record.getMessage()}
            if isinstance(record.args, dict):
                log_entry.update(record.args)
        except Exception:
            log_entry = {"ts": datetime.utcnow().isoformat() + "Z", "level": record.levelname, "msg": record.getMessage()}
        self.stream.write(json.dumps(log_entry) + "\n")
        self.flush()


def discover_sites(args: argparse.Namespace) -> List[Site]:
    candidates: Dict[Tuple[str, str], Site] = {}
    if args.auto_plesk:
        for s in discover_sites_via_plesk_cli():
            candidates.setdefault((s.domain, str(s.docroot)), s)
    if args.allow_psa_db and not candidates:
        for s in discover_sites_via_psa_db():
            candidates.setdefault((s.domain, str(s.docroot)), s)
    if not candidates:
        for s in discover_sites_via_fs():
            candidates.setdefault((s.domain, str(s.docroot)), s)
    # Extra explicit web paths
    for p in args.extra_path:
        path = Path(p)
        if path.exists() and path.is_dir():
            label = path.parts[-2] if len(path.parts) >= 2 else path.name
            candidates.setdefault((label, str(path)), Site(domain=label, docroot=path))

    # Filter: WordPress only
    wp_sites: List[Site] = []
    for s in list(candidates.values()):
        if any(ex in str(s.docroot) for ex in SENSITIVE_EXCLUDES):
            continue
        if s.domain in args.exclude_site:
            continue
        if is_wp_docroot(s.docroot):
            wp_sites.append(s)
    return wp_sites


# ----------------------------------- Main ------------------------------------

def excluded_by_patterns(rel_path: str, *, globs: Sequence[str], regexes: Sequence[str]) -> bool:
    if any(fnmatch.fnmatch(rel_path, g) for g in globs):
        return True
    for rx in regexes:
        try:
            if re.search(rx, rel_path):
                return True
        except re.error:
            continue
    return False


def confirm(prompt: str) -> bool:
    try:
        resp = input(f"{prompt} [y/N]: ").strip().lower()
        return resp in {"y", "yes"}
    except EOFError:
        return False


def double_confirm_delete(fp: Path, sha256_hex: str, *, force_token: Optional[str]) -> bool:
    token = f"DELETE:{sha256_hex[:8]}"
    if force_token is not None:
        if force_token == token:
            return True
        LOGGER.error("Incorrect --force-token provided. Expected token %s for %s", token, fp)
        return False
    print(f"\nPERMANENT DELETE requested for: {fp}\nType the confirmation token to proceed: {token}")
    typed = input("Token: ").strip()
    return typed == token


def restore_from_manifest(manifest_path: Path) -> int:
    if not manifest_path.exists():
        LOGGER.error("Manifest not found: %s", manifest_path)
        return 3
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        items = data.get("items", [])
    except Exception as e:
        LOGGER.error("Failed reading manifest: %s", e)
        return 3
    errors = 0
    for it in items:
        try:
            src = Path(it["quarantined_path"])  # current location
            dst = Path(it["original_path"])     # restore target
            dst.parent.mkdir(parents=True, exist_ok=True)
            expected = it.get("sha256")
            if expected and src.exists():
                actual = compute_sha256(src)
                if actual != expected:
                    LOGGER.error("Hash mismatch for %s; skipping restore", src)
                    errors += 1
                    continue
            os.replace(src, dst)
            try:
                os.chmod(dst, int(it.get("mode", "0o644"), 8))
            except Exception:
                pass
            try:
                atime = time.time()
                mtime_iso = it.get("mtime")
                if isinstance(mtime_iso, str):
                    if mtime_iso.endswith("Z"):
                        mtime_iso = mtime_iso[:-1]
                    mtime = datetime.fromisoformat(mtime_iso).timestamp()
                else:
                    mtime = datetime.now().timestamp()
                os.utime(dst, (atime, mtime))
            except Exception:
                pass
            LOGGER.info("Restored %s -> %s", src, dst)
        except Exception as e:
            LOGGER.error("Restore failure: %s", e)
            errors += 1
    return 0 if errors == 0 else 3


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    prepare_logging(args)

    if args.restore:
        return restore_from_manifest(Path(args.restore))

    if (args.permanent or (args.yes and not args.dry_run)) and not is_root():
        LOGGER.error("Refusing destructive action without root privileges.")
        return 11

    try:
        min_size = parse_size(args.min_size)
    except ValueError as e:
        LOGGER.error(str(e))
        return 1

    LOGGER.info("Discovering WordPress sites (web) and requested non-web roots…")
    web_sites = discover_sites(args)
    nonweb_sites = gather_nonweb_sites(args)

    if not web_sites and not nonweb_sites:
        LOGGER.warning("No scan roots discovered. Nothing to do.")
        return 0

    sites: List[Site] = web_sites + nonweb_sites
    LOGGER.info("Scan roots: %d (web=%d, non-web=%d)", len(sites), len(web_sites), len(nonweb_sites))

    all_findings: List[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futures = [
            ex.submit(
                scan_site,
                s,
                max_depth=args.max_depth,
                min_size=min_size,
                age_days=args.age_days,
                plugin_only=args.plugin_only if s in web_sites else False,
                follow_symlinks=args.follow_symlinks,
            )
            for s in sites
            if s.domain not in args.exclude_site
        ]
        for fut in concurrent.futures.as_completed(futures):
            try:
                all_findings.extend(fut.result())
            except Exception as e:
                LOGGER.error("Scan error: %s", e)

    # Apply user exclusions
    filtered: List[Finding] = []
    for f in all_findings:
        rel = f"{f.site.domain}/{f.rel_path}"
        if excluded_by_patterns(rel, globs=args.exclude_glob, regexes=args.exclude_regex):
            continue
        filtered.append(f)

    filtered.sort(key=lambda x: (x.site.domain, -x.risk, -x.size))

    if not filtered:
        LOGGER.info("No risky backup archives found.")
        return 0

    # Console preview
    if not args.quiet:
        print("\nPotentially risky backup archives found:\n")
        print(f"{'Risk':>4}  {'Size(MB)':>8}  {'Age(d)':>6}  {'Plugin':<22}  {'Site':<38}  Path")
        now = time.time()
        for f in filtered[:200]:
            age_d = int((now - f.mtime) / 86400.0)
            site_lbl = (f.site.domain[:38])
            print(f"{f.risk:>4}  {f.size/1024/1024:>8.1f}  {age_d:>6}  {str(f.plugin or '-')[:22]:<22}  {site_lbl:<38}  {f.rel_path}")
        if len(filtered) > 200:
            print(f"… and {len(filtered)-200} more. Use --report-* for full details.")

    # Reports
    if args.report_json:
        outp = Path(args.report_json); outp.parent.mkdir(parents=True, exist_ok=True)
        with outp.open("w", encoding="utf-8") as f:
            json.dump([fi.to_dict() for fi in filtered], f, indent=2)
        LOGGER.info("Wrote JSON report: %s", outp)
    if args.report_csv:
        outp = Path(args.report_csv); outp.parent.mkdir(parents=True, exist_ok=True)
        with outp.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "site","docroot","path","rel_path","size","mtime","ctime","mode","uid","gid","plugin","kind","risk","sha256"
            ])
            w.writeheader(); [w.writerow(fi.to_dict()) for fi in filtered]
        LOGGER.info("Wrote CSV report: %s", outp)

    # Dry-run ends here, but show space estimates as requested
    quarantine_root = Path(args.quarantine_root)
    ensure_quarantine_root(quarantine_root)

    pre_free, est_post_free = estimate_space(filtered, quarantine_root=quarantine_root, permanent=args.permanent)
    print("\n=== SPACE ESTIMATE (assuming all listed files are acted on) ===")
    print("Pre-operation free space:")
    for label, free in pre_free.items():
        print(f"  {label:35}  {free/1024/1024/1024:.2f} GiB free")
    print("Estimated post-operation free space:")
    for label, free in est_post_free.items():
        print(f"  {label:35}  {free/1024/1024/1024:.2f} GiB free")

    if args.dry_run:
        LOGGER.info("Dry-run complete. No changes made.")
        return 2

    # Prepare quarantine batch
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    batch_root = quarantine_root / ts
    ensure_quarantine_root(batch_root)

    # Summary & confirmation
    total_bytes = sum(f.size for f in filtered)
    print("\n=== ACTION SUMMARY (Quarantine by default unless --permanent) ===")
    print(f"Files matched: {len(filtered)}  |  Total size: {total_bytes/1024/1024:.1f} MB")
    if not args.yes:
        if not confirm("Proceed to review files one-by-one for quarantine/deletion?"):
            LOGGER.info("Aborted by user before actions.")
            return 10

    manifest_records: List[Dict[str, object]] = []
    errors = 0
    acted = 0

    for f in filtered:
        try:
            sha256_hex = compute_sha256(f.path)
            f.sha256 = sha256_hex
        except Exception as e:
            LOGGER.error("Hashing failed for %s: %s", f.path, e)
            continue

        action = "quarantine" if not args.permanent else "delete"
        apply_action = args.yes

        if not args.yes:
            now = time.time(); age_d = int((now - f.mtime) / 86400.0)
            print(f"\n[{f.site.domain}] {f.rel_path}\n  size={f.size/1024/1024:.1f} MB  age={age_d}d  plugin={f.plugin or '-'}  risk={f.risk}\n  path={f.path}")
            if args.permanent:
                if confirm("Permanently DELETE this file? (else it will be quarantined)"):
                    action = "delete"
                    if not double_confirm_delete(f.path, sha256_hex, force_token=args.force_token):
                        print("  Token mismatch or cancelled. Skipping.")
                        continue
                    apply_action = True
                else:
                    apply_action = confirm("Quarantine this file instead?")
                    action = "quarantine" if apply_action else "skip"
            else:
                apply_action = confirm("Quarantine this file?")
                action = "quarantine" if apply_action else "skip"

        if not apply_action:
            LOGGER.info("Skipped: %s", f.path)
            continue

        try:
            if action == "quarantine":
                # If cross-device, ensure destination has room for this file
                if device_id(f.path) != device_id(batch_root) and not has_free_space(batch_root, f.size * 2):
                    LOGGER.error("Insufficient space in quarantine for %s", f.path)
                    errors += 1
                    continue
                rel = Path(f.site.domain.replace('/', '_')) / f.rel_path
                qdst = batch_root / rel
                atomic_move(f.path, qdst)
                acted += 1
                rec = {
                    "site": f.site.domain,
                    "original_path": str(f.path),
                    "quarantined_path": str(qdst),
                    "sha256": f.sha256,
                    "size": f.size,
                    "mode": oct(f.mode),
                    "mtime": datetime.utcfromtimestamp(f.mtime).isoformat() + "Z",
                    "ctime": datetime.utcfromtimestamp(f.ctime).isoformat() + "Z",
                    "plugin": f.plugin,
                    "kind": f.kind,
                    "risk": f.risk,
                    "action": "quarantine",
                    "ts": datetime.utcnow().isoformat() + "Z",
                    "actor": getpass.getuser(),
                }
                manifest_records.append(rec)
                LOGGER.info("Quarantined: %s -> %s", f.path, qdst)
            elif action == "delete":
                if args.permanent and args.yes:
                    if not double_confirm_delete(f.path, sha256_hex, force_token=args.force_token):
                        LOGGER.warning("Delete token not confirmed for %s; skipping.", f.path)
                        continue
                os.remove(f.path)
                acted += 1
                LOGGER.warning("Permanently deleted: %s", f.path)
            else:
                LOGGER.info("Skipped: %s", f.path)
        except Exception as e:
            LOGGER.error("Failed to act on %s: %s", f.path, e)
            errors += 1

    # Manifest
    if manifest_records:
        manifest_path = batch_root / "manifest.json"
        try:
            write_manifest(manifest_path, manifest_records)
            LOGGER.info("Wrote quarantine manifest: %s", manifest_path)
            print(f"\nQuarantine manifest: {manifest_path}")
        except Exception as e:
            LOGGER.error("Failed writing manifest: %s", e)
            errors += 1

    # Actual post-op space (after actions)
    actual_pre, actual_post = estimate_space(filtered[:0], quarantine_root=quarantine_root, permanent=args.permanent)  # pre map for devices
    # Recompute current free space for devices we printed earlier
    print("\n=== SPACE AFTER ACTIONS (actual) ===")
    seen_labels = set()
    for label in pre_free.keys() | est_post_free.keys():
        base = quarantine_root if label.startswith('DEST:') else Path('/')
        # Heuristic: if DEST, measure at quarantine_root; else measure at site.docroot of first finding
        if label.startswith('DEST:'):
            free_now = disk_free(quarantine_root)
        else:
            # try using the first finding's path device matching this label
            free_now = None
            for f in filtered:
                if f"SRC:{f.path.anchor or f.site.docroot}" == label:
                    free_now = disk_free(f.path)
                    break
            if free_now is None:
                free_now = disk_free(Path('/'))
        print(f"  {label:35}  {free_now/1024/1024/1024:.2f} GiB free")

    print(f"\nActions complete: acted={acted}, errors={errors}, total_matches={len(filtered)}")
    if errors:
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
