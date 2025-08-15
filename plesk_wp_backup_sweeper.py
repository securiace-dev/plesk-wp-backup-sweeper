#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plesk_wp_backup_sweeper.py (v1.3.0)

Safely scan a Plesk-managed server for web-exposed **and non-web** WordPress backup
archives and (optionally) quarantine or permanently delete them — with strict
safety-first defaults. Now includes optional **Telegram/Discord** notifications,
**unique server identifier + environment info** in reports, and **enhanced logs**.

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
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import textwrap
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

__version__ = "1.3.0"

LOGGER = logging.getLogger("plesk_wp_backup_sweeper")
SERVER_ID = ""  # set at runtime

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


# ------------------------------ Server identity -----------------------------

def _read_text_first(*paths: str) -> Optional[str]:
    for p in paths:
        try:
            s = Path(p).read_text(encoding="utf-8", errors="ignore").strip()
            if s:
                return s
        except Exception:
            continue
    return None


def compute_server_id(override: Optional[str] = None) -> str:
    if override:
        return override
    # Try machine-id, then product_uuid, then hash of hostname + kernel + ips
    material = []
    mid = _read_text_first("/etc/machine-id", "/var/lib/dbus/machine-id")
    if mid:
        material.append(mid)
    puid = _read_text_first("/sys/class/dmi/id/product_uuid")
    if puid:
        material.append(puid)
    try:
        material.append(socket.gethostname())
    except Exception:
        pass
    try:
        material.append(platform.uname().release)
    except Exception:
        pass
    try:
        # Collect IPs
        ips = []
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                for info in socket.getaddrinfo(socket.gethostname(), None, fam):
                    ip = info[4][0]
                    ips.append(ip)
            except Exception:
                continue
        material.extend(sorted(set(ips)))
    except Exception:
        pass
    raw = "|".join(material) if material else str(time.time())
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"srv-{h}"


def collect_env_info() -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        pass
    try:
        info["kernel"] = platform.uname().release
    except Exception:
        pass
    # OS release
    try:
        osr = {}
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                osr[k.strip()] = v.strip().strip('"')
        info["os"] = f"{osr.get('NAME','Linux')} {osr.get('VERSION','')}".strip()
    except Exception:
        info["os"] = "Linux"
    # Uptime
    try:
        up_s = float(Path("/proc/uptime").read_text().split()[0])
        days = int(up_s // 86400)
        hours = int((up_s % 86400) // 3600)
        mins = int((up_s % 3600) // 60)
        info["uptime"] = f"{days}d {hours}h {mins}m"
    except Exception:
        pass
    # Plesk version
    for cmd in (["plesk", "version"], ["plesk", "bin", "server_pref", "--show", "-std"]):
        rc, out, _ = run_cmd(cmd, timeout=10)
        if rc == 0 and out:
            m = re.search(r"(Plesk|Product version)\s*:?\s*([\w\.-]+)", out)
            if m:
                info["plesk"] = m.group(2)
                break
    info["python"] = sys.version.split()[0]
    info["script_version"] = __version__
    info["server_id"] = SERVER_ID
    return info


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
        base = Path('/') if pat.startswith('/') else Path('.')
        for p in base.glob(pat.lstrip('/')):
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
    dev_labels: Dict[int, str] = {}
    pre_free: Dict[int, int] = {}

    q_dev = device_id(quarantine_root)
    dev_labels[q_dev] = f"DEST:{quarantine_root}"
    pre_free[q_dev] = disk_free(quarantine_root)

    for f in findings:
        d = device_id(f.path)
        if d not in dev_labels:
            dev_labels[d] = f"SRC:{f.path.anchor or f.site.docroot}"
            pre_free[d] = disk_free(f.path)

    post_free = dict(pre_free)

    for f in findings:
        src_dev = device_id(f.path)
        size = f.size
        if permanent:
            post_free[src_dev] = post_free.get(src_dev, 0) + size
        else:
            if src_dev == q_dev:
                continue
            post_free[src_dev] = post_free.get(src_dev, 0) + size
            post_free[q_dev] = post_free.get(q_dev, 0) - size

    pre_labeled = {dev_labels[d]: free for d, free in pre_free.items()}
    post_labeled = {dev_labels[d]: free for d, free in post_free.items()}
    return pre_labeled, post_labeled


# ------------------------------- Notifications -------------------------------
class Notifier:
    def __init__(self, *, tg_token: Optional[str], tg_chat: Optional[str], dc_webhook: Optional[str], include_logs: int, mode: str):
        self.tg_token = tg_token
        self.tg_chat = tg_chat
        self.dc_webhook = dc_webhook
        self.include_logs = max(0, int(include_logs or 0))
        self.mode = mode  # none|always|changes|errors

    def enabled(self) -> bool:
        return bool(self.tg_token and self.tg_chat) or bool(self.dc_webhook)

    def _send_telegram(self, text: str) -> None:
        if not (self.tg_token and self.tg_chat):
            return
        url = f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
        data = {
            "chat_id": self.tg_chat,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode("utf-8"))
        try:
            with urllib.request.urlopen(req, timeout=10) as _:
                pass
        except Exception as e:
            LOGGER.warning("Telegram send failed: %s", e)

    def _send_discord(self, text: str) -> None:
        if not self.dc_webhook:
            return
        data = json.dumps({"content": text}).encode("utf-8")
        req = urllib.request.Request(self.dc_webhook, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as _:
                pass
        except Exception as e:
            LOGGER.warning("Discord send failed: %s", e)

    def send(self, text: str) -> None:
        # Split to satisfy platform limits
        # Telegram: ~4096 chars; Discord: ~2000 chars
        chunks: List[str] = []
        max_len = 1800  # safe for both
        for i in range(0, len(text), max_len):
            chunks.append(text[i:i+max_len])
        for c in chunks:
            self._send_telegram(c)
            self._send_discord(c)


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

    ident = p.add_argument_group("Identity & Notifications")
    ident.add_argument("--server-id", default=os.environ.get("SERVER_ID"), help="Override/force a specific server identifier")
    ident.add_argument("--notify-on", choices=["none", "always", "changes", "errors"], default=os.environ.get("NOTIFY_ON", "changes"), help="When to send notifications")
    ident.add_argument("--notify-include-logs", type=int, default=int(os.environ.get("NOTIFY_INCLUDE_LOGS", "0")), help="Include last N log lines in notifications (0=none)")
    ident.add_argument("--telegram-bot-token", default=os.environ.get("TELEGRAM_BOT_TOKEN"))
    ident.add_argument("--telegram-chat-id", default=os.environ.get("TELEGRAM_CHAT_ID"))
    ident.add_argument("--discord-webhook-url", default=os.environ.get("DISCORD_WEBHOOK_URL"))

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


# ------------------------------- Logging setup -------------------------------
class JsonLineFileHandler(logging.FileHandler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            log_entry = {"ts": datetime.utcnow().isoformat() + "Z", "level": record.levelname, "msg": record.getMessage(), "server_id": SERVER_ID}
            if isinstance(record.args, dict):
                log_entry.update(record.args)
        except Exception:
            log_entry = {"ts": datetime.utcnow().isoformat() + "Z", "level": record.levelname, "msg": record.getMessage(), "server_id": SERVER_ID}
        self.stream.write(json.dumps(log_entry) + "\n")
        self.flush()


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


# --------------------------------- Exclusions --------------------------------

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


# ---------------------------------- Actions ----------------------------------

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


# ---------------------------------- Restore ----------------------------------

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


# ----------------------------------- Main ------------------------------------

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


def main(argv: Optional[Sequence[str]] = None) -> int:
    global SERVER_ID
    args = build_arg_parser().parse_args(argv)
    SERVER_ID = compute_server_id(args.server_id)
    prepare_logging(args)

    env_info = collect_env_info()
    LOGGER.info("Server identity: %s | Host: %s | OS: %s | Kernel: %s | Plesk: %s", env_info.get("server_id"), env_info.get("hostname"), env_info.get("os"), env_info.get("kernel"), env_info.get("plesk", "?"))

    if args.restore:
        rc = restore_from_manifest(Path(args.restore))
        return rc

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
                res = fut.result()
                all_findings.extend(res)
            except Exception as e:
                LOGGER.error("Scan error: %s", e)

    # Apply user exclusions
    filtered: List[Finding] = []
    for f in all_findings:
        rel = f"{f.site.domain}/{f.rel_path}"
        if excluded_by_patterns(rel, globs=args.exclude_glob, regexes=args.exclude_regex):
            LOGGER.debug("Excluded by pattern: %s", rel)
            continue
        filtered.append(f)

    filtered.sort(key=lambda x: (x.site.domain, -x.risk, -x.size))

    if not filtered:
        LOGGER.info("No risky backup archives found.")

    # Console preview
    if filtered and not args.quiet:
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

    # Space estimates (always computed, even for dry-run)
    quarantine_root = Path(args.quarantine_root)
    ensure_quarantine_root(quarantine_root)
    pre_free, est_post_free = estimate_space(filtered, quarantine_root=quarantine_root, permanent=args.permanent)

    print("\n=== SPACE ESTIMATE (assuming all listed files are acted on) ===")
    if pre_free:
        print("Pre-operation free space:")
        for label, free in pre_free.items():
            print(f"  {label:35}  {free/1024/1024/1024:.2f} GiB free")
    if est_post_free:
        print("Estimated post-operation free space:")
        for label, free in est_post_free.items():
            print(f"  {label:35}  {free/1024/1024/1024:.2f} GiB free")

    # Build notifier
    notifier = Notifier(
        tg_token=args.telegram_bot_token,
        tg_chat=args.telegram_chat_id,
        dc_webhook=args.discord_webhook_url,
        include_logs=args.notify_include_logs,
        mode=args.notify_on,
    )

    def should_notify(actions: int, errors: int, findings_n: int) -> bool:
        if not notifier.enabled():
            return False
        if notifier.mode == "none":
            return False
        if notifier.mode == "always":
            return True
        if notifier.mode == "errors":
            return errors > 0
        # changes
        return (actions > 0) or (errors > 0) or (findings_n > 0 and args.dry_run)

    def render_summary(actions: int, errors: int) -> str:
        env_lines = [
            f"<b>Server:</b> {env_info.get('server_id')} ({env_info.get('hostname')})",
            f"<b>OS:</b> {env_info.get('os')} | <b>Kernel:</b> {env_info.get('kernel')} | <b>Plesk:</b> {env_info.get('plesk','?')}",
        ]
        lines = [
            f"<b>Plesk WP Backup Sweeper {__version__}</b>",
            *env_lines,
            f"<b>Mode:</b> {'DRY-RUN' if args.dry_run else ('DELETE' if args.permanent else 'QUARANTINE')}",
            f"<b>Scan roots:</b> {len(sites)} (web={len(web_sites)}, non-web={len(nonweb_sites)})",
            f"<b>Findings:</b> {len(filtered)}",
            f"<b>Actions taken:</b> {actions}",
            f"<b>Errors:</b> {errors}",
        ]
        if pre_free:
            lines.append("<b>Space (GiB):</b>")
            for label in pre_free:
                lines.append(f"  {label}: before {pre_free[label]/1024/1024/1024:.2f} → est after {est_post_free.get(label, pre_free[label])/1024/1024/1024:.2f}")
        # Include top matches
        if filtered:
            lines.append("<b>Top findings:</b>")
            for f in filtered[:10]:
                age_d = int((time.time() - f.mtime) / 86400.0)
                lines.append(f"  [{f.risk}] {f.site.domain} :: {f.rel_path} ({f.size/1024/1024:.1f} MB, {age_d}d, {f.plugin or '-'})")
        # Optional log tail
        if notifier.include_logs > 0 and args.log_file and Path(args.log_file).exists():
            try:
                tail = Path(args.log_file).read_text(encoding="utf-8", errors="ignore").splitlines()[-notifier.include_logs:]
                lines.append("<b>Log tail:</b>")
                for ln in tail:
                    # Escape HTML minimal
                    ln = ln.replace("<", "&lt;").replace(">", "&gt;")
                    lines.append(ln)
            except Exception:
                pass
        return "\n".join(lines)

    if args.dry_run:
        LOGGER.info("Dry-run complete. No changes made.")
        # Notify if configured
        if should_notify(0, 0, len(filtered)):
            notifier.send(render_summary(actions=0, errors=0))
        return 2

    # Prepare quarantine batch
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    batch_root = Path(args.quarantine_root) / ts
    ensure_quarantine_root(batch_root)

    # Summary & confirmation
    total_bytes = sum(f.size for f in filtered)
    print("\n=== ACTION SUMMARY (Quarantine by default unless --permanent) ===")
    print(f"Files matched: {len(filtered)}  |  Total size: {total_bytes/1024/1024:.1f} MB")
    if filtered and not args.yes:
        if not confirm("Proceed to review files one-by-one for quarantine/deletion?"):
            LOGGER.info("Aborted by user before actions.")
            if should_notify(0, 0, len(filtered)):
                notifier.send(render_summary(actions=0, errors=0))
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
                    "server_id": SERVER_ID,
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

    # Print actual free space now
    print("\n=== SPACE AFTER ACTIONS (actual) ===")
    labels = set(list(pre_free.keys()) + list(est_post_free.keys()))
    for label in labels:
        if label.startswith("DEST:"):
            free_now = disk_free(quarantine_root)
        else:
            free_now = None
            for f in filtered:
                src_label = f"SRC:{f.path.anchor or f.site.docroot}"
                if src_label == label:
                    free_now = disk_free(f.path)
                    break
            if free_now is None:
                free_now = disk_free(Path('/'))
        print(f"  {label:35}  {free_now/1024/1024/1024:.2f} GiB free")

    # Log summary
    LOGGER.info("Summary: findings=%d acted=%d errors=%d mode=%s", len(filtered), acted, errors, "delete" if args.permanent else "quarantine")

    # Notify if configured
    if should_notify(acted, errors, len(filtered)):
        notifier.send(render_summary(actions=acted, errors=errors))

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
