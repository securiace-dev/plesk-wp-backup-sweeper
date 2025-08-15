# Plesk WordPress Backup Sweeper

Safely scan a **Plesk-managed server** for **web-exposed** and **non-web-exposed** WordPress backup archives and optionally **quarantine** or **permanently delete** them. Includes **space usage estimation** before and after operations.

## Features
- **Comprehensive plugin coverage** — Detects backup files from popular WordPress backup/migration plugins:
  - UpdraftPlus
  - All-in-One WP Migration (`.wpress`)
  - Duplicator (`.zip`, `.daf`)
  - WPvivid
  - BackWPup
  - BackupBuddy (`.backupbuddy`, `.solidbackup`)
  - WP Staging
  - XCloner
  - Total Upkeep
  - WP-DBManager
  - Backup Migration
  - All In One Security
  - Shipper
- **Generic risky file detection** — Finds `.zip`, `.tar`, `.wpress`, `.daf`, `.backupbuddy`, `.solidbackup`, `.sql`, `.bak`, and more.
- **Non-web path scanning** — Can scan common backup storage outside web roots:
  - `/var/backups`
  - `/var/lib/psa/dumps`
  - `/root`
  - `/home`
- **Dry-run by default** — Never deletes anything without explicit confirmation.
- **Quarantine mode** — Moves files to a secure location with a manifest for restoration.
- **Permanent delete mode** — Requires per-file confirmation tokens.
- **Space usage estimation** — Shows disk usage before and after operation to verify space reclaimed.
- **Structured reporting** — JSON and CSV outputs.

## Requirements
- Python **3.10.12** or newer
- Linux with Plesk installed
- No external dependencies (standard library only)

## Installation
```bash
curl -O https://raw.githubusercontent.com/<your-repo>/plesk-wp-backup-sweeper/main/plesk_wp_backup_sweeper.py
chmod +x plesk_wp_backup_sweeper.py
```

## Usage Examples
**Dry-run (safe, no deletions):**
```bash
python3 plesk_wp_backup_sweeper.py --dry-run \
  --report-json /root/reports/backups.json \
  --report-csv /root/reports/backups.csv \
  --verbose
```

**Scan non-web paths as well:**
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web
```

**Quarantine old/large files:**
```bash
sudo python3 plesk_wp_backup_sweeper.py --yes --age-days 14 --min-size 5M --include-non-web
```

**Permanently delete (dangerous):**
```bash
sudo python3 plesk_wp_backup_sweeper.py --permanent --age-days 30 --min-size 20M --include-non-web
```

**Space Usage Report:**
The script prints a **SPACE ESTIMATE** before operations and a **SPACE AFTER ACTIONS** report once complete.

## Safety Notes
- Default mode is **dry-run**.
- Permanent delete mode requires **DELETE token** per file.
- Quarantined files can be restored from the manifest.
- Designed to be safe for production servers.

## License
MIT License — see [LICENSE](LICENSE)
