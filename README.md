# Plesk WordPress Backup Sweeper

Safely scan a **Plesk-managed server** for **web-exposed** and **non-web-exposed** WordPress backup archives, with options to **quarantine** or **permanently delete** them. Includes **space usage estimation** before and after operations, customizable scanning paths, and production-grade safeguards.

## Features
- **Comprehensive Plugin Coverage** — Detects backup files from popular and niche WordPress backup/migration plugins:
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
- **Generic Risky File Detection** — Finds `.zip`, `.tar`, `.tgz`, `.bz2`, `.xz`, `.wpress`, `.daf`, `.backupbuddy`, `.solidbackup`, `.sql`, `.bak`, `.dump`, and more.
- **Non-Web Path Scanning** — Scan common and custom backup storage locations outside web roots.
- **Custom Paths** — Add extra directories to scan via `--extra-nonweb-path`.
- **Dry-Run by Default** — No changes without explicit approval.
- **Quarantine Mode** — Moves files to a secure, restorable location with a manifest.
- **Permanent Delete Mode** — Requires per-file DELETE token confirmation.
- **Space Usage Estimation** — Displays estimated and actual free space before/after.
- **Structured Reporting** — JSON and CSV output for compliance/audit.

## Requirements
- Python **3.10.12+**
- Linux with Plesk installed
- Standard library only (no extra dependencies)

## Installation
```bash
curl -O https://raw.githubusercontent.com/securiace-dev/plesk-wp-backup-sweeper/main/plesk_wp_backup_sweeper.py
chmod +x plesk_wp_backup_sweeper.py
```

## Usage Examples (All Combinations)

### 1. Safe Audit (Web Roots Only)
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --verbose
```

### 2. Safe Audit (Web + Non-Web)
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web
```

### 3. Safe Audit (Web + Non-Web + Plesk Dumps)
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web --include-plesk-dumps
```

### 4. Custom Paths Only
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --extra-nonweb-path /mnt/legacy --extra-nonweb-path /data/archives
```

### 5. Quarantine (Web Roots Only)
```bash
sudo python3 plesk_wp_backup_sweeper.py --yes --age-days 7 --min-size 2M
```

### 6. Quarantine (Web + Non-Web)
```bash
sudo python3 plesk_wp_backup_sweeper.py --yes --age-days 14 --min-size 5M --include-non-web
```

### 7. Quarantine (Custom Paths)
```bash
sudo python3 plesk_wp_backup_sweeper.py --yes --extra-nonweb-path /srv/backups --age-days 30 --min-size 1M
```

### 8. Permanent Delete (Web Roots Only)
```bash
sudo python3 plesk_wp_backup_sweeper.py --permanent --age-days 30 --min-size 10M
```

### 9. Permanent Delete (Web + Non-Web)
```bash
sudo python3 plesk_wp_backup_sweeper.py --permanent --age-days 60 --min-size 50M --include-non-web
```

### 10. Permanent Delete (Custom Paths)
```bash
sudo python3 plesk_wp_backup_sweeper.py --permanent --extra-nonweb-path /tmp/old --age-days 90 --min-size 100M
```

### 11. Combined Report & Quarantine
```bash
sudo python3 plesk_wp_backup_sweeper.py --yes --report-json /root/reports/backups.json --report-csv /root/reports/backups.csv
```

### 12. Restore From Quarantine
```bash
sudo python3 plesk_wp_backup_sweeper.py --restore /var/backup-quarantine/<timestamp>/manifest.json
```

### 13. Space Usage Only (No Action)
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --verbose | grep "SPACE"
```

### 14. Quarantine + Include Plesk Dumps
```bash
sudo python3 plesk_wp_backup_sweeper.py --yes --include-plesk-dumps --age-days 15 --min-size 20M
```

## Safety Notes
- Always start with a **dry-run**.
- Quarantine first; only delete permanently after verification.
- Permanent delete requires DELETE token entry per file.
- Space usage estimates help prevent storage overflow risks.

## License
MIT License — see [LICENSE](LICENSE)
