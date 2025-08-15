# 🛡️ Plesk WordPress Backup Sweeper — v1.3 (Telegram + Discord)

Safely **scan, quarantine, and remove risky WordPress backup archives** on **Plesk‑managed Linux servers** — across **web‑exposed** and **non‑web** paths. Built for **production**: dry‑run first, strict confirmations, space usage estimates, structured reports, and optional **Telegram**/**Discord** notifications with a **unique server ID** and environment context in every message.

> **Default is DRY‑RUN.** Nothing is modified unless you opt in.

---

## ✨ Highlights
- **Plesk‑aware discovery** of domains & subdomains (CLI → PSA DB → FS fallback)
- **Backup plugin formats**: UpdraftPlus, All‑in‑One WP Migration (`.wpress`), Duplicator (`.zip`, `.daf`), WPvivid, BackWPup, BackupBuddy (`.backupbuddy`, `.solidbackup`), WP Staging, XCloner, Total Upkeep, WP‑DBManager, Backup Migration, WP Reset autosnapshots
- **Generic risky files**: `.zip`, `.tar(.gz|.bz2|.xz)`, `.tgz`, `.7z`, `.zst`, `.sql(.gz)`, `.dump`, `.bak`, `.backup`, `.jpa`, `.jps`, plus patterns like `*_backup.*` / `backup_*.*`
- **Non‑web scanning** (opt‑in): `/var/backups`, `/var/www/vhosts/*/private`, `/var/www/vhosts/*/files`, `/var/www/vhosts/system/*/backup`, **and** `/var/lib/psa/dumps` (explicit flag)
- **Custom roots**: `--extra-nonweb-path /path` (repeatable)
- **Quarantine** with manifest & restore; **Permanent delete** guarded by per‑file token or `--force-token`
- **Space estimates** before actions and actual free space after actions
- **Structured logs** (JSONL) and **JSON/CSV reports**
- **Notifications** via Telegram Bot API and Discord Webhook; control when to notify and include log tails
- **Unique server ID** (`srv-<hash>` or `--server-id`) + Hostname/OS/Kernel/Uptime/Plesk in each notification

---

## 📦 Requirements
- Python **3.10.12+**
- Linux with **Plesk**
- Internet egress only if Telegram/Discord notifications are enabled
- **No third‑party Python packages** (stdlib only)

---

## ⚙️ Install
```bash
sudo curl -L -o /usr/local/bin/plesk_wp_backup_sweeper.py \
  https://raw.githubusercontent.com/securiace-dev/plesk-wp-backup-sweeper/telegram-discord/plesk_wp_backup_sweeper_v1_3.py
sudo chmod +x /usr/local/bin/plesk_wp_backup_sweeper.py
sudo mkdir -p /var/log && sudo touch /var/log/plesk-wp-backup-sweeper.log
```

> Tip: keep the script path in `/usr/local/bin` for easy scheduling.

---

## 🔧 Configuration (.env & CLI)
Create a `.env` (optional) and `source` it before running:

```dotenv
# Identity & notifications
SERVER_ID=prod-mumbai-01
NOTIFY_ON=changes          # none|always|changes|errors
NOTIFY_INCLUDE_LOGS=50     # tail last N log lines in notifications

# Telegram (optional)
TELEGRAM_BOT_TOKEN=123:abc
TELEGRAM_CHAT_ID=-1001234567890

# Discord (optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
```
Load env:
```bash
set -a; source .env; set +a
```

> All values can also be passed via flags: `--server-id`, `--notify-on`, `--telegram-bot-token`, `--telegram-chat-id`, `--discord-webhook-url`, etc.

---

## 📣 Telegram — Full Setup
1. **Create a bot** with [@BotFather](https://t.me/botfather) → `/newbot` → copy the `TELEGRAM_BOT_TOKEN`.
2. **Find your chat ID**:
   - Add the bot to your group/private chat.
   - Use [@userinfobot](https://t.me/userinfobot) (or similar) to obtain your numeric Chat ID (groups usually start with `-100`).
3. **Export variables** (or put them in `.env`):
   ```bash
   export TELEGRAM_BOT_TOKEN="123456:ABC..."
   export TELEGRAM_CHAT_ID="-1001234567890"
   ```
4. **Run with notifications**:
   ```bash
   python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web \
     --notify-on changes --notify-include-logs 50 --verbose
   ```

**Notes**
- Plain HTTPS to Telegram Bot API (no extra deps).
- Messages use safe HTML formatting and are auto‑chunked.
- Prefer a private group; restrict membership.

---

## 🎮 Discord — Full Setup (Complete)

### A) Create a Webhook
1. Server Settings → **Integrations → Webhooks → New Webhook**.
2. Select the target channel (e.g., `#ops-alerts`) and **copy** the Webhook URL.
3. Export the URL (or put it in `.env`):
   ```bash
   export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
   ```

### B) Post to a Specific Thread (Forum/Threaded Channels)
Append `?thread_id=<ID>` to the webhook URL:
```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy?thread_id=123456789012345678"
```
How to get a thread ID:
- Enable **Developer Mode** (User Settings → Advanced)
- Right‑click the thread → **Copy ID**

> You may create multiple webhooks for different servers/environments.

### C) Security & Permissions
- Use a **private ops channel** with restricted members.
- Rotate webhooks periodically; update `.env`.
- Keep secrets out of version control (`.gitignore` your `.env`).

### D) Test the Webhook
```bash
curl -H 'Content-Type: application/json' \
     -d '{"content":"Test from Plesk WP Backup Sweeper"}' \
     "$DISCORD_WEBHOOK_URL"
```

### E) Run with Discord Notifications
```bash
python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web \
  --notify-on changes --notify-include-logs 50 --verbose
```

### F) Rate Limits & Message Size
- Auto‑chunks messages (~1,800 chars) to avoid platform limits.
- Discord rate limit is **per webhook**; avoid very frequent schedules.

### G) Troubleshooting
- **HTTP 404**: Webhook deleted or URL wrong → recreate.
- **HTTP 401**: Expired/invalid URL → recreate.
- **HTTP 429**: Rate limited → reduce frequency or consolidate reports.
- Script logs show: `Discord send failed: <error>`.

---

## 🧪 Quick Start Recipes

Audit (safe):
```bash
python3 /usr/local/bin/plesk_wp_backup_sweeper.py --dry-run --verbose \
  --report-json /var/log/wp-backups.json --report-csv /var/log/wp-backups.csv
```

Quarantine old/large:
```bash
sudo python3 /usr/local/bin/plesk_wp_backup_sweeper.py \
  --yes --age-days 14 --min-size 10M --include-non-web
```

Permanent delete (extreme caution):
```bash
sudo python3 /usr/local/bin/plesk_wp_backup_sweeper.py \
  --permanent --age-days 45 --min-size 100M --include-non-web
```

Restore from quarantine:
```bash
sudo python3 /usr/local/bin/plesk_wp_backup_sweeper.py \
  --restore /var/backup-quarantine/<timestamp>/manifest.json
```

---

## 🧭 CLI Usage — All Scenarios & Combinations
This section enumerates the **most common permutations** so you can copy‑paste for any scenario.

### 1) Scope & Discovery
- **Web roots only (default)**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run
  ```
- **Include non‑web locations**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web
  ```
- **Include Plesk dumps** (quarantine‑first recommended)
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --include-plesk-dumps
  ```
- **Extra explicit web docroots**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run \
    --extra-path /var/www/vhosts/example.com/httpdocs \
    --extra-path /srv/custom/site
  ```
- **Custom non‑web roots**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run \
    --extra-nonweb-path /mnt/backups --extra-nonweb-path /data/archives
  ```

### 2) Filters & Limits
- **Minimum size** (ignore tiny files)
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --min-size 20M
  ```
- **Age filter** (act only on older files)
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --yes --age-days 30
  ```
- **Plugin directories only** (inside web roots)
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --plugin-only
  ```
- **Exclude by glob/regex/site**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run \
    --exclude-glob "*/uploads/safe/*" \
    --exclude-regex "/archive/20(1[0-9]|20)" \
    --exclude-site example.com
  ```
- **Depth control**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --max-depth 8
  ```

### 3) Actions & Safety Modes
- **Audit only** (default)
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run
  ```
- **Quarantine with auto‑approve**
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --yes --include-non-web
  ```
- **Permanent delete with interactive token**
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --permanent --age-days 60 --min-size 100M
  ```
- **Permanent delete in automation (non‑interactive)**
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --permanent --age-days 90 --min-size 200M \
    --force-token DELETE:deadbeef
  ```
- **Custom quarantine location** (separate mount)
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --yes --quarantine-root /mnt/quarantine
  ```

### 4) Output, Logs & Reports
- **Quiet / Verbose / Debug**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --quiet
  python3 plesk_wp_backup_sweeper.py --dry-run --verbose
  python3 plesk_wp_backup_sweeper.py --dry-run --debug
  ```
- **Structured reports**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run \
    --report-json /var/log/wp-backups.json --report-csv /var/log/wp-backups.csv
  ```
- **Custom log file**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --log-file /var/log/backup-sweeper.jsonl
  ```

### 5) Notifications & Identity
- **Telegram only**
  ```bash
  export TELEGRAM_BOT_TOKEN=123:abc TELEGRAM_CHAT_ID=-1001234567890
  python3 plesk_wp_backup_sweeper.py --dry-run --notify-on changes --notify-include-logs 50
  ```
- **Discord only**
  ```bash
  export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
  python3 plesk_wp_backup_sweeper.py --dry-run --notify-on errors
  ```
- **Both Telegram & Discord**
  ```bash
  export TELEGRAM_BOT_TOKEN=123:abc TELEGRAM_CHAT_ID=-1001234567890
  export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
  python3 plesk_wp_backup_sweeper.py --dry-run --notify-on always --notify-include-logs 100
  ```
- **Override server ID** (multi‑server clarity)
  ```bash
  SERVER_ID=prod-mumbai-01 python3 plesk_wp_backup_sweeper.py --dry-run --notify-on changes
  ```

### 6) Performance & Timeouts
- **Concurrency**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --concurrency 16
  ```
- **Soft timeout**
  ```bash
  python3 plesk_wp_backup_sweeper.py --dry-run --timeout 900
  ```

### 7) End‑to‑End Examples (Compound Scenarios)
- **Thorough audit + non‑web + dumps + reports + Discord**
  ```bash
  export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxx/yyy"
  python3 plesk_wp_backup_sweeper.py --dry-run --include-non-web --include-plesk-dumps \
    --report-json /var/log/wp-audit.json --report-csv /var/log/wp-audit.csv \
    --notify-on changes --notify-include-logs 50 --verbose
  ```
- **Aggressive cleanup on staging (quarantine first)**
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --yes --include-non-web --age-days 7 --min-size 5M \
    --exclude-site production.example --notify-on changes
  ```
- **Production delete window (token + specific mounts)**
  ```bash
  sudo python3 plesk_wp_backup_sweeper.py --permanent --age-days 60 --min-size 200M \
    --extra-nonweb-path /backups --quarantine-root /mnt/quarantine \
    --force-token DELETE:deadbeef --notify-on errors --quiet
  ```

---

## ⏱️ Scheduling

### systemd (recommended)
**/etc/systemd/system/plesk-wp-sweeper.service**
```ini
[Unit]
Description=Plesk WP Backup Sweeper (one-shot)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
User=root
Environment=SERVER_ID=prod-mumbai-01
Environment=TELEGRAM_BOT_TOKEN=xxx
Environment=TELEGRAM_CHAT_ID=-1001234567890
Environment=DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
Environment=NOTIFY_ON=changes
Environment=NOTIFY_INCLUDE_LOGS=50
ExecStart=/usr/bin/python3 /usr/local/bin/plesk_wp_backup_sweeper.py \
  --include-non-web --include-plesk-dumps --dry-run \
  --report-json /var/log/plesk-wp-sweeper.json \
  --report-csv /var/log/plesk-wp-sweeper.csv --verbose
```

**/etc/systemd/system/plesk-wp-sweeper.timer**
```ini
[Unit]
Description=Run Plesk WP Sweeper daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=10m

[Install]
WantedBy=timers.target
```
Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now plesk-wp-sweeper.timer
```

### Cron (alternative)
```bash
# daily at 03:20
20 3 * * * root SERVER_ID=prod-mumbai-01 TELEGRAM_BOT_TOKEN=xxx TELEGRAM_CHAT_ID=-1001234567890 DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy \
/usr/bin/python3 /usr/local/bin/plesk_wp_backup_sweeper.py --include-non-web --dry-run --verbose \
>> /var/log/plesk-wp-sweeper.cron.log 2>&1
```

---

## 📊 Space Usage Estimation
- **Pre‑operation**: prints free space per relevant filesystem.
- **Estimated post‑operation**: assumes all listed files are acted upon.
- **Post‑actions**: prints **actual** free space to verify reclamation.

---

## 🧯 Restore Workflow
1. Locate the quarantine batch directory (e.g., `/var/backup-quarantine/<ts>/manifest.json`).
2. Run:
   ```bash
   sudo python3 plesk_wp_backup_sweeper.py --restore /var/backup-quarantine/<ts>/manifest.json
   ```
3. SHA‑256 (if present) is verified; files move back to original paths.

---

## 🔐 Safety & Best Practices
- Always start with **`--dry-run`** on new servers.
- Prefer **quarantine** before **permanent delete**.
- Keep secrets safe: `.env` in `.gitignore`, use private channels/webhooks.
- Use `--exclude-*` to protect known safe dumps/backups.

---

## 🧰 Troubleshooting
- **No results**: ensure Plesk discovery works; try `--allow-psa-db`, `--extra-path`.
- **Permissions**: destructive actions require `root`.
- **Telegram 400/401**: invalid token or bot not added to chat.
- **Discord 401/404/429**: wrong/deleted webhook or rate limited.
- **Plesk CLI missing**: falls back to PSA DB/FS; repair Plesk if discovery fails.

---

## 📜 License
MIT — see `LICENSE`.
