# Security Advisor Telegram Bot

A Telegram bot that sends a daily digest of newly discovered open-source vulnerabilities from OSV.dev. Users select broad technology groups; the bot maps those groups to OSV package ecosystems. Digests include only advisories with a CVSS v3 or v4 base score of **9.0 or higher**. Advisories without a usable CVSS v3/v4 vector are omitted. Daily digests default to **09:00 UTC**; each user can choose another UTC time.

## Requirements

- Linux server with `systemd` and outbound HTTPS access
- Python **3.15.2** (latest stable release as of 2026-11-11); install the latest available 3.15.x security release alongside the operating system's Python. Do not replace `/usr/bin/python3`.
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

Check the installed interpreter:

```bash
python3.15 --version
```

If your distribution does not offer Python 3.15 yet, install it side-by-side using a supported package source, `pyenv`, or the official source release. The bot uses `python-telegram-bot` 22.6, which documents support for Python 3.10 and later.

## Remote server setup (systemd)

The example unit is [deploy/security-advisor.service](deploy/security-advisor.service). It runs the bot as a dedicated unprivileged account, uses a virtual environment, stores persistent data under `/var/lib/security-advisor`, and writes logs to the system journal. It uses Telegram long polling, so no inbound port or reverse proxy is needed.

### 1. Create the service account and install the project

Create the account and project directory:

```bash
sudo useradd --system --home-dir /var/lib/security-advisor \
  --create-home --shell /usr/sbin/nologin security-advisor
sudo install -d -o root -g root -m 0755 /opt/security-advisor
```

Copy or clone this project into `/opt/security-advisor`, including `requirements.txt` and the `security_advisor/` package. Keep the application files owned by root so the service account can read and execute them but cannot change its code.

### 2. Create the virtual environment and install dependencies

```bash
cd /opt/security-advisor
sudo python3.15 -m venv .venv
sudo .venv/bin/python -m pip install --upgrade pip
sudo .venv/bin/python -m pip install -r requirements.txt
```

The virtual environment is inside the project directory and uses Python 3.15.x. Repeat the `pip install -r` command after changing dependencies.

### 3. Configure the bot token and database path

Create a root-readable environment file:

```bash
sudoedit /etc/security-advisor.env
```

Set these values:

```dotenv
TELEGRAM_BOT_TOKEN=replace-with-the-token-from-BotFather
DATABASE_PATH=/var/lib/security-advisor/security_advisor.sqlite3
OSV_MODIFIED_INDEX=https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv
```

Restrict access to the token:

```bash
sudo chown root:root /etc/security-advisor.env
sudo chmod 0600 /etc/security-advisor.env
```

### 4. Install and start the service

```bash
cd /opt/security-advisor
sudo install -m 0644 deploy/security-advisor.service \
  /etc/systemd/system/security-advisor.service
sudo systemctl daemon-reload
sudo systemctl enable --now security-advisor
```

Check service state and logs:

```bash
sudo systemctl status security-advisor
sudo journalctl -u security-advisor -f
```

The journal reports each OSV sync with the number of unique records in the modified index, records fetched and saved, fetch failures, and records no longer found. At each user's scheduled time it logs how many advisory records were sent to that chat (including zero). Review today's entries with:

```bash
sudo journalctl -u security-advisor --since today
```

To restart after deploying an application update:

```bash
cd /opt/security-advisor
sudo .venv/bin/python -m pip install -r requirements.txt
sudo systemctl restart security-advisor
```

The bot needs outbound HTTPS to Telegram, OSV.dev, and the OSV public storage endpoint. No inbound firewall rule is required. Keep `/var/lib/security-advisor` backed up; it contains user selections, ingestion progress, and delivery history.

## Local development

```bash
python3.15 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
# Set TELEGRAM_BOT_TOKEN in .env, then:
set -a; . ./.env; set +a
python -m security_advisor
```

The process uses Telegram long polling and must remain running. On its first run, it imports OSV records modified during the previous 24 hours instead of importing the full historical database.

## Telegram commands

- `/start` — register or resume and open the technology selector
- `/settings` — edit selected technology groups
- `/time` — view the current notification time and instructions; use `/time 14:15` to set a daily UTC time in 24-hour `HH:MM` format
- `/digest` — preview matching items discovered in the last seven days
- `/stop` — pause scheduled digests
- `/help` — show help

## Initial technology groups

JavaScript / TypeScript (npm), Python (PyPI), Java (Maven), PHP (Packagist), Go, Rust (crates.io), Ruby (RubyGems), and .NET (NuGet). The selector groups OSV ecosystems under familiar labels.

## Data handling and scope

The bot periodically reads OSV.dev's public `modified_id.csv` index and fetches changed records through the OSV API. Advisories are stored by OSV ID; CVE and GHSA aliases are used to combine matching records and avoid repeat notifications. Digest entries include affected packages and version guidance, with links to OSV records.

This first version covers OSV's open-source package data. It does not yet cover general vendor products or hosted services. Additional sources can be added later and deduplicated using shared advisory identifiers.
