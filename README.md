# HS NC News and Media Monitor

Automated scraper that monitors news and public social media for mentions of the **Holly Springs NC Police Department**. Filters out results from other states (MS, TX, GA, etc.) using keyword and pattern matching.

## What It Monitors

| Source | Method |
|---|---|
| WRAL, WTVD ABC11, CBS17 | RSS feeds |
| News & Observer | RSS feed |
| Holly Springs Sun | RSS feed |
| Google News | RSS search |
| Reddit (r/raleigh, r/NorthCarolina) | Public JSON API |
| Holly Springs PD Facebook | Public page scraping (mbasic) |
| Holly Springs PD Twitter/X | Nitter mirror (no API key needed) |

## Quick Start (Local)

```bash
# 1. Clone or download this folder
# 2. Install dependencies
pip install -r requirements.txt

# 3. Run it
python scraper.py
```

Results are saved to `data/latest_report.html` — open it in your browser.

## Email Notifications (Optional)

Set these environment variables before running:

```bash
export SMTP_HOST=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=you@gmail.com
export SMTP_PASS=your_app_password   # Gmail App Password (not your main password)
export NOTIFY_EMAIL=you@gmail.com
```

**Gmail App Password**: Go to Google Account → Security → 2-Step Verification → App Passwords → generate one for "Mail".

## Automated Scheduling via GitHub Actions (Free)

This runs every 6 hours for free on GitHub:

1. Create a **free** GitHub account at github.com
2. Create a new repository (can be private)
3. Upload all files in this folder to the repo
4. Add your email secrets: **Settings → Secrets → Actions → New repository secret**
   - `SMTP_HOST` → `smtp.gmail.com`
   - `SMTP_PORT` → `587`
   - `SMTP_USER` → your Gmail address
   - `SMTP_PASS` → your Gmail App Password
   - `NOTIFY_EMAIL` → where to send alerts
5. The workflow runs automatically every 6 hours. You can also trigger it manually from the **Actions** tab.

Each run uploads an HTML report under **Actions → [run] → Artifacts**.

## Run Locally on a Schedule (Alternative)

### macOS / Linux (cron)
```bash
# Run every 6 hours
crontab -e
# Add this line:
0 */6 * * * cd /path/to/holly-springs-monitor && python scraper.py
```

### Windows (Task Scheduler)
Create a task that runs `python scraper.py` in the project folder every 6 hours.

## How NC Filtering Works

The scraper uses two layers:
1. **Exclude patterns** — rejects text matching "holly springs, ms / tx / ga / ky / sc / ca"
2. **NC signals** — only keeps results containing "nc", "north carolina", "wake county", "27540", etc.

## Customization

- **`KEYWORDS`** in `scraper.py` — add/remove search terms
- **`RSS_FEEDS`** — add more local news sources
- **`FB_PAGES`** — add more Facebook pages to monitor
- **`TWITTER_ACCOUNTS`** — add more Twitter/X handles
- **Cron schedule** in `.github/workflows/monitor.yml` — change frequency

## Notes

- Facebook public page scraping uses `mbasic.facebook.com` (lightweight mobile version, no login required). If Facebook blocks it, results from that source may be empty.
- Twitter is accessed via Nitter mirrors (no API key needed). Nitter instances can go offline; the scraper tries multiple.
- All results are deduplicated — you'll never see the same item twice.
- Seen items are stored in `data/seen_hashes.json`.
