"""
Holly Springs NC Police Monitor
Scrapes news and public social media for Holly Springs NC police mentions.
"""

import json
import hashlib
import logging
import os
import re
import smtplib
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import feedparser
import requests
from bs4 import BeautifulSoup

# ── Configuration ─────────────────────────────────────────────────────────────

KEYWORDS = [
    "holly springs police",
    "holly springs pd",
    "holly springs nc police",
    "holly springs north carolina police",
    "hspd nc",
]

# Negative filters: skip results that look like other states
EXCLUDE_PATTERNS = [
    r"holly springs,?\s*(ms|mississippi)",
    r"holly springs,?\s*(tx|texas)",
    r"holly springs,?\s*(ga|georgia)",
    r"holly springs,?\s*(ky|kentucky)",
    r"holly springs,?\s*(sc|south carolina)",
    r"holly springs,?\s*(ca|california)",
]

# Must contain at least one NC signal to be kept
NC_SIGNALS = [
    "nc", "north carolina", "wake county", "raleigh", "holly springs, nc",
    "hollyspringsnc", "holly springs nc", "27540",
]

# ── File Paths ────────────────────────────────────────────────────────────────

BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
LOG_DIR    = BASE_DIR / "logs"
SEEN_FILE  = DATA_DIR / "seen_hashes.json"
REPORT_FILE = DATA_DIR / "latest_report.html"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "monitor.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_seen() -> set:
    if SEEN_FILE.exists():
        return set(json.loads(SEEN_FILE.read_text()))
    return set()


def save_seen(seen: set):
    SEEN_FILE.write_text(json.dumps(list(seen), indent=2))


def make_hash(url: str, title: str) -> str:
    return hashlib.md5(f"{url}{title}".encode()).hexdigest()


def is_nc_relevant(text: str) -> bool:
    """Return True only if text is about Holly Springs NC, not another state."""
    text_lower = text.lower()

    # Reject if it matches another state
    for pat in EXCLUDE_PATTERNS:
        if re.search(pat, text_lower):
            return False

    # Accept if it has an NC signal
    for signal in NC_SIGNALS:
        if signal in text_lower:
            return True

    # Accept if a broad Holly Springs police keyword is there (assume NC by default
    # since we're already searching NC-focused sources)
    for kw in ["holly springs police", "holly springs pd"]:
        if kw in text_lower:
            return True

    return False


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


# ── News RSS Feeds ────────────────────────────────────────────────────────────

RSS_FEEDS = {
    "WRAL News":        "https://www.wral.com/rss/news/",
    "WTVD ABC11":       "https://abc11.com/feed/",
    "CBS17":            "https://www.cbs17.com/feed/",
    "News & Observer":  "https://www.newsobserver.com/news/?widgetName=rssfeed&widgetContentId=712015&getXmlFeed=true",
    "Holly Springs Sun":"https://hollyspringssun.com/feed/",
    "NCNewsLine":       "https://ncnewsline.com/feed/",
}

GOOGLE_NEWS_QUERIES = [
    # Core PD queries
    "Holly Springs NC police",
    "Holly Springs North Carolina police department",
    '"Holly Springs" "NC" police',
    # Incident & crime
    "Holly Springs NC crime",
    "Holly Springs NC arrest",
    "Holly Springs NC shooting",
    "Holly Springs NC incident",
    "Holly Springs NC officer",
    # Broader law enforcement
    "Holly Springs NC sheriff Wake County",
    '"Holly Springs" "27540" police',
    # Community & accountability
    "Holly Springs NC police misconduct",
    "Holly Springs NC police investigation",
    "Holly Springs North Carolina crime report",
]


def scrape_rss(seen: set) -> list:
    results = []
    for source, url in RSS_FEEDS.items():
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                title   = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                link    = entry.get("link", "")
                combined = f"{title} {summary}"

                if not any(kw in combined.lower() for kw in KEYWORDS):
                    continue
                if not is_nc_relevant(combined):
                    continue

                h = make_hash(link, title)
                if h in seen:
                    continue

                published = entry.get("published", "Unknown date")
                results.append({
                    "source":    source,
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": published,
                    "category":  "News",
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[RSS] New: {title} ({source})")
        except Exception as e:
            log.warning(f"[RSS] Failed {source}: {e}")
    return results


def scrape_google_news(seen: set) -> list:
    results = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; NewsBot/1.0)"}

    for query in GOOGLE_NEWS_QUERIES:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = feedparser.parse(url)
            time.sleep(1)

            for entry in feed.entries:
                title   = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                link    = entry.get("link", "")
                combined = f"{title} {summary}"

                if not is_nc_relevant(combined):
                    continue

                h = make_hash(link, title)
                if h in seen:
                    continue

                results.append({
                    "source":    "Google News",
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown"),
                    "category":  "News",
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Google News] New: {title}")
        except Exception as e:
            log.warning(f"[Google News] Query failed '{query}': {e}")
    return results


# ── Google Search – Facebook public posts ─────────────────────────────────────

# Google indexes many public Facebook posts; searching site:facebook.com lets us
# find community mentions without needing FB login or API access.
GOOGLE_FACEBOOK_QUERIES = [
    'site:facebook.com "holly springs" "police" "nc"',
    'site:facebook.com "holly springs police" "north carolina"',
    'site:facebook.com "holly springs nc" "police department"',
    'site:facebook.com "holly springs nc" "arrest" OR "crime" OR "incident"',
    'site:facebook.com "holly springs nc" "officer" OR "shooting"',
]


def scrape_google_for_facebook(seen: set) -> list:
    """
    Use Google News RSS to surface public Facebook posts about Holly Springs NC police.
    This catches community group posts, local shares, and public pages Google has indexed.
    """
    results = []

    for query in GOOGLE_FACEBOOK_QUERIES:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = feedparser.parse(url)
            time.sleep(1.5)

            for entry in feed.entries:
                title   = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                link    = entry.get("link", "")
                combined = f"{title} {summary} {link}"

                # Only keep results that are actually Facebook links
                if "facebook.com" not in link.lower():
                    continue
                if not is_nc_relevant(combined):
                    continue

                h = make_hash(link, title)
                if h in seen:
                    continue

                results.append({
                    "source":    "Facebook (via Google Search)",
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown"),
                    "category":  "Social Media",
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Google→FB] New: {title}")
        except Exception as e:
            log.warning(f"[Google→FB] Query failed '{query}': {e}")

    return results


# ── Reddit ────────────────────────────────────────────────────────────────────

REDDIT_QUERIES = [
    "holly springs police nc",
    "holly springs nc police department",
    '"holly springs" police "north carolina"',
    '"holly springs" pd nc',
]

REDDIT_SUBREDDITS = ["raleigh", "NorthCarolina", "triangle"]


def scrape_reddit(seen: set) -> list:
    results = []

    # Method 1: Reddit RSS feeds (no auth needed, very reliable)
    for subreddit in REDDIT_SUBREDDITS:
        for query in REDDIT_QUERIES[:2]:
            try:
                encoded = requests.utils.quote(query)
                url = (
                    f"https://www.reddit.com/r/{subreddit}/search.rss"
                    f"?q={encoded}&sort=new&restrict_sr=1"
                )
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/122.0.0.0 Safari/537.36",
                    "Accept": "application/rss+xml, application/xml, text/xml"
                }
                feed = feedparser.parse(url)
                time.sleep(2)

                for entry in feed.entries:
                    title   = clean_text(entry.get("title", ""))
                    summary = clean_text(entry.get("summary", ""))
                    link    = entry.get("link", "")
                    combined = f"{title} {summary}"

                    if not any(kw in combined.lower() for kw in KEYWORDS) and \
                       not is_nc_relevant(combined):
                        continue

                    h = make_hash(link, title)
                    if h in seen:
                        continue

                    published = entry.get("published", datetime.now().strftime("%Y-%m-%d"))
                    results.append({
                        "source":    f"Reddit r/{subreddit}",
                        "title":     title,
                        "summary":   BeautifulSoup(summary, "html.parser").get_text()[:300],
                        "url":       link,
                        "published": published,
                        "category":  "Reddit",
                        "hash":      h,
                    })
                    seen.add(h)
                    log.info(f"[Reddit RSS] New: {title}")

            except Exception as e:
                log.warning(f"[Reddit RSS] r/{subreddit} '{query}': {e}")

    # Method 2: Reddit global search via RSS
    for query in REDDIT_QUERIES:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://www.reddit.com/search.rss?q={encoded}&sort=new&t=week"
            headers = {"User-Agent": "Mozilla/5.0"}
            feed = feedparser.parse(url)
            time.sleep(2)

            for entry in feed.entries:
                title   = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                link    = entry.get("link", "")
                combined = f"{title} {summary}"

                if not is_nc_relevant(combined):
                    continue

                h = make_hash(link, title)
                if h in seen:
                    continue

                published = entry.get("published", "")
                results.append({
                    "source":    "Reddit (all)",
                    "title":     title,
                    "summary":   BeautifulSoup(summary, "html.parser").get_text()[:300],
                    "url":       link,
                    "published": published,
                    "category":  "Reddit",
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Reddit global] New: {title}")

        except Exception as e:
            log.warning(f"[Reddit global] '{query}': {e}")

    return results


# ── Public Social Media (Facebook public pages via scraping) ──────────────────

FB_PAGES = [
    # Official PD page — always included regardless of keywords
    {
        "name": "Holly Springs Police Dept (Facebook)",
        "url":  "https://www.facebook.com/HollySpringsPoliceDepartmentNC",
        "keyword_filter": False,
    },
    # Town of Holly Springs — posts police-related notices
    {
        "name": "Town of Holly Springs NC (Facebook)",
        "url":  "https://www.facebook.com/TownofHollySpringsNC",
        "keyword_filter": True,
    },
    # Local TV news pages — filter for HS police mentions
    {
        "name": "WRAL News (Facebook)",
        "url":  "https://www.facebook.com/wral",
        "keyword_filter": True,
    },
    {
        "name": "ABC11 WTVD (Facebook)",
        "url":  "https://www.facebook.com/ABC11",
        "keyword_filter": True,
    },
    {
        "name": "CBS17 (Facebook)",
        "url":  "https://www.facebook.com/CBS17",
        "keyword_filter": True,
    },
    # Public community groups
    {
        "name": "Holly Springs NC Community Group (Facebook)",
        "url":  "https://www.facebook.com/groups/HollySpringsNC",
        "keyword_filter": True,
    },
    {
        "name": "Holly Springs Happenings (Facebook)",
        "url":  "https://www.facebook.com/groups/hollyspringshappenings",
        "keyword_filter": True,
    },
]

# Keywords required to keep a post from keyword_filter=True pages
FB_KEYWORDS = [
    "holly springs police", "holly springs pd", "hspd",
    "holly springs nc police", "holly springs crime",
    "holly springs arrest", "holly springs officer",
    "holly springs incident", "holly springs shooting",
    "holly springs investigation",
]

TWITTER_ACCOUNTS = [
    {"handle": "HollySpringsPD",   "name": "Holly Springs PD (X/Twitter)"},
    {"handle": "TownHollySprings", "name": "Town of Holly Springs (X/Twitter)"},
    {"handle": "WRALNews",         "name": "WRAL News (X/Twitter)"},
    {"handle": "ABC11_WTVD",       "name": "ABC11 WTVD (X/Twitter)"},
]

NITTER_INSTANCES = [
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
]


def scrape_facebook_public(seen: set) -> list:
    """
    Scrape public Facebook pages via the public mbasic view.
    No login required for public pages.
    """
    results = []
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
    }

    for page in FB_PAGES:
        try:
            # mbasic.facebook.com is the lightweight mobile version - no JS required
            handle = page["url"].rstrip("/").split("/")[-1]
            url = f"https://mbasic.facebook.com/{handle}"
            r = requests.get(url, headers=headers, timeout=15)
            soup = BeautifulSoup(r.text, "html.parser")

            # Each post is in a <div> with an id starting with "u_" or story articles
            posts = soup.find_all("div", attrs={"data-ft": True})

            if not posts:
                # Fallback: grab any article-style blocks
                posts = soup.find_all("article")

            for post in posts[:15]:
                text = clean_text(post.get_text(" ", strip=True))
                if len(text) < 20:
                    continue

                # For pages that aggregate content, filter by keyword
                if page.get("keyword_filter", False):
                    text_lower = text.lower()
                    if not any(kw in text_lower for kw in FB_KEYWORDS):
                        continue
                    if not is_nc_relevant(text):
                        continue

                # Build a stable URL from the post link if available
                link_tag = post.find("a", href=re.compile(r"/story\.php|/permalink/"))
                post_url = page["url"]
                if link_tag:
                    href = link_tag.get("href", "")
                    post_url = "https://www.facebook.com" + href.split("?")[0]

                h = make_hash(post_url, text[:100])
                if h in seen:
                    continue

                results.append({
                    "source":    page["name"],
                    "title":     text[:120] + ("…" if len(text) > 120 else ""),
                    "summary":   text[:400],
                    "url":       page["url"],
                    "published": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                    "category":  "Social Media",
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Facebook] New post from {page['name']}: {text[:80]}")

        except Exception as e:
            log.warning(f"[Facebook] Failed {page['name']}: {e}")

    return results


def scrape_twitter_nitter(seen: set) -> list:
    """
    Fetch public tweets via Nitter (open-source Twitter front-end).
    No API key needed.
    """
    results = []
    headers = {"User-Agent": "Mozilla/5.0"}

    for account in TWITTER_ACCOUNTS:
        fetched = False
        for instance in NITTER_INSTANCES:
            try:
                url = f"{instance}/{account['handle']}"
                r = requests.get(url, headers=headers, timeout=10)
                if r.status_code != 200:
                    continue

                soup = BeautifulSoup(r.text, "html.parser")
                tweets = soup.select(".timeline-item .tweet-content")
                times  = soup.select(".timeline-item .tweet-date a")

                for tweet, t_time in zip(tweets, times):
                    text = clean_text(tweet.get_text())
                    href = t_time.get("href", "")
                    tweet_url = f"https://twitter.com{href}" if href else f"https://twitter.com/{account['handle']}"
                    published = t_time.get("title", datetime.now().strftime("%Y-%m-%d"))

                    h = make_hash(tweet_url, text)
                    if h in seen:
                        continue

                    results.append({
                        "source":    account["name"],
                        "title":     text[:120],
                        "summary":   text[:400],
                        "url":       tweet_url,
                        "published": published,
                        "category":  "Social Media",
                        "hash":      h,
                    })
                    seen.add(h)
                    log.info(f"[Twitter] New tweet: {text[:80]}")

                fetched = True
                break   # stop trying other instances if this worked
            except Exception as e:
                log.warning(f"[Nitter] {instance} failed for @{account['handle']}: {e}")

        if not fetched:
            log.warning(f"[Twitter] All Nitter instances failed for @{account['handle']}")

    return results


# ── HTML Report ───────────────────────────────────────────────────────────────

CATEGORY_COLORS = {
    "News":         "#1a56db",
    "Reddit":       "#ff4500",
    "Social Media": "#1877f2",
}


def build_html_report(items: list, is_full: bool = False) -> str:
    now = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    label = "Full History" if is_full else "New Results"

    rows = ""
    for item in items:
        color = CATEGORY_COLORS.get(item["category"], "#555")
        rows += f"""
        <div class="card">
          <div class="meta">
            <span class="badge" style="background:{color}">{item['category']}</span>
            <span class="source">{item['source']}</span>
            <span class="date">{item['published']}</span>
          </div>
          <a class="title" href="{item['url']}" target="_blank">{item['title']}</a>
          <p class="summary">{item['summary']}</p>
        </div>"""

    if not rows:
        rows = '<p style="color:#888;text-align:center;padding:2rem">No new results found.</p>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Holly Springs NC Police Monitor – {label}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f0f4f8; color: #1a202c; padding: 1.5rem; }}
  header {{ background: #1a365d; color: #fff; padding: 1.2rem 1.5rem;
            border-radius: 10px; margin-bottom: 1.5rem; }}
  header h1 {{ font-size: 1.4rem; font-weight: 700; }}
  header p  {{ font-size: 0.85rem; opacity: 0.75; margin-top: 0.3rem; }}
  .stats    {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .stat     {{ background:#fff; border-radius:8px; padding:0.8rem 1.2rem;
               font-size:0.85rem; color:#555; border-left:4px solid #1a56db; }}
  .stat strong {{ display:block; font-size:1.4rem; color:#1a202c; }}
  .card     {{ background:#fff; border-radius:10px; padding:1rem 1.2rem;
               margin-bottom:1rem; box-shadow:0 1px 4px rgba(0,0,0,.08); }}
  .meta     {{ display:flex; align-items:center; gap:.6rem; flex-wrap:wrap;
               margin-bottom:.5rem; }}
  .badge    {{ color:#fff; font-size:.7rem; font-weight:600; padding:.2rem .6rem;
               border-radius:99px; text-transform:uppercase; letter-spacing:.04em; }}
  .source   {{ font-size:.8rem; color:#555; }}
  .date     {{ font-size:.75rem; color:#888; margin-left:auto; }}
  .title    {{ font-size:1rem; font-weight:600; color:#1a56db; text-decoration:none;
               display:block; margin-bottom:.4rem; }}
  .title:hover {{ text-decoration:underline; }}
  .summary  {{ font-size:.85rem; color:#4a5568; line-height:1.5; }}
</style>
</head>
<body>
<header>
  <h1>🚔 Holly Springs NC Police Monitor</h1>
  <p>Generated {now} · {label} · {len(items)} result(s)</p>
</header>
<div class="stats">
  <div class="stat"><strong>{sum(1 for i in items if i['category']=='News')}</strong>News Articles</div>
  <div class="stat"><strong>{sum(1 for i in items if i['category']=='Reddit')}</strong>Reddit Posts</div>
  <div class="stat"><strong>{sum(1 for i in items if i['category']=='Social Media')}</strong>Social Posts</div>
</div>
{rows}
</body>
</html>"""


# ── Email Notification ────────────────────────────────────────────────────────

def send_email(items: list, config: dict):
    """Send an HTML email digest. Config from environment variables."""
    if not items:
        log.info("No new items — skipping email.")
        return

    smtp_host = config.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(config.get("SMTP_PORT", 587))
    smtp_user = config.get("SMTP_USER", "")
    smtp_pass = config.get("SMTP_PASS", "")
    to_addr   = config.get("NOTIFY_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        log.warning("Email credentials not set — skipping email notification.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[Holly Springs PD Monitor] {len(items)} new result(s)"
    msg["From"]    = smtp_user
    msg["To"]      = to_addr

    html_body = build_html_report(items)
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_addr, msg.as_string())
        log.info(f"Email sent to {to_addr}")
    except Exception as e:
        log.error(f"Email failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    log.info("=" * 60)
    log.info("Holly Springs NC Police Monitor starting...")
    log.info("=" * 60)

    seen = load_seen()
    all_new = []

    log.info("Scraping RSS feeds...")
    all_new += scrape_rss(seen)

    log.info("Scraping Google News...")
    all_new += scrape_google_news(seen)

    log.info("Scraping Reddit...")
    all_new += scrape_reddit(seen)

    log.info("Scraping Facebook public pages...")
    all_new += scrape_facebook_public(seen)

    log.info("Searching Google for public Facebook posts...")
    all_new += scrape_google_for_facebook(seen)

    log.info("Scraping Twitter/X via Nitter...")
    all_new += scrape_twitter_nitter(seen)

    save_seen(seen)

    log.info(f"Found {len(all_new)} new result(s).")

    # Save HTML report
    html = build_html_report(all_new)
    REPORT_FILE.write_text(html, encoding="utf-8")
    log.info(f"Report saved: {REPORT_FILE}")

    # Email if configured
    email_config = {k: os.environ.get(k, "") for k in
                    ["SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "NOTIFY_EMAIL"]}
    send_email(all_new, email_config)

    log.info("Done.")
    return all_new


if __name__ == "__main__":
    run()
