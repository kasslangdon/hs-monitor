"""
HS NC News & Media Monitor
Threat monitoring & accountability edition.
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

EXCLUDE_PATTERNS = [
    r"holly springs,?\s*(ms|mississippi)",
    r"holly springs,?\s*(tx|texas)",
    r"holly springs,?\s*(ga|georgia)",
    r"holly springs,?\s*(ky|kentucky)",
    r"holly springs,?\s*(sc|south carolina)",
    r"holly springs,?\s*(ca|california)",
]

# Obituaries/death notices regularly mention "Holly Springs" as a hometown
# or funeral home location and pollute results with irrelevant content.
OBITUARY_PATTERNS = [
    r"\bobituary\b", r"\bobituaries\b",
    r"\bpassed away\b", r"\bpeacefully passed\b",
    r"\bfuneral (home|service|services|arrangements)\b",
    r"\bcelebration of life\b", r"\bin lieu of flowers\b",
    r"\bsurvived by\b", r"\bpreceded in death\b",
    r"\bvisitation will be held\b", r"\blaid to rest\b",
]

NC_SIGNALS = [
    "nc", "north carolina", "wake county", "raleigh", "holly springs, nc",
    "hollyspringsnc", "holly springs nc", "27540",
]

# ── HIGH PRIORITY / THREAT KEYWORDS ──────────────────────────────────────────
# Any result containing these gets flagged as critical (red banner)

HIGH_PRIORITY_KEYWORDS = [
    # Use of force
    "officer involved shooting", "officer-involved shooting", "ois",
    "use of force", "excessive force", "police shooting",
    "shot by police", "killed by police", "tased", "choked",
    "in custody death", "death in custody", "died in custody",
    # Legal / accountability
    "civil rights lawsuit", "1983", "§1983", "section 1983",
    "wrongful death", "police misconduct", "brutality",
    "internal affairs", "under investigation", "indicted",
    "criminal charges", "officer charged", "officer arrested",
    "decertified", "post commission", "sustained complaint",
    # Threats / serious incidents
    "active shooter", "hostage", "barricade", "swat",
    "pursuit ended", "high speed chase", "officer struck",
    "officer injured", "officer killed", "ambush",
]

# ── File Paths ────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
DATA_DIR    = BASE_DIR / "data"
LOG_DIR     = BASE_DIR / "logs"
SEEN_FILE   = DATA_DIR / "seen_hashes.json"
ARCHIVE_FILE = DATA_DIR / "archive.json"
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

ARCHIVE_WINDOW_DAYS = 365

def load_archive() -> dict:
    """Returns {hash: item} for everything previously seen, with a
    'first_seen' ISO timestamp recorded on each item."""
    if ARCHIVE_FILE.exists():
        try:
            return json.loads(ARCHIVE_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_archive(archive: dict):
    ARCHIVE_FILE.write_text(json.dumps(archive, indent=2))

def prune_archive(archive: dict) -> dict:
    """Drop anything older than ARCHIVE_WINDOW_DAYS based on first_seen."""
    cutoff = datetime.now(timezone.utc).timestamp() - ARCHIVE_WINDOW_DAYS * 86400
    kept = {}
    for h, item in archive.items():
        try:
            ts = datetime.fromisoformat(item["first_seen"]).timestamp()
        except Exception:
            ts = 0
        if ts >= cutoff:
            kept[h] = item
    return kept

def make_hash(url: str, title: str) -> str:
    return hashlib.md5(f"{url}{title}".encode()).hexdigest()

def is_nc_relevant(text: str) -> bool:
    text_lower = text.lower()
    for pat in EXCLUDE_PATTERNS:
        if re.search(pat, text_lower):
            return False
    for pat in OBITUARY_PATTERNS:
        if re.search(pat, text_lower):
            return False
    for signal in NC_SIGNALS:
        if signal in text_lower:
            return True
    for kw in ["holly springs police", "holly springs pd"]:
        if kw in text_lower:
            return True
    return False

def is_high_priority(text: str) -> bool:
    text_lower = text.lower()
    for kw in HIGH_PRIORITY_KEYWORDS:
        if kw in text_lower:
            return True
    return False

def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


FEED_TIMEOUT = 15
FEED_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/rss+xml, application/xml, text/xml, */*",
}


def fetch_feed(url: str):
    """Fetch a feed URL with a hard timeout and parse it.

    feedparser.parse(url) has no timeout when given a URL string and can
    hang indefinitely on a slow/unresponsive server. Fetching with
    requests first (which always has a timeout) avoids that."""
    try:
        r = requests.get(url, headers=FEED_HEADERS, timeout=FEED_TIMEOUT)
        r.raise_for_status()
        return feedparser.parse(r.content)
    except Exception as e:
        log.warning(f"Feed fetch failed for {url}: {e}")
        return feedparser.parse(b"")  # empty feed, .entries == []



# ── News RSS Feeds ────────────────────────────────────────────────────────────

RSS_FEEDS = {
    "WRAL News":        "https://www.wral.com/news/rss/142/",
    "WTVD ABC11":       "https://abc11.com/feed/",
    "CBS17":            "https://www.cbs17.com/feed/",
    "News & Observer":  "https://www.newsobserver.com/news/?widgetName=rssfeed&widgetContentId=712015&getXmlFeed=true",
    "Holly Springs Sun":"https://hollyspringssun.com/feed/",
    "NCNewsLine":       "https://ncnewsline.com/feed/",
    "NC DOJ":           "https://ncdoj.gov/feed/",
    "ACLU NC":          "https://www.acluofnorthcarolina.org/feed/",
}

GOOGLE_NEWS_QUERIES = [
    # Core
    "Holly Springs NC police",
    "Holly Springs North Carolina police department",
    '"Holly Springs" "NC" police',
    # Incidents
    "Holly Springs NC crime",
    "Holly Springs NC arrest",
    "Holly Springs NC shooting",
    "Holly Springs NC incident",
    "Holly Springs NC officer",
    # Accountability
    "Holly Springs NC police misconduct",
    "Holly Springs NC police investigation",
    "Holly Springs NC use of force",
    "Holly Springs NC officer involved shooting",
    "Holly Springs NC civil rights lawsuit",
    "Holly Springs NC police lawsuit",
    "Holly Springs NC internal affairs",
    # Court / legal
    "Holly Springs NC police charged",
    "Holly Springs NC officer indicted",
    '"Holly Springs" "27540" police',
    # Broader
    "Holly Springs NC sheriff Wake County",
    "Holly Springs North Carolina crime report",
    # NC POST
    '"Holly Springs" officer decertified NC',
    '"Holly Springs Police" POST commission',
    # Town governance
    "Holly Springs NC town council police",
    "Holly Springs NC police budget",
]


def scrape_rss(seen: set) -> list:
    results = []
    for source, url in RSS_FEEDS.items():
        try:
            feed = fetch_feed(url)
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

                results.append({
                    "source":    source,
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown date"),
                    "category":  "News",
                    "priority":  is_high_priority(combined),
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[RSS] New: {title} ({source})")
        except Exception as e:
            log.warning(f"[RSS] Failed {source}: {e}")
    return results


def scrape_google_news(seen: set) -> list:
    results = []
    for query in GOOGLE_NEWS_QUERIES:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = fetch_feed(url)
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
                    "priority":  is_high_priority(combined),
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Google News] New: {title}")
        except Exception as e:
            log.warning(f"[Google News] Query failed '{query}': {e}")
    return results


# ── Court Records ─────────────────────────────────────────────────────────────

COURT_QUERIES = [
    # Federal civil rights
    '"holly springs" "north carolina" "1983"',
    '"holly springs police" "civil rights"',
    '"holly springs" officer "use of force" lawsuit',
    '"holly springs" police "wrongful death"',
    # Criminal charges against officers
    '"holly springs" officer charged "north carolina"',
    '"holly springs" officer indicted',
    # PACER / court filings via Google
    'site:courtlistener.com "holly springs" "north carolina" police',
    'site:pacermonitor.com "holly springs" police "north carolina"',
]


def scrape_court_records(seen: set) -> list:
    """
    Search Google News + CourtListener RSS for court cases involving HSPD.
    Covers §1983 civil rights, use of force, and officer criminal charges.
    """
    results = []

    # CourtListener RSS (public federal court filings)
    court_feeds = [
        ("CourtListener — HSPD Civil Rights",
         "https://www.courtlistener.com/feed/search/?q=%22holly+springs%22+%22north+carolina%22+police&type=o"),
        ("CourtListener — Officer Force NC",
         "https://www.courtlistener.com/feed/search/?q=%22holly+springs%22+%22use+of+force%22+%22north+carolina%22&type=o"),
    ]

    for source, url in court_feeds:
        try:
            feed = fetch_feed(url)
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
                    "source":    source,
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown"),
                    "category":  "Court Records",
                    "priority":  True,   # all court hits are high priority
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Court] New filing: {title}")
            time.sleep(1)
        except Exception as e:
            log.warning(f"[Court] Feed failed {source}: {e}")

    # Google News search for court coverage
    for query in COURT_QUERIES:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = fetch_feed(url)
            time.sleep(1.5)

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
                    "source":    "Court / Legal (Google)",
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown"),
                    "category":  "Court Records",
                    "priority":  True,
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Court/Google] New: {title}")
        except Exception as e:
            log.warning(f"[Court] Google query failed: {e}")

    return results


# ── NC DOJ & Town Council ─────────────────────────────────────────────────────

def scrape_accountability_sources(seen: set) -> list:
    """
    Scrape NC DOJ press releases, town council minutes, and NC POST news
    for accountability-specific content.
    """
    results = []

    sources = [
        {
            "name": "NC DOJ Press Releases",
            "url":  "https://ncdoj.gov/press-releases/",
            "keywords": ["holly springs", "wake county police", "hspd"],
        },
        {
            "name": "Town of Holly Springs — Agendas",
            "url":  "https://www.hollyspringsnc.us/AgendaCenter",
            "keywords": ["police", "officer", "public safety", "crime"],
        },
        {
            "name": "Wake County Sheriff Press Releases",
            "url":  "https://www.wakegov.com/departments-government/sheriff/news",
            "keywords": ["holly springs"],
        },
    ]

    headers = {"User-Agent": "Mozilla/5.0"}

    for source in sources:
        try:
            r = requests.get(source["url"], headers=headers, timeout=15)
            soup = BeautifulSoup(r.text, "html.parser")

            # Grab all links with text matching keywords
            for a in soup.find_all("a", href=True):
                text = clean_text(a.get_text())
                if len(text) < 10:
                    continue
                text_lower = text.lower()
                if not any(kw in text_lower for kw in source["keywords"]):
                    continue

                href = a["href"]
                if not href.startswith("http"):
                    base = "/".join(source["url"].split("/")[:3])
                    href = base + "/" + href.lstrip("/")

                h = make_hash(href, text)
                if h in seen:
                    continue

                results.append({
                    "source":    source["name"],
                    "title":     text[:200],
                    "summary":   f"Found on {source['name']}",
                    "url":       href,
                    "published": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "category":  "Accountability",
                    "priority":  is_high_priority(text),
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Accountability] New: {text[:80]} ({source['name']})")

            time.sleep(1)
        except Exception as e:
            log.warning(f"[Accountability] Failed {source['name']}: {e}")

    # Also search Google News for town council + police
    council_queries = [
        "Holly Springs NC town council police 2024",
        "Holly Springs NC town council police 2025",
        "Holly Springs NC police budget town meeting",
        "Holly Springs NC public safety committee",
    ]
    for query in council_queries:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = fetch_feed(url)
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
                    "source":    "Town Council / Governance",
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown"),
                    "category":  "Accountability",
                    "priority":  is_high_priority(combined),
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Council] New: {title}")
        except Exception as e:
            log.warning(f"[Council] Query failed: {e}")

    return results


# ── Citizen App — Filtered High-Priority Only ─────────────────────────────────

CITIZEN_HIGH_PRIORITY = [
    "officer involved", "shooting", "shot fired", "shots fired",
    "pursuit", "chase", "swat", "hostage", "barricade",
    "officer down", "officer injured", "officer struck",
    "use of force", "in custody", "death investigation",
    "homicide", "critical incident",
]

def scrape_citizen_app(seen: set) -> list:
    """
    Search Google for high-priority Citizen App incidents in Holly Springs NC.
    Filters to serious incidents only — not routine calls for service.
    """
    results = []
    queries = [
        'site:citizen.com "holly springs" "north carolina" shooting',
        'site:citizen.com "holly springs" NC "officer involved"',
        'site:citizen.com "holly springs" NC pursuit OR "shots fired"',
        'site:citizen.com "holly springs" NC "use of force" OR "officer down"',
    ]

    for query in queries:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = fetch_feed(url)
            time.sleep(1)

            for entry in feed.entries:
                title   = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                link    = entry.get("link", "")
                combined = f"{title} {summary}"

                # Strict filter — only serious incidents
                text_lower = combined.lower()
                if not any(kw in text_lower for kw in CITIZEN_HIGH_PRIORITY):
                    continue
                if not is_nc_relevant(combined):
                    continue

                h = make_hash(link, title)
                if h in seen:
                    continue

                results.append({
                    "source":    "Citizen App",
                    "title":     title,
                    "summary":   summary[:300],
                    "url":       link,
                    "published": entry.get("published", "Unknown"),
                    "category":  "Critical Incident",
                    "priority":  True,
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Citizen] Critical incident: {title}")
        except Exception as e:
            log.warning(f"[Citizen] Query failed: {e}")

    return results


# ── Reddit ────────────────────────────────────────────────────────────────────

REDDIT_QUERIES = [
    "holly springs police nc",
    "holly springs nc police department",
    '"holly springs" police "north carolina"',
    '"holly springs" pd nc',
]
REDDIT_SUBREDDITS = ["raleigh", "NorthCarolina", "triangle", "HollySpringsNC"]

# Hyper-local subreddit already implies location, so we can search broader
# terms without requiring "nc"/"north carolina" in the query itself.
REDDIT_LOCAL_QUERIES = ["police", "officer", "arrest", "shooting", "crime"]


def scrape_reddit(seen: set) -> list:
    results = []

    for subreddit in REDDIT_SUBREDDITS:
        queries = REDDIT_LOCAL_QUERIES if subreddit == "HollySpringsNC" else REDDIT_QUERIES[:2]
        for query in queries:
            try:
                encoded = requests.utils.quote(query)
                url = (f"https://www.reddit.com/r/{subreddit}/search.rss"
                       f"?q={encoded}&sort=new&restrict_sr=1")
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                feed = fetch_feed(url)
                time.sleep(2)

                for entry in feed.entries:
                    title   = clean_text(entry.get("title", ""))
                    summary = clean_text(entry.get("summary", ""))
                    link    = entry.get("link", "")
                    combined = f"{title} {summary}"

                    if any(re.search(pat, combined.lower()) for pat in OBITUARY_PATTERNS):
                        continue

                    if subreddit != "HollySpringsNC" and \
                       not any(kw in combined.lower() for kw in KEYWORDS) and \
                       not is_nc_relevant(combined):
                        continue

                    h = make_hash(link, title)
                    if h in seen:
                        continue

                    results.append({
                        "source":    f"Reddit r/{subreddit}",
                        "title":     title,
                        "summary":   BeautifulSoup(summary, "html.parser").get_text()[:300],
                        "url":       link,
                        "published": entry.get("published", ""),
                        "category":  "Reddit",
                        "priority":  is_high_priority(combined),
                        "hash":      h,
                    })
                    seen.add(h)
                    log.info(f"[Reddit] New: {title}")
            except Exception as e:
                log.warning(f"[Reddit] r/{subreddit} '{query}': {e}")

    # Global Reddit search
    for query in REDDIT_QUERIES:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://www.reddit.com/search.rss?q={encoded}&sort=new&t=week"
            feed = fetch_feed(url)
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

                results.append({
                    "source":    "Reddit (all)",
                    "title":     title,
                    "summary":   BeautifulSoup(summary, "html.parser").get_text()[:300],
                    "url":       link,
                    "published": entry.get("published", ""),
                    "category":  "Reddit",
                    "priority":  is_high_priority(combined),
                    "hash":      h,
                })
                seen.add(h)
        except Exception as e:
            log.warning(f"[Reddit global] '{query}': {e}")

    return results


# ── Facebook Public Pages ─────────────────────────────────────────────────────

FB_PAGES = [
    {"name": "Holly Springs Police Dept (Facebook)",
     "url":  "https://www.facebook.com/HollySpringsPoliceDepartmentNC",
     "keyword_filter": False},
    {"name": "Town of Holly Springs NC (Facebook)",
     "url":  "https://www.facebook.com/TownofHollySpringsNC",
     "keyword_filter": True},
    {"name": "WRAL News (Facebook)",
     "url":  "https://www.facebook.com/wral",
     "keyword_filter": True},
    {"name": "ABC11 WTVD (Facebook)",
     "url":  "https://www.facebook.com/ABC11",
     "keyword_filter": True},
    {"name": "CBS17 (Facebook)",
     "url":  "https://www.facebook.com/CBS17",
     "keyword_filter": True},
    {"name": "Holly Springs NC Community Group (Facebook)",
     "url":  "https://www.facebook.com/groups/HollySpringsNC",
     "keyword_filter": True},
    {"name": "Holly Springs Happenings (Facebook)",
     "url":  "https://www.facebook.com/groups/hollyspringshappenings",
     "keyword_filter": True},
]

FB_KEYWORDS = [
    "holly springs police", "holly springs pd", "hspd",
    "holly springs nc police", "holly springs crime",
    "holly springs arrest", "holly springs officer",
    "holly springs incident", "holly springs shooting",
    "holly springs investigation", "holly springs use of force",
    "holly springs lawsuit", "holly springs misconduct",
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
    results = []
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"}

    for page in FB_PAGES:
        try:
            handle = page["url"].rstrip("/").split("/")[-1]
            url = f"https://mbasic.facebook.com/{handle}"
            r = requests.get(url, headers=headers, timeout=15)
            soup = BeautifulSoup(r.text, "html.parser")

            posts = soup.find_all("div", attrs={"data-ft": True})
            if not posts:
                posts = soup.find_all("article")

            for post in posts[:15]:
                text = clean_text(post.get_text(" ", strip=True))
                if len(text) < 20:
                    continue

                if page.get("keyword_filter", False):
                    text_lower = text.lower()
                    if not any(kw in text_lower for kw in FB_KEYWORDS):
                        continue
                    if not is_nc_relevant(text):
                        continue

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
                    "priority":  is_high_priority(text),
                    "hash":      h,
                })
                seen.add(h)
                log.info(f"[Facebook] New post from {page['name']}: {text[:80]}")
        except Exception as e:
            log.warning(f"[Facebook] Failed {page['name']}: {e}")

    return results


def scrape_google_for_facebook(seen: set) -> list:
    results = []
    queries = [
        'site:facebook.com "holly springs" "police" "nc"',
        'site:facebook.com "holly springs police" "north carolina"',
        'site:facebook.com "holly springs nc" "police department"',
        'site:facebook.com "holly springs nc" "arrest" OR "crime" OR "incident"',
        'site:facebook.com "holly springs nc" "officer" OR "shooting"',
        'site:facebook.com "holly springs nc" "misconduct" OR "lawsuit" OR "force"',
    ]

    for query in queries:
        try:
            encoded = requests.utils.quote(query)
            url = f"https://news.google.com/rss/search?q={encoded}&hl=en-US&gl=US&ceid=US:en"
            feed = fetch_feed(url)
            time.sleep(1.5)

            for entry in feed.entries:
                title   = clean_text(entry.get("title", ""))
                summary = clean_text(entry.get("summary", ""))
                link    = entry.get("link", "")
                combined = f"{title} {summary} {link}"

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
                    "priority":  is_high_priority(combined),
                    "hash":      h,
                })
                seen.add(h)
        except Exception as e:
            log.warning(f"[Google→FB] Query failed: {e}")

    return results


def scrape_twitter_nitter(seen: set) -> list:
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
                        "priority":  is_high_priority(text),
                        "hash":      h,
                    })
                    seen.add(h)

                fetched = True
                break
            except Exception as e:
                log.warning(f"[Nitter] {instance} failed for @{account['handle']}: {e}")

        if not fetched:
            log.warning(f"[Twitter] All Nitter instances failed for @{account['handle']}")

    return results


# ── HTML Report ───────────────────────────────────────────────────────────────

CATEGORY_COLORS = {
    "News":             "#1a56db",
    "Reddit":           "#ff4500",
    "Social Media":     "#1877f2",
    "Court Records":    "#7c3aed",
    "Accountability":   "#b45309",
    "Critical Incident":"#dc2626",
}


def build_html_report(items: list, is_full: bool = False, new_hashes: set = None) -> str:
    new_hashes = new_hashes or set()
    now   = datetime.now().strftime("%B %d, %Y at %I:%M %p")
    label = f"Last {ARCHIVE_WINDOW_DAYS} Days"

    high_priority = [i for i in items if i.get("priority")]
    normal        = [i for i in items if not i.get("priority")]

    def render_card(item, compact=False):
        color = CATEGORY_COLORS.get(item["category"], "#555")
        pri   = ' data-pri="1"' if item.get("priority") else ""
        is_new = item.get("hash") in new_hashes
        new_tag = '<span class="new-tag">🆕 NEW</span>' if is_new else ""
        cls = "card card-compact" if compact else "card"

        priority_tag = ""
        if not compact and item.get("priority"):
            priority_tag = '<span class="priority-tag">⚠ HIGH PRIORITY</span>'

        summary_html = "" if compact else f'<p class="summary">{item["summary"]}</p>'

        return f"""
        <div class="{cls}" data-cat="{item['category']}"{pri}>
          <div class="meta">
            <span class="badge" style="background:{color}">{item['category']}</span>
            {priority_tag}
            {new_tag}
            <span class="source">{item['source']}</span>
            <span class="date">{item['published']}</span>
          </div>
          <a class="title" href="{item['url']}" target="_blank">{item['title']}</a>
          {summary_html}
        </div>"""

    # Sidebar: compact priority list
    sidebar_cards = "".join(render_card(i, compact=True) for i in high_priority)
    if not sidebar_cards:
        sidebar_cards = '<div class="empty-sidebar">✅ No high priority items right now.</div>'

    normal_cards = "".join(render_card(i) for i in normal)
    if not normal_cards:
        normal_cards = '''<div class="empty">
          <p>✅ No new routine results this run.</p>
          <p>The monitor is working — nothing new matched your keywords since the last check.</p>
        </div>'''

    cat_counts = {}
    for i in items:
        cat_counts[i["category"]] = cat_counts.get(i["category"], 0) + 1

    stat_html = "".join(
        f'<div class="stat"><strong>{v}</strong>{k}</div>'
        for k, v in cat_counts.items()
    )
    stat_html += f'<div class="stat" style="border-color:#dc2626"><strong>{len(high_priority)}</strong>⚠ High Priority</div>'

    filter_cats = list(CATEGORY_COLORS.keys())
    filter_btns = "".join(
        f'<button class="filter-btn" onclick="filterCards(\'{c}\', this)">{c}</button>'
        for c in filter_cats
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>HS NC News & Media Monitor</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f0f4f8; color: #1a202c; padding: 1.5rem; max-width: 1280px; margin: 0 auto; }}
  header {{ background: #1a365d; color: #fff; padding: 1.2rem 1.5rem;
            border-radius: 10px; margin-bottom: 1.5rem;
            display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: .5rem; }}
  header h1 {{ font-size: 1.4rem; font-weight: 700; }}
  header p  {{ font-size: 0.8rem; opacity: 0.7; }}
  .refresh  {{ font-size: .75rem; background: rgba(255,255,255,.15); color: #fff;
               padding: .3rem .8rem; border-radius: 99px; text-decoration: none; }}
  .refresh:hover {{ background: rgba(255,255,255,.25); }}

  /* ── Two-column layout ── */
  .layout   {{ display: flex; gap: 1.5rem; align-items: flex-start; }}
  .main-col {{ flex: 1; min-width: 0; }}
  .sidebar  {{ width: 300px; flex-shrink: 0; position: sticky; top: 1.5rem;
               background: #fff1f1; border: 1px solid #fecaca; border-radius: 10px;
               max-height: calc(100vh - 3rem); overflow-y: auto; }}
  .sidebar-header {{ background: #dc2626; color: #fff; font-weight: 700; font-size: .85rem;
                      letter-spacing: .02em; padding: .8rem 1rem; border-radius: 10px 10px 0 0;
                      position: sticky; top: 0; }}
  .sidebar-list   {{ padding: .6rem; }}
  .empty-sidebar  {{ padding: 1.5rem 1rem; text-align: center; color: #6b7280; font-size: .8rem; }}
  .card-compact {{ padding: .65rem .8rem; margin-bottom: .5rem; }}
  .card-compact .meta {{ margin-bottom: .25rem; }}
  .card-compact .title {{ font-size: .82rem; margin-bottom: 0; }}
  .card-compact .summary {{ display: none; }}

  @media (max-width: 860px) {{
    .layout {{ flex-direction: column; }}
    .sidebar {{ width: 100%; position: static; max-height: none; order: -1; }}
  }}

  .stats    {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
  .stat     {{ background:#fff; border-radius:8px; padding:0.8rem 1.2rem;
               font-size:0.8rem; color:#555; border-left:4px solid #1a56db; flex:1; min-width:110px; }}
  .stat strong {{ display:block; font-size:1.3rem; color:#1a202c; }}
  .filters  {{ display:flex; gap:.5rem; flex-wrap:wrap; margin-bottom:1rem; }}
  .filter-btn {{ background:#fff; border:1.5px solid #d1d5db; border-radius:99px;
                 padding:.3rem .9rem; font-size:.8rem; cursor:pointer; color:#374151; }}
  .filter-btn.active {{ background:#1a365d; color:#fff; border-color:#1a365d; }}

  .card     {{ background:#fff; border-radius:10px; padding:1rem 1.2rem;
               margin-bottom:.8rem; box-shadow:0 1px 4px rgba(0,0,0,.08);
               border-left: 3px solid transparent; }}
  .meta     {{ display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; margin-bottom:.5rem; }}
  .badge    {{ color:#fff; font-size:.7rem; font-weight:600; padding:.2rem .6rem;
               border-radius:99px; text-transform:uppercase; letter-spacing:.04em; }}
  .priority-tag {{ background:#dc2626; color:#fff; font-size:.65rem; font-weight:700;
                   padding:.15rem .5rem; border-radius:4px; }}
  .new-tag  {{ background:#16a34a; color:#fff; font-size:.65rem; font-weight:700;
               padding:.15rem .5rem; border-radius:4px; }}
  .source   {{ font-size:.78rem; color:#555; }}
  .date     {{ font-size:.72rem; color:#888; margin-left:auto; }}
  .title    {{ font-size:.95rem; font-weight:600; color:#1a56db; text-decoration:none;
               display:block; margin-bottom:.4rem; line-height:1.4; }}
  .title:hover {{ text-decoration:underline; }}
  .summary  {{ font-size:.83rem; color:#4a5568; line-height:1.5; }}
  .empty    {{ background:#fff; border-radius:10px; padding:2.5rem; text-align:center;
               color:#6b7280; line-height:2; }}
  footer    {{ text-align:center; font-size:.72rem; color:#9ca3af; margin-top:2rem;
               padding-top:1rem; border-top:1px solid #e5e7eb; }}

  .section-label {{ font-size:.8rem; font-weight:600; color:#6b7280; text-transform:uppercase;
                    letter-spacing:.08em; margin: 1.2rem 0 .6rem; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>📰 HS NC News & Media Monitor</h1>
    <p>Threat & Accountability Edition · Auto-updated every 6 hours · {label} · {len(items)} result(s)</p>
  </div>
  <a class="refresh" href="javascript:location.reload()">↻ Refresh</a>
</header>

<div class="stats">
  {stat_html}
</div>

<div class="layout">
  <main class="main-col">
    <div class="filters">
      <button class="filter-btn active" onclick="filterCards('all', this)">All</button>
      {filter_btns}
      <button class="filter-btn" onclick="filterCards('priority', this)">⚠ Priority Only</button>
    </div>

    <div class="section-label">All Results</div>
    <div id="results">
    {normal_cards}
    </div>
  </main>

  <aside class="sidebar">
    <div class="sidebar-header">⚠ High Priority ({len(high_priority)})</div>
    <div class="sidebar-list">{sidebar_cards}</div>
  </aside>
</div>

<footer>Generated {now} · HS NC News & Media Monitor · Showing the last {ARCHIVE_WINDOW_DAYS} days, newest first<br>
Monitors: News · Reddit · Facebook · Twitter · Court Records · NC DOJ · Town Council · Citizen App (critical only)</footer>

<script>
function filterCards(cat, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#results .card').forEach(card => {{
    if (cat === 'all') {{ card.style.display = ''; }}
    else if (cat === 'priority') {{ card.style.display = card.dataset.pri === '1' ? '' : 'none'; }}
    else {{ card.style.display = card.dataset.cat === cat ? '' : 'none'; }}
  }});
}}
</script>
</body>
</html>"""


# ── Email — Immediate Alert for High Priority ─────────────────────────────────

def send_email(items: list, config: dict, subject_override: str = ""):
    if not items:
        log.info("No new items — skipping email.")
        return

    smtp_host = config.get("SMTP_HOST") or "smtp.gmail.com"
    smtp_port = int(config.get("SMTP_PORT") or 587)
    smtp_user = config.get("SMTP_USER", "")
    smtp_pass = config.get("SMTP_PASS", "")
    to_addr   = config.get("NOTIFY_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        log.warning("Email credentials not set — skipping.")
        return

    subject = subject_override or f"[HS Monitor] {len(items)} new result(s)"
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_user
    msg["To"]      = to_addr
    msg.attach(MIMEText(build_html_report(items), "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_addr, msg.as_string())
        log.info(f"Email sent to {to_addr}: {subject}")
    except Exception as e:
        log.error(f"Email failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def run():
    log.info("=" * 60)
    log.info("Holly Springs NC Police Monitor — Threat & Accountability")
    log.info("=" * 60)

    seen    = load_seen()
    all_new = []

    log.info("Scraping RSS feeds...")
    all_new += scrape_rss(seen)

    log.info("Scraping Google News...")
    all_new += scrape_google_news(seen)

    log.info("Scraping court records...")
    all_new += scrape_court_records(seen)

    log.info("Scraping accountability sources...")
    all_new += scrape_accountability_sources(seen)

    log.info("Scraping Citizen App (critical incidents only)...")
    all_new += scrape_citizen_app(seen)

    log.info("Scraping Reddit...")
    all_new += scrape_reddit(seen)

    log.info("Scraping Facebook public pages...")
    all_new += scrape_facebook_public(seen)

    log.info("Searching Google for public Facebook posts...")
    all_new += scrape_google_for_facebook(seen)

    log.info("Scraping Twitter/X via Nitter...")
    all_new += scrape_twitter_nitter(seen)

    save_seen(seen)

    high_priority = [i for i in all_new if i.get("priority")]
    log.info(f"Found {len(all_new)} new result(s), {len(high_priority)} HIGH PRIORITY.")

    # Merge newly found items into the persistent archive
    archive = load_archive()
    now_iso = datetime.now(timezone.utc).isoformat()
    new_hashes = set()
    for item in all_new:
        h = item["hash"]
        new_hashes.add(h)
        item_copy = dict(item)
        item_copy["first_seen"] = now_iso
        archive[h] = item_copy

    archive = prune_archive(archive)
    save_archive(archive)

    # Sort newest-first by first_seen for display
    display_items = sorted(archive.values(), key=lambda i: i.get("first_seen", ""), reverse=True)

    # Save HTML report
    html = build_html_report(display_items, new_hashes=new_hashes)
    REPORT_FILE.write_text(html, encoding="utf-8")
    log.info(f"Report saved: {REPORT_FILE} ({len(display_items)} item(s) in last {ARCHIVE_WINDOW_DAYS} days)")

    log.info("Done.")
    return all_new


if __name__ == "__main__":
    run()
