#!/usr/bin/env python3
"""PDPA Breach Watch collector (stdlib only).
Stores only title, link, source, date and a short snippet -- never full text or leaked data."""
import hashlib, json, re, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path

OUT = Path(__file__).parent / "docs" / "feed.json"
UA = "Mozilla/5.0 (compatible; PDPA-BreachWatch/1.0; regulatory monitoring)"
KEEP_DAYS, MIN_SCORE = 90, 2


def gn(q, lang="en"):
    hl, ceid = ("ms-MY", "MY:ms") if lang == "ms" else ("en-MY", "MY:en")
    return f"https://news.google.com/rss/search?q={urllib.parse.quote(q)}&hl={hl}&gl=MY&ceid={ceid}"


def rd(sub, q):
    return f"https://www.reddit.com/r/{sub}/search.rss?q={urllib.parse.quote(q)}&restrict_sr=1&sort=new&t=month"


# my=True -> Malaysia-focused source (adds relevance). EDIT THIS LIST to add or remove sources.
SOURCES = [
    {"name": "Google News (EN)", "type": "News", "my": True, "url": gn('Malaysia ("data breach" OR "data leak" OR ransomware OR hacked) when:7d')},
    {"name": "Google News (BM)", "type": "News", "my": True, "url": gn('kebocoran data OR "data bocor" OR digodam OR "serangan siber" when:7d', "ms")},
    {"name": "Google News (PDPA)", "type": "News", "my": True, "url": gn('PDPA OR JPDP OR NACSA "data breach" when:30d')},
    {"name": "FMT data breach tag", "type": "News", "my": True, "url": "https://www.freemalaysiatoday.com/category/tag/data-breach/feed/"},
    {"name": "Lowyat.NET", "type": "News", "my": True, "url": "https://www.lowyat.net/feed/"},
    {"name": "SoyaCincau", "type": "News", "my": True, "url": "https://soyacincau.com/feed/"},
    {"name": "Reddit r/malaysia", "type": "Reddit", "my": True, "url": rd("malaysia", "data breach OR leak OR bocor OR hacked")},
    {"name": "Reddit r/MalaysianPF", "type": "Reddit", "my": True, "url": rd("MalaysianPF", "data breach OR leak OR hacked")},
    {"name": "Reddit r/cybersecurity", "type": "Reddit", "my": False, "url": rd("cybersecurity", "Malaysia")},
    {"name": "BleepingComputer", "type": "News", "my": False, "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Record", "type": "News", "my": False, "url": "https://therecord.media/feed"},
    {"name": "SecurityWeek", "type": "News", "my": False, "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "The Hacker News", "type": "News", "my": False, "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "DataBreaches.net", "type": "News", "my": False, "url": "https://databreaches.net/feed/"},
    {"name": "ransomware.live (MY)", "type": "Tracker", "my": True, "url": "https://api.ransomware.live/v2/countryvictims/MY"},
]
TRUST = {"News": "Media report", "Reddit": "Unverified", "Tracker": "Actor claim", "Advisory": "Official"}

MY = [
    (r"\bmalaysia(n|ns)?\b", 3, "mentions Malaysia"),
    (r"\bkuala lumpur\b|\bselangor\b|\bjohor\b|\bpenang\b|\bsabah\b|\bsarawak\b|\bputrajaya\b|\bcyberjaya\b", 2, "Malaysian place"),
    (r"\.(com\.|gov\.|edu\.|org\.)?my\b", 2, ".my domain"),
    (r"\bmykad\b|\bmy ?kad\b|mydigital id", 3, "MyKad / MyDigital ID"),
    (r"\bpdpa\b|\bjpdp\b|\bnacsa\b|\bmycert\b|\bmcmc\b|cybersecurity malaysia|personal data protection", 3, "Malaysian regulator/law"),
    (r"\bbursa\b|\bringgit\b|\brm ?\d", 1, "Malaysian finance term"),
    (r"maybank|cimb|public bank|\brhb\b|hong leong|petronas|\btnb\b|telekom malaysia|\baxiata\b|\bcelcom\b|\bmaxis\b|\bsocso\b|\bperkeso\b|\bkwsp\b|\blhdn\b|malindo|batik air|airasia|touch ?n ?go", 2, "Malaysian organisation"),
    (r"kebocoran|\bbocor\b|\bpenggodam\b|serangan siber|\bdigodam\b", 2, "Bahasa Malaysia breach terms"),
]
BREACH = re.compile(r"data breach|data leak|leak(ed|s)?\b|breach(ed|es)?\b|ransomware|stolen data|data theft|exposed|kebocoran|\bbocor\b|dark ?web|infostealer|hacked|\bdigodam\b|penggodam|serangan siber|cyber ?attack", re.I)
STRONG = re.compile(r"data breach|data leak|ransomware|kebocoran|\bbocor\b|leaked", re.I)
SCAM = re.compile(r"scam|phishing|penipuan|scammer|macau", re.I)
STOP = set("the and with from after over says said malaysia malaysian data breach leak cyber attack hackers hacked this that have been will into about".split())


def score(text, my_source):
    if not BREACH.search(text) or (SCAM.search(text) and not STRONG.search(text)):
        return 0, []
    s, why = 0, []
    if my_source:
        s, why = 2, ["Malaysia-focused source"]
    for pat, w, label in MY:
        if re.search(pat, text, re.I):
            s += w
            why.append(label)
    return s, why


def fetch(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=25) as r:
        return r.read()


def ln(tag):
    return tag.rsplit("}", 1)[-1]


def parse_feed(xml_bytes):
    out = []
    for e in ET.fromstring(xml_bytes).iter():
        if ln(e.tag) not in ("item", "entry"):
            continue
        d = {}
        for c in e:
            k = ln(c.tag)
            if k == "link":
                d.setdefault("link", c.get("href") or (c.text or "").strip())
            elif k in ("title", "description", "summary", "content", "pubDate", "published", "updated", "source"):
                d.setdefault(k, (c.text or "").strip())
        out.append(d)
    return out


def pdate(s):
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)
    except Exception:
        try:
            d = datetime.fromisoformat(s.strip().replace("Z", "+00:00").replace(" ", "T"))
        except Exception:
            return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def clean(s, n=220):
    s = unescape(re.sub(r"<[^>]+>", " ", s or ""))
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s)).strip()[:n]


def norm(u):
    p = urllib.parse.urlsplit(u)
    q = [(k, v) for k, v in urllib.parse.parse_qsl(p.query) if not k.startswith("utm_")]
    return urllib.parse.urlunsplit((p.scheme, p.netloc.lower(), p.path.rstrip("/"), urllib.parse.urlencode(q), ""))


def lang(t):
    return "BM" if len(re.findall(r"\b(dan|yang|di|untuk|dengan|kebocoran|bocor|siber|akan|pada)\b", t.lower())) >= 2 else "EN"


def make(s, title, link, snip, d, sc, why, source=None):
    return {"id": hashlib.sha1(norm(link).encode()).hexdigest()[:12], "title": title, "url": link,
            "source": source or s["name"], "type": s["type"], "trust": TRUST[s["type"]],
            "date": d.isoformat(), "snippet": snip, "score": sc, "reasons": why, "lang": lang(title + " " + snip)}


def from_feed(s, cutoff):
    out = []
    for e in parse_feed(fetch(s["url"])):
        title, link = clean(e.get("title"), 200), e.get("link", "")
        d = pdate(e.get("pubDate") or e.get("published") or e.get("updated"))
        if not title or not link.startswith("http") or not d or d < cutoff:
            continue
        snip = clean(e.get("description") or e.get("summary") or e.get("content"))
        sc, why = score(title + " " + snip, s["my"])
        if sc >= MIN_SCORE:
            outlet = clean(e.get("source"), 60)
            out.append(make(s, title, link, snip, d, sc, why, f"{outlet} (Google News)" if outlet else None))
    return out


def from_tracker(s, cutoff):
    out = []
    for v in json.loads(fetch(s["url"])):
        name, grp = v.get("victim") or v.get("post_title") or "", v.get("group") or v.get("group_name") or ""
        d = pdate(v.get("discovered") or v.get("attackdate") or "")
        if not name or not d or d < cutoff:
            continue
        link = "https://www.ransomware.live/group/" + urllib.parse.quote(grp)  # never store leak-site links
        out.append(make(s, f"{name} listed by {grp} ransomware group", link, clean(v.get("description")), d, 6, ["Country = MY per tracker"]))
    return out


def toks(t):
    return {w for w in re.findall(r"[a-z0-9]{4,}", t.lower()) if w not in STOP}


def cluster(items):
    reps = []
    for it in sorted(items, key=lambda i: i["date"]):
        t, sid = toks(it["title"]), None
        for s, rt in reps:
            if t and rt and len(t & rt) / len(t | rt) >= 0.4:
                sid = s
                break
        if not sid:
            sid = it["id"]
            reps.append((sid, t))
        it["story"] = sid


def main():
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=KEEP_DAYS)
    old, oldh = {}, {}
    try:
        prev = json.loads(OUT.read_text())
        old = {i["id"]: i for i in prev.get("items", [])}
        oldh = {h["name"]: h for h in prev.get("health", [])}
    except Exception:
        pass
    items = {k: v for k, v in old.items() if pdate(v["date"]) and pdate(v["date"]) >= cutoff}
    health = []
    for s in SOURCES:
        h = {"name": s["name"], "type": s["type"], "ok": True, "count": 0, "error": "",
             "last_ok": oldh.get(s["name"], {}).get("last_ok", "")}
        try:
            got = from_tracker(s, cutoff) if s["type"] == "Tracker" else from_feed(s, cutoff)
            for it in got:
                it["first_seen"] = items.get(it["id"], {}).get("first_seen", now.isoformat())
                items[it["id"]] = it
            h["count"], h["last_ok"] = len(got), now.isoformat()
        except Exception as ex:
            h["ok"], h["error"] = False, str(ex)[:120]
        health.append(h)
        print(("OK  " if h["ok"] else "FAIL"), s["name"], h["count"], h["error"])
    lst = list(items.values())
    cluster(lst)
    lst.sort(key=lambda i: i["date"], reverse=True)
    OUT.write_text(json.dumps({"generated": now.isoformat(), "items": lst, "health": health}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
