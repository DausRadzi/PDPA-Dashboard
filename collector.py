#!/usr/bin/env python3
"""PDPA Breach Watch collector (stdlib only).
Stores only title, link, source, date and a short snippet -- never full text or leaked data."""
import hashlib, json, re, time, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path

OUT = Path(__file__).parent / "docs" / "feed.json"
UA = "Mozilla/5.0 (compatible; PDPA-BreachWatch/1.0; regulatory monitoring)"
KEEP_DAYS, MIN_SCORE = 90, 3
RL = "https://api.ransomware.live/v2"


def gn(q, lang="en"):
    hl, ceid = ("ms-MY", "MY:ms") if lang == "ms" else ("en-MY", "MY:en")
    return f"https://news.google.com/rss/search?q={urllib.parse.quote(q)}&hl={hl}&gl=MY&ceid={ceid}"


def rd(sub, q):
    return f"https://www.reddit.com/r/{sub}/search.rss?q={urllib.parse.quote(q)}&restrict_sr=1&sort=new&t=month"


def bing(q, mkt="en-MY"):
    return f"https://www.bing.com/news/search?q={urllib.parse.quote(q)}&format=rss&setmkt={mkt}"


def unwrap(link):
    if "bing.com/news/apiclick" in link:
        u = urllib.parse.parse_qs(urllib.parse.urlsplit(link).query).get("url")
        if u:
            return u[0]
    return link


# EDIT THIS LIST to add or remove sources. kind = how a Tracker endpoint is read.
SOURCES = [
    {"name": "Google News (EN)", "type": "News", "url": gn('Malaysia ("data breach" OR "data leak" OR ransomware OR hacked) when:7d')},
    {"name": "Google News (BM)", "type": "News", "url": gn('kebocoran data OR "data bocor" OR digodam OR "serangan siber" Malaysia when:7d', "ms")},
    {"name": "Google News (PDPA)", "type": "News", "url": gn('PDPA OR JPDP OR NACSA "data breach" when:30d')},
    {"name": "Bing News (EN)", "type": "News", "url": bing('Malaysia ("data breach" OR "data leak" OR ransomware OR hacked)')},
    {"name": "Bing News (BM)", "type": "News", "url": bing('Malaysia (kebocoran data OR "data bocor" OR digodam OR "serangan siber")', "ms-MY")},
    {"name": "Bing News (PDPA)", "type": "News", "url": bing('(PDPA OR JPDP OR NACSA) "data breach" Malaysia')},
    {"name": "Lowyat.NET", "type": "News", "url": "https://www.lowyat.net/feed/"},
    {"name": "SoyaCincau", "type": "News", "url": "https://soyacincau.com/feed/"},
    {"name": "Reddit r/malaysia", "type": "Reddit", "url": rd("malaysia", "data breach OR leak OR bocor OR hacked")},
    {"name": "Reddit r/MalaysianPF", "type": "Reddit", "url": rd("MalaysianPF", "data breach OR leak OR hacked")},
    {"name": "Reddit r/cybersecurity", "type": "Reddit", "url": rd("cybersecurity", "Malaysia")},
    {"name": "BleepingComputer", "type": "News", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Record", "type": "News", "url": "https://therecord.media/feed"},
    {"name": "SecurityWeek", "type": "News", "url": "https://feeds.feedburner.com/securityweek"},
    {"name": "The Hacker News", "type": "News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "DataBreaches.net", "type": "News", "url": "https://databreaches.net/feed/"},
    {"name": "ransomware.live victims (MY)", "type": "Tracker", "kind": "country", "url": RL + "/countryvictims/MY"},
    {"name": "ransomware.live cyberattacks (MY)", "type": "Cyberattack log", "kind": "cyber", "url": RL + "/countrycyberattacks/MY"},
    {"name": "ransomware.live search: sdn bhd", "type": "Tracker", "kind": "search", "url": RL + "/searchvictims/sdn%20bhd"},
    {"name": "ransomware.live search: berhad", "type": "Tracker", "kind": "search", "url": RL + "/searchvictims/berhad"},
    {"name": "ransomware.live search: malaysia", "type": "Tracker", "kind": "search", "url": RL + "/searchvictims/malaysia"},
]
TRUST = {"News": "Media report", "Reddit": "Unverified", "Tracker": "Actor claim", "Cyberattack log": "Media report", "Advisory": "Official"}
TRACKERS = ("Tracker", "Cyberattack log")

# (pattern, weight, label, hard). A story needs at least one HARD Malaysia signal.
MY = [
    (r"\bmalaysia(n|ns)?\b", 3, "mentions Malaysia", True),
    (r"\bkuala lumpur\b|\bselangor\b|\bjohor\b|\bpenang\b|\bsabah\b|\bsarawak\b|\bputrajaya\b|\bcyberjaya\b", 3, "Malaysian place", True),
    (r"\.(com\.|gov\.|edu\.|org\.)?my\b", 3, ".my domain", True),
    (r"\bmykad\b|\bmy ?kad\b|mydigital id", 3, "MyKad / MyDigital ID", True),
    (r"\bpdpa\b|\bjpdp\b|\bnacsa\b|\bmycert\b|\bmcmc\b|cybersecurity malaysia", 3, "Malaysian regulator/law", True),
    (r"maybank|cimb|public bank|\brhb\b|hong leong|petronas|\btnb\b|telekom malaysia|\baxiata\b|\bcelcom\b|\bmaxis\b|\bsocso\b|\bperkeso\b|\bkwsp\b|\blhdn\b|malindo|batik air|airasia|touch ?n ?go|\bsdn\.? bhd\b|\bberhad\b", 3, "Malaysian organisation", True),
    (r"\bbursa\b|\bringgit\b|\brm ?\d", 1, "Malaysian finance term", False),
    (r"kebocoran|\bbocor\b|\bpenggodam\b|serangan siber|\bdigodam\b", 1, "Bahasa Malaysia breach terms", False),
]
BREACH = re.compile(r"data breach|data leak|leaked (data|database|records|personal|customer|credential)|breach(ed|es)?\b|ransomware|stolen data|data theft|exposed (data|records|database)|data exposed|kebocoran data|data bocor|dark ?web|infostealer|hacked|\bdigodam\b|penggodam|serangan siber|cyber ?attack", re.I)
STRONG = re.compile(r"data breach|data leak|ransomware|kebocoran|\bbocor\b|leaked", re.I)
SCAM = re.compile(r"scam|phishing|penipuan|scammer|macau", re.I)
STOP = set("the and with from after over says said malaysia malaysian data breach leak cyber attack hackers hacked this that have been will into about".split())


def score(text):
    if not BREACH.search(text) or (SCAM.search(text) and not STRONG.search(text)):
        return 0, []
    s, why, hard = 0, [], False
    for pat, w, label, h in MY:
        if re.search(pat, text, re.I):
            s += w
            why.append(label)
            hard = hard or h
    return (s, why) if hard else (0, [])


def fetch(url):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=25) as r:
                return r.read()
        except Exception:
            if attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))


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


def make(s, title, link, snip, d, sc, why, source=None, **extra):
    it = {"id": hashlib.sha1(norm(link).encode()).hexdigest()[:12], "title": title, "url": link,
          "source": source or s["name"], "type": s["type"], "trust": TRUST[s["type"]],
          "date": d.isoformat(), "snippet": snip, "score": sc, "reasons": why, "lang": lang(title + " " + snip)}
    it.update(extra)
    return it


def from_feed(s, cutoff):
    out, google = [], s["name"].startswith("Google")
    for e in parse_feed(fetch(s["url"])):
        title, link = clean(e.get("title"), 200), unwrap(e.get("link", ""))
        d = pdate(e.get("pubDate") or e.get("published") or e.get("updated"))
        if not title or not link.startswith("http") or not d or d < cutoff:
            continue
        snip = "" if google else clean(e.get("description") or e.get("summary") or e.get("content"))
        text = (title.rsplit(" - ", 1)[0] if google else title) + " " + snip  # ignore outlet name
        sc, why = score(text)
        if sc >= MIN_SCORE:
            outlet = clean(e.get("source"), 60)
            out.append(make(s, title, link, snip, d, sc, why, f"{outlet} (Google News)" if outlet else None))
    return out


def g(v, *keys):
    for k in keys:
        if v.get(k):
            return str(v[k])
    return ""


def from_tracker(s, cutoff):
    data = json.loads(fetch(s["url"]))
    if isinstance(data, dict):
        data = data.get("victims") or data.get("results") or data.get("attacks") or []
    out = []
    for v in data:
        d = pdate(g(v, "discovered", "published", "date", "attackdate"))
        if not d or d < cutoff:
            continue
        if s["kind"] == "cyber":
            title = clean(g(v, "title", "victim", "name"), 200)
            link = g(v, "url", "link", "source")
            if not link.startswith("http"):
                continue
            if not title:
                continue
            out.append(make(s, title, link, clean(g(v, "summary", "description")), d, 6, ["Country = MY per ransomware.live"], group="", sector=g(v, "sector", "activity")))
            continue
        name, grp = g(v, "victim", "post_title"), g(v, "group", "group_name")
        if not name:
            continue
        site = g(v, "website", "domain").lower()
        if s["kind"] == "search":
            if not (g(v, "country").upper() == "MY" or site.endswith(".my") or re.search(r"\b(sdn\.? bhd|berhad)\b", name, re.I)):
                continue
            why = ["Malaysian company name or .my domain"]
        else:
            why = ["Country = MY per tracker"]
        link = "https://www.ransomware.live/group/" + urllib.parse.quote(grp)  # never store leak-site links
        out.append(make(s, f"{name} listed by {grp} ransomware group", link, clean(g(v, "description")), d, 6, why,
                        group=grp, sector=g(v, "activity", "sector")))
    return out


def still_ok(it):
    """Re-check retained items against the current rules so old noise is purged."""
    if it["type"] in TRACKERS:
        return True
    google = it["source"].startswith("Google") or it["source"].endswith("(Google News)")
    t = it["title"].rsplit(" - ", 1)[0] if google else it["title"]
    sc, why = score(t + " " + ("" if google else it.get("snippet", "")))
    it["score"], it["reasons"] = sc, why
    return sc >= MIN_SCORE


def toks(t):
    return {w for w in re.findall(r"[a-z0-9]{4,}", t.lower()) if w not in STOP}


def cluster(items):
    reps = []
    for it in sorted(items, key=lambda i: i["date"]):
        if it["type"] in TRACKERS:
            it["story"] = it["id"]
            continue
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
    items = {k: v for k, v in old.items() if pdate(v["date"]) and pdate(v["date"]) >= cutoff and still_ok(v)}
    health = []
    for s in SOURCES:
        h = {"name": s["name"], "type": s["type"], "ok": True, "count": 0, "error": "",
             "last_ok": oldh.get(s["name"], {}).get("last_ok", "")}
        try:
            got = from_tracker(s, cutoff) if s["type"] in TRACKERS else from_feed(s, cutoff)
            for it in got:
                it["first_seen"] = items.get(it["id"], {}).get("first_seen", now.isoformat())
                items[it["id"]] = it
            h["count"], h["last_ok"] = len(got), now.isoformat()
        except Exception as ex:
            h["ok"], h["error"] = False, str(ex)[:120]
        health.append(h)
        print(("OK  " if h["ok"] else "FAIL"), s["name"], h["count"], h["error"])
        time.sleep(3)
    lst = list(items.values())
    cluster(lst)
    lst.sort(key=lambda i: i["date"], reverse=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"generated": now.isoformat(), "items": lst, "health": health}, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
