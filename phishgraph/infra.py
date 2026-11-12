"""Live infrastructure context: domain age (RDAP) and DNS.

These lookups are shown to the user as context. They are NOT model inputs
yet: the training data has no infrastructure snapshot taken while the
phishing sites were live, and looking up dead phishing domains today would
give misleading values (see README, "Roadmap").

All lookups are cached per domain and bounded by short timeouts so the
extension stays responsive.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

import dns.resolver
import requests
from cachetools import TTLCache, cached

_RDAP = "https://rdap.org/domain/{}"
TIMEOUT = 3.0


@cached(TTLCache(maxsize=5000, ttl=24 * 3600))
def domain_age_days(domain: str) -> dict:
    try:
        r = requests.get(_RDAP.format(domain), timeout=TIMEOUT,
                         headers={"Accept": "application/rdap+json", "User-Agent": "phishgraph/1.0"})
        if r.status_code != 200:
            return {"domain_age_days": None, "registrar": None}
        data = r.json()
        created = next((e["eventDate"] for e in data.get("events", [])
                        if e.get("eventAction") == "registration"), None)
        registrar = None
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [None, []])[1]
                registrar = next((v[3] for v in vcard if v[0] == "fn"), None)
        age = None
        if created:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - dt).days
        return {"domain_age_days": age, "registrar": registrar}
    except (requests.RequestException, ValueError, KeyError, IndexError, TypeError):
        return {"domain_age_days": None, "registrar": None}


@cached(TTLCache(maxsize=5000, ttl=3600))
def dns_info(host: str) -> dict:
    res = dns.resolver.Resolver()
    res.lifetime = TIMEOUT
    try:
        ips = sorted(a.to_text() for a in res.resolve(host, "A"))
    except Exception:  # NXDOMAIN, timeout, no answer...
        ips = []
    return {"ips": ips[:5], "n_a_records": len(ips)}


_POOL = ThreadPoolExecutor(max_workers=8)
BUDGET = 2.5  # seconds the API is willing to wait in total


def lookup(domain: str, host: str, budget: float = BUDGET) -> dict:
    """Run both lookups in parallel; return whatever finished within `budget`.

    Lookups that are still running keep going in the background and fill the
    cache, so the next request for the same domain gets the full answer.
    """
    out = {"domain": domain, "domain_age_days": None, "registrar": None, "ips": [], "n_a_records": None,
           "complete": True}
    futures = [_POOL.submit(domain_age_days, domain), _POOL.submit(dns_info, host)]
    done, pending = wait(futures, timeout=budget)
    for f in done:
        out.update(f.result())
    out["complete"] = not pending
    return out
