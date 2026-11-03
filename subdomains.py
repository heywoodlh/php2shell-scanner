#!/usr/bin/env python3
"""Pure-Python passive subdomain enumeration (replaces amass).

Uses Certificate Transparency logs via crt.sh (the same public data amass'
passive data sources draw from), requires no external tools, and never
touches the target. Results are deduplicated, restricted to the queried
domain, and always include the apex domain itself.
"""

import json
import re
import socket
import sys
import time
import urllib.request

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
USER_AGENT = "php2shell-scanner"
RETRIES = 3


def _crtsh_names(domain, timeout=60):
    url = CRTSH_URL.format(domain=domain)
    data = None
    for attempt in range(1, RETRIES + 1):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            break
        except (OSError, ValueError) as exc:
            # crt.sh regularly answers 502 under load; retry with backoff.
            if attempt >= RETRIES:
                raise
            time.sleep(5 * attempt)
    if data is None:
        raise OSError("crt.sh returned no data for " + domain)
    names = set()
    for entry in data:
        for field in ("name_value", "common_name"):
            raw = entry.get(field) or ""
            # name_value entries may contain newline-separated SANs.
            for name in str(raw).split("\n"):
                names.add(name.strip().lower().lstrip("*."))
    return names


def _resolve(host):
    try:
        return socket.gethostbyname(host) is not None
    except OSError:
        return False


def enumerate_subdomains(domain, timeout=60, resolve=False, verbose=True):
    """Return a sorted list of subdomains of `domain` (apex included).

    With resolve=True, only names that actually resolve are kept; the apex
    is always kept. On any crt.sh failure the apex alone is returned (the
    caller's behavior degrades the same way amass failures did).
    """
    domain = domain.lower().strip()
    hosts = set()
    try:
        for name in _crtsh_names(domain, timeout=timeout):
            if name == domain or name.endswith("." + domain):
                if re.match(r"^[a-z0-9._-]+$", name):
                    hosts.add(name)
    except (OSError, ValueError, KeyError) as exc:
        if verbose:
            print("crt.sh enumeration failed for %s: %s"
                  % (domain, exc), file=sys.stderr)
    hosts.add(domain)
    if resolve:
        hosts = {h for h in hosts if h == domain or _resolve(h)}
    return sorted(hosts)
