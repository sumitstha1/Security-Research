#!/usr/bin/env python3
"""
log_analyzer.py — Security Log Analysis Starter Script
=======================================================
Parse and triage common security-relevant log formats:
  - auth.log  (SSH login attempts, sudo usage, PAM events)
  - syslog    (general system messages)
  - apache    (Apache/Nginx combined access log format)

Usage
-----
    python3 log_analyzer.py --file /var/log/auth.log --type auth
    python3 log_analyzer.py --file access.log --type apache --top 20
    python3 log_analyzer.py --file /var/log/syslog --type syslog

Author : Security-Research Portfolio
Licence: MIT
"""

import argparse
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

PATTERNS = {
    "auth": {
        "failed_ssh": re.compile(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
        ),
        "accepted_ssh": re.compile(
            r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"
        ),
        "sudo": re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)"),
        "invalid_user": re.compile(r"Invalid user (\S+) from ([\d.]+)"),
    },
    "apache": {
        # Combined Log Format: IP - - [date] "METHOD /path HTTP/1.x" status bytes
        "request": re.compile(
            r'([\d.]+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]+) HTTP/[\d.]+" (\d{3}) (\d+|-)'
        ),
    },
    "syslog": {
        # Generic syslog line: Month DD HH:MM:SS hostname process[pid]: message
        "line": re.compile(
            r"(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (\S+?)(?:\[(\d+)\])?: (.+)"
        ),
        "error": re.compile(r"\b(error|critical|fatal|panic|emerg)\b", re.IGNORECASE),
        "warning": re.compile(r"\b(warn(?:ing)?)\b", re.IGNORECASE),
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def read_log(filepath: str) -> list[str]:
    """Read a log file and return its lines, skipping undecodable bytes."""
    path = Path(filepath)
    if not path.exists():
        print(f"[ERROR] File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    with path.open(encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def print_section(title: str) -> None:
    width = 60
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def print_counter(counter: Counter, label: str, top: int) -> None:
    """Pretty-print the top N entries of a Counter."""
    print_section(label)
    if not counter:
        print("  (none found)")
        return
    for item, count in counter.most_common(top):
        print(f"  {count:>6}  {item}")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def analyze_auth(lines: list[str], top: int, threshold: int = 10) -> None:
    """Parse auth.log style entries."""
    failed_users: Counter = Counter()
    failed_ips: Counter = Counter()
    accepted_users: Counter = Counter()
    accepted_ips: Counter = Counter()
    sudo_users: Counter = Counter()
    invalid_users: Counter = Counter()

    for line in lines:
        if m := PATTERNS["auth"]["failed_ssh"].search(line):
            failed_users[m.group(1)] += 1
            failed_ips[m.group(2)] += 1

        if m := PATTERNS["auth"]["accepted_ssh"].search(line):
            accepted_users[m.group(1)] += 1
            accepted_ips[m.group(2)] += 1

        if m := PATTERNS["auth"]["sudo"].search(line):
            sudo_users[m.group(1)] += 1

        if m := PATTERNS["auth"]["invalid_user"].search(line):
            invalid_users[m.group(1)] += 1

    total_failed = sum(failed_ips.values())
    total_accepted = sum(accepted_ips.values())

    print_section("AUTH LOG SUMMARY")
    print(f"  Total lines processed : {len(lines)}")
    print(f"  Failed SSH attempts   : {total_failed}")
    print(f"  Accepted SSH logins   : {total_accepted}")

    print_counter(failed_ips, f"Top {top} IPs — Failed SSH Attempts", top)
    print_counter(failed_users, f"Top {top} Usernames — Failed SSH Attempts", top)
    print_counter(accepted_ips, f"Top {top} IPs — Successful SSH Logins", top)
    print_counter(invalid_users, f"Top {top} Invalid Usernames Attempted", top)
    print_counter(sudo_users, f"Top {top} Users Running sudo Commands", top)

    # Brute-force alert threshold
    print_section(f"⚠  BRUTE-FORCE ALERTS (>= {threshold} attempts)")
    alerted = False
    for ip, count in failed_ips.items():
        if count >= threshold:
            print(f"  [ALERT] {ip} — {count} failed attempts (threshold: {threshold})")
            alerted = True
    if not alerted:
        print(f"  No IPs exceeded the {threshold}-attempt threshold.")


def analyze_apache(lines: list[str], top: int) -> None:
    """Parse Apache/Nginx combined access log entries."""
    status_counter: Counter = Counter()
    ip_counter: Counter = Counter()
    path_counter: Counter = Counter()
    method_counter: Counter = Counter()
    error_4xx: Counter = Counter()
    error_5xx: Counter = Counter()

    pattern = PATTERNS["apache"]["request"]

    for line in lines:
        m = pattern.search(line)
        if not m:
            continue
        ip, _date, method, path, status, _size = m.groups()
        status_counter[status] += 1
        ip_counter[ip] += 1
        path_counter[path] += 1
        method_counter[method] += 1
        if status.startswith("4"):
            error_4xx[f"{status} {ip} {path}"] += 1
        elif status.startswith("5"):
            error_5xx[f"{status} {ip} {path}"] += 1

    print_section("APACHE ACCESS LOG SUMMARY")
    print(f"  Total lines processed : {len(lines)}")

    print_counter(status_counter, "HTTP Status Code Breakdown", top)
    print_counter(method_counter, "HTTP Methods", top)
    print_counter(ip_counter, f"Top {top} Client IPs", top)
    print_counter(path_counter, f"Top {top} Requested Paths", top)
    print_counter(error_4xx, f"Top {top} 4xx Errors (status IP path)", top)
    print_counter(error_5xx, f"Top {top} 5xx Errors (status IP path)", top)


def analyze_syslog(lines: list[str], top: int) -> None:
    """Parse generic syslog entries."""
    process_counter: Counter = Counter()
    error_counter: Counter = Counter()
    warning_counter: Counter = Counter()

    line_pattern = PATTERNS["syslog"]["line"]
    error_pattern = PATTERNS["syslog"]["error"]
    warning_pattern = PATTERNS["syslog"]["warning"]

    errors: list[str] = []
    warnings: list[str] = []

    for line in lines:
        m = line_pattern.match(line)
        if not m:
            continue
        _timestamp, _host, process, _pid, message = m.groups()
        process_counter[process] += 1

        if error_pattern.search(message):
            errors.append(line.rstrip())
            error_counter[process] += 1
        elif warning_pattern.search(message):
            warnings.append(line.rstrip())
            warning_counter[process] += 1

    print_section("SYSLOG SUMMARY")
    print(f"  Total lines processed : {len(lines)}")
    print(f"  Error-level lines     : {len(errors)}")
    print(f"  Warning-level lines   : {len(warnings)}")

    print_counter(process_counter, f"Top {top} Processes by Log Volume", top)
    print_counter(error_counter, f"Top {top} Processes with Errors", top)
    print_counter(warning_counter, f"Top {top} Processes with Warnings", top)

    print_section(f"Most Recent {top} Error Lines")
    for line in errors[-top:]:
        print(f"  {line}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log_analyzer.py",
        description="Security log analysis starter script — auth, apache, syslog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        metavar="PATH",
        help="Path to the log file to analyse",
    )
    parser.add_argument(
        "--type", "-t",
        required=True,
        choices=["auth", "apache", "syslog"],
        help="Log format type",
    )
    parser.add_argument(
        "--top", "-n",
        type=int,
        default=10,
        metavar="N",
        help="Number of top results to display per category (default: 10)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        metavar="N",
        help="Failed-attempt count that triggers a brute-force alert (default: 10)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    print(f"\n[*] Log Analyzer — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] File : {args.file}")
    print(f"[*] Type : {args.type}")
    print(f"[*] Top  : {args.top}")

    lines = read_log(args.file)

    if args.type == "auth":
        analyze_auth(lines, args.top, args.threshold)
    elif args.type == "apache":
        analyze_apache(lines, args.top)
    elif args.type == "syslog":
        analyze_syslog(lines, args.top)

    print(f"\n[*] Analysis complete.\n")


if __name__ == "__main__":
    main()
