"""Correlation detector for the mixed dnsmasq / sshd / nginx boundary log.

The old SOC rule emitted one row per failed password and per HTTP request and
alerted on every long DNS label, so the noise buried the two real incidents.
This version correlates events into behavioural chains instead:

  dns_tunnel         high-entropy, long, unique sublabels of one parent
                     domain, repeated by one client in a short window
  lateral_movement   one credential (user + publickey auth) accepted from
                     several one-off source hosts outside the stable
                     workstation pool, inside a short window
  brute_force        repeated password failures from one source against one
                     account (capability retained; sub-threshold bursts whose
                     outcome cannot be judged go to needs_review)
  path_scan          repeated blocked probes of sensitive paths from one
                     source (capability retained; sub-threshold probes go to
                     needs_review)

A finding is only raised when every signal in a rule is present. Sequences
that look suspicious but do not clear the confirmation bar are returned in
``needs_review`` with the exact information that is missing.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------

# dns_tunnel
DNS_WINDOW = timedelta(minutes=5)
DNS_MIN_QUERIES = 8            # 12 in the labelled incident
DNS_MIN_LABEL_LEN = 20         # baseline only checked "long"; we demand long + more
DNS_MIN_UNIQUE_RATIO = 0.9
DNS_MIN_ENTROPY_BITS = 3.4
DNS_VOWEL_MAX = 0.30           # encoded payloads are consonant/digit heavy
DNS_MIN_DIGIT_RATIO = 0.15     # base32/hex-style payloads carry many digits
# either a long unbroken consonant/digit run (base32) or heavy digit content
# (hex) is required; natural-language names show neither
DNS_MIN_CONSONANT_RUN = 6
DNS_HEX_DIGIT_RATIO = 0.30

# lateral_movement
LATERAL_WINDOW = timedelta(minutes=5)
LATERAL_MIN_HOSTS = 2
# A source IP only counts as a normal workstation once it has authenticated
# several times across the capture. One-off source IPs never join the pool, so
# an attacker box cannot launder itself with a single accepted login.
POOL_MIN_OBSERVATIONS = 3

# brute_force (capability rule; below the bar -> needs_review)
BRUTE_WINDOW = timedelta(minutes=5)
BRUTE_MIN_FAILURES = 5

# path_scan (capability rule; below the bar -> needs_review)
SCAN_WINDOW = timedelta(minutes=5)
SCAN_MIN_HITS = 4
SENSITIVE_PATHS = re.compile(
    r"(?:^|/)(?:\.env|\.git|admin|administrator|wp-admin|phpmyadmin|config"
    r"|backup|\.ssh|etc/passwd|shell|cmd|actuator|server-status)",
    re.IGNORECASE,
)
BLOCKED_STATUS = {"401", "403", "404"}

# ---------------------------------------------------------------------------
# Line parsing
# ---------------------------------------------------------------------------

RE_DNS = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+dnsmasq\[\d+\]:\s+"
    r"query\[(?P<qtype>[A-Z]+)\]\s+(?P<qname>\S+)\s+from\s+(?P<ip>[\d.]+)"
)
RE_SSH_OK = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted\s+(?P<auth>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)"
)
RE_SSH_FAIL = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)"
)
RE_NGINX = re.compile(
    r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+nginx:\s+'
    r'(?P<ip>[\d.]+)\s+-\s+-\s+"(?P<path>\S+)(?:\s+\S+)?"\s+(?P<status>\d{3})'
)

# syslog lines carry no year; pin it so datetime math works across month ends.
def _parse_ts(raw: str, year: int | None = None) -> datetime:
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")


def parse_log(path: str) -> list[dict]:
    """Turn raw lines into typed events. Unknown lines are ignored."""
    events: list[dict] = []
    year: int | None = None
    with open(path, encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if year is None:
                year = datetime.now().year
            for kind, regex in (
                ("dns", RE_DNS),
                ("ssh_accept", RE_SSH_OK),
                ("ssh_fail", RE_SSH_FAIL),
                ("http", RE_NGINX),
            ):
                m = regex.match(line)
                if not m:
                    continue
                gd = m.groupdict()
                event = {
                    "kind": kind,
                    "line": line_no,
                    "ts": _parse_ts(gd["ts"], year),
                    "raw": line,
                    "ip": gd["ip"],
                }
                if kind == "dns":
                    event.update(qtype=gd["qtype"], qname=gd["qname"])
                elif kind == "ssh_accept":
                    event.update(auth=gd["auth"], user=gd["user"])
                elif kind == "ssh_fail":
                    event.update(user=gd["user"])
                elif kind == "http":
                    event.update(path=gd["path"], status=gd["status"])
                events.append(event)
                break
    return events


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _chain(events: list[dict]) -> list[dict]:
    """Numbered event chain, ordered as it happened."""
    return [
        {
            "seq": idx,
            "line": ev["line"],
            "timestamp": ev["ts"].strftime("%b %d %H:%M:%S"),
            "event": ev["kind"],
            "ip": ev["ip"],
            "detail": _detail(ev),
        }
        for idx, ev in enumerate(events, start=1)
    ]


def _detail(ev: dict) -> str:
    if ev["kind"] == "dns":
        return f'query[{ev["qtype"]}] {ev["qname"]}'
    if ev["kind"] == "ssh_accept":
        return f'accepted {ev["auth"]} for {ev["user"]}'
    if ev["kind"] == "ssh_fail":
        return f'failed password for {ev["user"]}'
    if ev["kind"] == "http":
        return f'{ev["path"]} -> {ev["status"]}'
    return ev["kind"]


def _window(events: list[dict]) -> tuple[str, str, int]:
    first, last = events[0]["ts"], events[-1]["ts"]
    span = int((last - first).total_seconds())
    return (
        first.strftime("%b %d %H:%M:%S"),
        last.strftime("%b %d %H:%M:%S"),
        span,
    )


def _finding(rule: str, severity: str, events: list[dict],
             entities: dict, summary: str, signals: list[str]) -> dict:
    first, last, span = _window(events)
    return {
        "rule": rule,
        "severity": severity,
        "first_seen": first,
        "last_seen": last,
        "window_seconds": span,
        "entities": entities,
        "summary": summary,
        "signals": signals,
        "evidence": _chain(events),
    }


# ---------------------------------------------------------------------------
# Rule 1: DNS tunnelling / data exfiltration
# ---------------------------------------------------------------------------

def _dns_groups(events: list[dict]) -> dict[tuple, list[dict]]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["kind"] != "dns":
            continue
        labels = ev["qname"].rstrip(".").split(".")
        if len(labels) < 2:
            continue
        encoded = labels[0]
        parent = ".".join(labels[1:])
        groups[(ev["ip"], parent)].append(
            {**ev, "encoded_label": encoded}
        )
    return groups


def detect_dns_tunnel(events: list[dict]) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    reviews: list[dict] = []
    for (client, parent), group in sorted(_dns_groups(events).items()):
        group.sort(key=lambda e: e["ts"])
        # sliding window over the client+parent stream
        lo = 0
        best: list[dict] = []
        for hi in range(len(group)):
            while group[hi]["ts"] - group[lo]["ts"] > DNS_WINDOW:
                lo += 1
            window = group[lo:hi + 1]
            if len(window) > len(best):
                best = window
        if len(best) < 2:
            continue

        labels = [e["encoded_label"] for e in best]
        unique_ratio = len(set(labels)) / len(labels)
        long_enough = sum(len(x) >= DNS_MIN_LABEL_LEN for x in labels) / len(labels)
        avg_entropy = sum(_shannon_entropy(x) for x in labels) / len(labels)
        avg_vowel = sum(
            sum(c in "aeiou" for c in x) / len(x) for x in labels
        ) / len(labels)
        avg_digit = sum(
            sum(c.isdigit() for c in x) / len(x) for x in labels
        ) / len(labels)
        # longest unbroken run of consonants/digits in any label
        longest_run = max(
            (len(m.group(0))
             for x in labels
             for m in re.finditer(r"[bcdfghjklmnpqrstvwxz0-9]+", x)),
            default=0,
        )
        # base32-style payloads have long consonant/digit runs; hex-style
        # payloads alternate but are digit-dense. Require one of the two.
        encoded_shape = (
            longest_run >= DNS_MIN_CONSONANT_RUN
            or avg_digit >= DNS_HEX_DIGIT_RATIO
        )

        signals = [
            f"{len(best)} queries in {int((best[-1]['ts']-best[0]['ts']).total_seconds())}s window",
            f"{long_enough:.0%} of leading labels >= {DNS_MIN_LABEL_LEN} chars",
            f"unique-label ratio {unique_ratio:.2f}",
            f"mean Shannon entropy {avg_entropy:.2f} bits/char",
            f"mean vowel ratio {avg_vowel:.2f}, mean digit ratio {avg_digit:.2f}",
            f"longest consonant/digit run {longest_run} chars",
        ]
        confirmed = (
            len(best) >= DNS_MIN_QUERIES
            and long_enough >= 0.9
            and unique_ratio >= DNS_MIN_UNIQUE_RATIO
            and avg_entropy >= DNS_MIN_ENTROPY_BITS
            and avg_vowel <= DNS_VOWEL_MAX
            and avg_digit >= DNS_MIN_DIGIT_RATIO
            and encoded_shape
        )
        entities = {
            "client_ips": [client],
            "domains": [parent],
            "users": [],
            "hosts": [],
        }
        if confirmed:
            findings.append(_finding(
                "dns_tunnel", "high", best, entities,
                f"{len(best)} encoded lookups of {parent} from {client} "
                "carry high-entropy unique payload labels - DNS exfiltration",
                signals,
            ))
            continue

        # Only escalate to needs_review when the labels are at least payload
        # *shaped* (long or encoded-looking). Plain short, readable service
        # names are normal traffic, not a borderline tunnel candidate.
        anomalous = [
            long_enough >= 0.9,
            avg_entropy >= DNS_MIN_ENTROPY_BITS,
            encoded_shape,
        ]
        if not any(anomalous):
            continue

        missing = []
        if len(best) < DNS_MIN_QUERIES:
            missing.append(
                f"query volume {len(best)} < {DNS_MIN_QUERIES}; need a longer "
                "capture to establish a sustained exfil channel")
        if long_enough < 0.9:
            missing.append("most labels are short; payload-size evidence absent")
        if unique_ratio < DNS_MIN_UNIQUE_RATIO:
            missing.append("labels repeat; could be normal polling/retries")
        if avg_entropy < DNS_MIN_ENTROPY_BITS:
            missing.append(
                "label entropy is low; consistent with human-readable service "
                "names rather than encoded data")
        if avg_vowel > DNS_VOWEL_MAX:
            missing.append(
                "vowel ratio looks like natural language; need resolved-IP / "
                "response-size data to rule out a normal service lookup")
        if avg_digit < DNS_MIN_DIGIT_RATIO:
            missing.append(
                "labels contain almost no digits; base32/hex exfil payloads do")
        if not encoded_shape:
            missing.append(
                "neither a long consonant/digit run nor hex-level digit density; "
                "the shape matches words, not encoded chunks")
        reviews.append(_review(
            "dns_suspicious", best, entities,
            f"unusual DNS pattern for {parent} from {client} but tunnel not confirmed",
            missing,
        ))
    return findings, reviews


# ---------------------------------------------------------------------------
# Rule 2: lateral movement with one credential across hosts
# ---------------------------------------------------------------------------

def detect_lateral_movement(events: list[dict]) -> tuple[list[dict], list[dict]]:
    accepts = sorted(
        (e for e in events if e["kind"] == "ssh_accept"),
        key=lambda e: e["ts"],
    )

    # Build the global stable workstation pool from the full capture: nightly
    # batch jobs authenticate from the same workstations over and over, while
    # an intrusion touches a fresh box once and moves on. The pool is global
    # (not per user) because every workstation is shared by several accounts;
    # one-off source IPs never join, so an attacker box cannot launder itself
    # with a single accepted login.
    source_counts: Counter = Counter(ev["ip"] for ev in accepts)
    pool = {ip for ip, n in source_counts.items() if n >= POOL_MIN_OBSERVATIONS}

    findings: list[dict] = []
    reviews: list[dict] = []
    by_user: dict[str, list[dict]] = defaultdict(list)
    for ev in accepts:
        by_user[ev["user"]].append(ev)

    for user, user_events in sorted(by_user.items()):
        # accepts from source hosts that never became part of the stable pool
        outsiders = [e for e in user_events if e["ip"] not in pool]
        # maximal non-overlapping clusters inside the movement window
        clusters: list[list[dict]] = []
        cluster: list[dict] = []
        for ev in outsiders:
            if cluster and ev["ts"] - cluster[0]["ts"] > LATERAL_WINDOW:
                clusters.append(cluster)
                cluster = []
            cluster.append(ev)
        if cluster:
            clusters.append(cluster)

        for cluster in clusters:
            hosts = sorted({e["ip"] for e in cluster})
            if len(hosts) < LATERAL_MIN_HOSTS:
                continue
            # anchor the chain on the user's surrounding activity in the window
            anchor = [
                e for e in user_events
                if cluster[0]["ts"] - LATERAL_WINDOW <= e["ts"] <= cluster[-1]["ts"]
            ]
            chain = sorted(anchor or cluster, key=lambda e: e["ts"])
            auth_methods = sorted({e["auth"] for e in cluster})
            signals = [
                f"credential '{user}' accepted from {len(hosts)} source hosts "
                "absent from the stable workstation pool",
                f"hosts: {', '.join(hosts)}",
                f"stable pool holds {len(pool)} hosts (each >= "
                f"{POOL_MIN_OBSERVATIONS} authentications), "
                f"e.g. {sorted(pool)[:3]}",
                "movement completed in "
                f"{int((cluster[-1]['ts']-cluster[0]['ts']).total_seconds())}s",
                f"auth method(s): {', '.join(auth_methods)}",
            ]
            entities = {
                "client_ips": hosts,
                "domains": [],
                "users": [user],
                "hosts": hosts,
            }
            if len(auth_methods) == 1 and "publickey" in auth_methods:
                findings.append(_finding(
                    "lateral_movement", "high", chain, entities,
                    f"same public-key credential '{user}' used on {len(hosts)} "
                    "non-pool hosts inside one short window - lateral movement",
                    signals,
                ))
            else:
                reviews.append(_review(
                    "lateral_movement", chain, entities,
                    f"credential '{user}' reused on non-pool hosts but auth methods differ",
                    ["mixed/unknown auth methods; sshd key fingerprint or session "
                     "log needed to prove it is the same credential rather than "
                     "independent password logins"],
                ))
    return _dedupe(findings), reviews


# ---------------------------------------------------------------------------
# Rule 3 (capability): brute-force password guessing
# ---------------------------------------------------------------------------

def detect_brute_force(events: list[dict]) -> tuple[list[dict], list[dict]]:
    failures = [e for e in events if e["kind"] == "ssh_fail"]
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for ev in failures:
        groups[(ev["ip"], ev["user"])].append(ev)

    findings: list[dict] = []
    reviews: list[dict] = []
    for (ip, user), group in sorted(groups.items()):
        group.sort(key=lambda e: e["ts"])
        lo = 0
        best: list[dict] = []
        for hi in range(len(group)):
            while group[hi]["ts"] - group[lo]["ts"] > BRUTE_WINDOW:
                lo += 1
            if hi - lo + 1 > len(best):
                best = group[lo:hi + 1]
        if not best:
            continue
        # what happened afterwards from the same source?
        later_accept = next(
            (e for e in events
             if e["kind"] == "ssh_accept" and e["ip"] == ip
             and e["user"] == user and e["ts"] >= best[-1]["ts"]),
            None,
        )
        chain = best + ([later_accept] if later_accept else [])
        entities = {"client_ips": [ip], "domains": [], "users": [user], "hosts": [ip]}
        span = int((best[-1]["ts"] - best[0]["ts"]).total_seconds())
        signals = [
            f"{len(best)} failed password attempts in {span}s from one source",
            "outcome: " + (
                f"successful {later_accept['auth']} login at "
                f"{later_accept['ts'].strftime('%H:%M:%S')}"
                if later_accept else "no successful login observed in log"),
        ]
        if len(best) >= BRUTE_MIN_FAILURES:
            findings.append(_finding(
                "brute_force",
                "high" if later_accept else "medium",
                chain, entities,
                f"{len(best)} password failures for '{user}' from {ip}"
                + (" followed by a successful login - likely compromise"
                   if later_accept else " - brute-force spraying"),
                signals,
            ))
        else:
            missing = [
                f"only {len(best)} failures in window (< {BRUTE_MIN_FAILURES}); "
                "volume alone does not clear the brute-force bar"]
            if later_accept:
                missing.append(
                    "a success followed the failures, but without key/password "
                    "change records we cannot tell a fat-fingered admin from a "
                    "guessed password - need IAM ticket or credential-rotation data")
            else:
                missing.append(
                    "no success observed; need longer retention or upstream "
                    "block/IDS data to decide whether the probe continued elsewhere")
            reviews.append(_review(
                "brute_force", chain, entities,
                f"small failure burst for '{user}' from {ip}, outcome undecidable",
                missing,
            ))
    return findings, reviews


# ---------------------------------------------------------------------------
# Rule 4 (capability): sensitive-path scanning
# ---------------------------------------------------------------------------

def detect_path_scan(events: list[dict]) -> tuple[list[dict], list[dict]]:
    probes: dict[str, list[dict]] = defaultdict(list)
    for ev in events:
        if ev["kind"] != "http":
            continue
        if SENSITIVE_PATHS.search(ev["path"]) and ev["status"] in BLOCKED_STATUS:
            probes[ev["ip"]].append(ev)

    findings: list[dict] = []
    reviews: list[dict] = []
    for ip, group in sorted(probes.items()):
        group.sort(key=lambda e: e["ts"])
        lo = 0
        best: list[dict] = []
        for hi in range(len(group)):
            while group[hi]["ts"] - group[lo]["ts"] > SCAN_WINDOW:
                lo += 1
            if hi - lo + 1 > len(best):
                best = group[lo:hi + 1]
        paths = sorted({e["path"] for e in best})
        entities = {"client_ips": [ip], "domains": [], "users": [], "hosts": [ip]}
        signals = [
            f"{len(best)} blocked requests to {len(paths)} distinct sensitive paths",
            f"paths: {', '.join(paths)}",
            f"statuses: {', '.join(sorted({e['status'] for e in best}))}",
        ]
        if len(best) >= SCAN_MIN_HITS:
            findings.append(_finding(
                "path_scan", "medium", best, entities,
                f"{ip} probed {len(paths)} sensitive paths, all blocked",
                signals,
            ))
        else:
            reviews.append(_review(
                "path_scan", best, entities,
                f"{ip} requested {len(best)} sensitive path(s), below scan threshold",
                [f"only {len(best)} probe(s) (< {SCAN_MIN_HITS}); a single typo or "
                 "manual admin click looks identical - need WAF/edge logs or more "
                 "retention to see whether the enumeration continued"]))
    return findings, reviews


# ---------------------------------------------------------------------------
# needs_review + bookkeeping
# ---------------------------------------------------------------------------

def _review(rule: str, events: list[dict], entities: dict,
            reason: str, missing_info: list[str]) -> dict:
    first, last, span = _window(events)
    return {
        "rule": rule,
        "first_seen": first,
        "last_seen": last,
        "window_seconds": span,
        "entities": entities,
        "reason": reason,
        "missing_information": missing_info,
        "evidence": _chain(events),
    }


def _dedupe(findings: list[dict]) -> list[dict]:
    """Sliding windows can emit the same cluster at several end positions."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for f in sorted(findings, key=lambda x: (x["first_seen"], x["rule"])):
        key = (f["rule"], f["first_seen"], f["last_seen"],
               tuple(f["entities"].get("client_ips", [])),
               tuple(f["entities"].get("users", [])),
               tuple(f["entities"].get("domains", [])))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def scan(path: str) -> dict:
    events = parse_log(path)
    findings: list[dict] = []
    needs_review: list[dict] = []
    for detector in (
        detect_dns_tunnel,
        detect_lateral_movement,
        detect_brute_force,
        detect_path_scan,
    ):
        f, r = detector(events)
        findings.extend(f)
        needs_review.extend(r)
    findings = _dedupe(findings)
    needs_review = _dedupe(needs_review)
    findings.sort(key=lambda x: (x["first_seen"], x["rule"]))
    needs_review.sort(key=lambda x: (x["first_seen"], x["rule"]))
    return {"findings": findings, "needs_review": needs_review}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(
        f"{len(result['findings'])} findings, "
        f"{len(result['needs_review'])} needs_review -> {sys.argv[2]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
