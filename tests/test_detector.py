import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")
DETECTOR = os.path.join(ROOT, "detector", "detector.py")

sys.path.insert(0, os.path.join(ROOT, "detector"))
import detector  # noqa: E402


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, DETECTOR, log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def _result(tmp_path, log=LOG):
    r, out = run(tmp_path, log)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# harness basics
# --------------------------------------------------------------------------

def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 2


def test_detector_runs(tmp_path):
    result = _result(tmp_path)
    assert "findings" in result
    assert "needs_review" in result


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    result = _result(tmp_path, str(empty))
    assert result == {"findings": [], "needs_review": []}


# --------------------------------------------------------------------------
# required output schema (rule, first_seen, last_seen, entities, evidence)
# --------------------------------------------------------------------------

def test_findings_have_required_fields(tmp_path):
    result = _result(tmp_path)
    assert result["findings"], "labelled incidents must produce findings"
    for f in result["findings"]:
        assert f["rule"]
        assert f["first_seen"] and f["last_seen"]
        assert f["last_seen"] >= f["first_seen"]
        assert set(f["entities"]) == {"client_ips", "domains", "users", "hosts"}
        assert isinstance(f["evidence"], list) and f["evidence"]


def test_evidence_chain_is_sequential(tmp_path):
    result = _result(tmp_path)
    for f in result["findings"] + result["needs_review"]:
        seqs = [e["seq"] for e in f["evidence"]]
        assert seqs == list(range(1, len(seqs) + 1))
        lines = [e["line"] for e in f["evidence"]]
        assert lines == sorted(lines)
        for e in f["evidence"]:
            assert e["timestamp"] and e["event"] and e["ip"] and e["detail"]


# --------------------------------------------------------------------------
# labels.json: every labelled event is hit, exactly
# --------------------------------------------------------------------------

def test_labelled_events_all_detected(tmp_path):
    result = _result(tmp_path)
    rules = {f["rule"]: f for f in result["findings"]}
    assert set(rules) == {"dns_tunnel", "lateral_movement"}

    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)["events"]

    dns = rules["dns_tunnel"]
    dns_label = next(e for e in labels if e["kind"] == "dns_tunnel")
    assert dns_label["ip"] in dns["entities"]["client_ips"]
    assert dns_label["evidence"].split()[0] == str(len(dns["evidence"]))  # 12 queries
    assert all(dns_label["ip"] == e["ip"] for e in dns["evidence"])
    assert all(e["event"] == "dns" for e in dns["evidence"])

    lm = rules["lateral_movement"]
    lm_label = next(e for e in labels if e["kind"] == "lateral_movement")
    assert lm["entities"]["client_ips"] == lm_label["ips"]
    assert lm_label["user"] in lm["entities"]["users"]
    assert lm["window_seconds"] <= 300
    assert [e["ip"] for e in lm["evidence"]] == lm_label["ips"]


def test_zero_false_positives_on_benign_traffic(tmp_path):
    # The corpus intentionally contains unlabelled benign look-alikes
    # (3 failed passwords then a success; 2 blocked sensitive-path probes).
    # None of them may appear as findings.
    result = _result(tmp_path)
    assert len(result["findings"]) == 2
    flagged_ips = {
        ip for f in result["findings"] for ip in f["entities"]["client_ips"]
    }
    assert flagged_ips == {"10.20.1.51", "10.20.1.52"}
    # the 840 lines of nightly batch traffic (pool IPs .10-.39, GET / 200)
    # never produce a finding
    assert not any(
        any(ip.endswith(tuple(f".{n}" for n in range(10, 40)))
            for ip in f["entities"]["client_ips"])
        for f in result["findings"]
    )


# --------------------------------------------------------------------------
# needs_review: undecidable sequences with the missing information stated
# --------------------------------------------------------------------------

def test_lookalikes_go_to_needs_review(tmp_path):
    result = _result(tmp_path)
    reviews = {r["rule"]: r for r in result["needs_review"]}
    assert set(reviews) == {"brute_force", "path_scan"}

    bf = reviews["brute_force"]
    assert bf["entities"]["client_ips"] == ["10.20.1.77"]
    assert bf["missing_information"]  # must state what is missing
    # the full chain, including the later success, is preserved
    assert [e["event"] for e in bf["evidence"]].count("ssh_fail") == 3
    assert bf["evidence"][-1]["event"] == "ssh_accept"

    ps = reviews["path_scan"]
    assert ps["entities"]["client_ips"] == ["10.20.1.88"]
    assert {e["detail"] for e in ps["evidence"]} == {
        "/admin -> 403", "/.env -> 403"}
    assert ps["missing_information"]


# --------------------------------------------------------------------------
# retained capabilities: brute force and path scan still fire on strong cases
# --------------------------------------------------------------------------

def _write(tmp_path, lines):
    path = tmp_path / "synthetic.log"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def test_brute_force_still_detected_above_threshold(tmp_path):
    lines = [
        f"Oct 01 10:00:{i:02d} web01 sshd[1000]: Failed password for root "
        f"from 10.20.9.9 port 4000{i} ssh2"
        for i in range(6)
    ]
    result = detector.scan(_write(tmp_path, lines))
    rules = [f["rule"] for f in result["findings"]]
    assert "brute_force" in rules
    bf = next(f for f in result["findings"] if f["rule"] == "brute_force")
    assert len(bf["evidence"]) == 6
    assert bf["entities"]["users"] == ["root"]
    assert result["needs_review"] == []


def test_brute_force_success_escalates(tmp_path):
    lines = [
        "Oct 01 10:00:00 web01 sshd[1000]: Failed password for root "
        "from 10.20.9.9 port 40001 ssh2",
        "Oct 01 10:00:10 web01 sshd[10000]: Accepted password for root "
        "from 10.20.9.9 port 40002 ssh2",
    ]
    result = detector.scan(_write(tmp_path, lines))
    # one failure is not brute force; it must be reviewed, not alerted
    assert result["findings"] == []
    assert len(result["needs_review"]) == 1


def test_path_scan_still_detected_above_threshold(tmp_path):
    paths = ["/admin", "/.env", "/.git/config", "/wp-admin", "/phpmyadmin"]
    lines = [
        f'Oct 01 11:00:0{i} web01 nginx: 10.20.9.10 - - "{p}" 403 10 "x"'
        for i, p in enumerate(paths)
    ]
    result = detector.scan(_write(tmp_path, lines))
    rules = [f["rule"] for f in result["findings"]]
    assert "path_scan" in rules
    ps = next(f for f in result["findings"] if f["rule"] == "path_scan")
    assert len(ps["evidence"]) == 5


def test_benign_200_traffic_never_alarms(tmp_path):
    lines = [
        f'Oct 01 12:00:0{i} web01 nginx: 10.20.1.{10+i} - - "/" 200 500 "Mozilla"'
        for i in range(5)
    ]
    result = detector.scan(_write(tmp_path, lines))
    assert result == {"findings": [], "needs_review": []}


# --------------------------------------------------------------------------
# rule logic unit checks
# ---------------------------------------------------------------------------

def test_dns_tunnel_ignores_human_readable_labels(tmp_path):
    # long labels alone must not trigger: readable, low-entropy names
    lines = [
        f"Oct 01 13:00:0{i} web01 dnsmasq[811]: query[A] "
        f"service-node-number-{i:02d}.cluster.internal from 10.20.1.10"
        for i in range(10)
    ]
    result = detector.scan(_write(tmp_path, lines))
    assert not any(f["rule"] == "dns_tunnel" for f in result["findings"])


def test_lateral_movement_ignores_pool_rotation(tmp_path):
    # same user, short gaps, but every source IP is a recurring workstation
    lines = []
    for i in range(6):
        ip = f"10.20.1.{10 + (i % 5)}"
        for _ in range(4):  # make each IP a well-established pool member
            lines.append(
                f"Oct 01 14:{i:02d}:00 web01 sshd[10000]: Accepted publickey "
                f"for ops from {ip} port 50000 ssh2")
    result = detector.scan(_write(tmp_path, lines))
    assert not any(
        f["rule"] == "lateral_movement" for f in result["findings"])


def test_lateral_movement_fires_on_two_one_off_hosts(tmp_path):
    lines = [
        # establish a normal pool first
        "Oct 01 15:00:00 web01 sshd[10000]: Accepted publickey "
        "for ops from 10.20.1.10 port 50001 ssh2",
        "Oct 01 15:00:30 web01 sshd[10000]: Accepted publickey "
        "for ops from 10.20.1.10 port 50002 ssh2",
        "Oct 01 15:01:00 web01 sshd[10000]: Accepted publickey "
        "for ops from 10.20.1.10 port 50003 ssh2",
        # one credential on two fresh hosts within seconds
        "Oct 01 15:10:00 web01 sshd[10000]: Accepted publickey "
        "for ops from 10.20.7.1 port 50004 ssh2",
        "Oct 01 15:10:20 web01 sshd[10000]: Accepted publickey "
        "for ops from 10.20.7.2 port 50005 ssh2",
    ]
    result = detector.scan(_write(tmp_path, lines))
    lm = [f for f in result["findings"] if f["rule"] == "lateral_movement"]
    assert len(lm) == 1
    assert lm[0]["entities"]["client_ips"] == ["10.20.7.1", "10.20.7.2"]
    assert lm[0]["entities"]["users"] == ["ops"]
