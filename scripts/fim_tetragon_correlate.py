#!/var/ossec/framework/python/bin/python3
"""Lab-only FIM + Tetragon correlation, invoked by a stateless Active Response.

No endpoint commands, blocking, network HTTP calls, or file-content collection.
Default invocation consumes one AR JSON line. --replay-stdin uses only memory,
does not access the Wazuh socket, and accepts original alert JSON lines.
See README.md for identity limits, installation gates and delivery semantics.
"""

import argparse
import hashlib
import json
import logging
import logging.handlers
import os
import re
import socket
import sqlite3
import sys
import time
from datetime import datetime


from scenario_settings import (AGENT_ID, FIM_PATH, READ_PATH, DESTINATION,
                               DESTINATION_PORT, BINARY_ALIASES)
WINDOW = 60
RETENTION = 900
MAX_EVENTS = 2000
MAX_OUTBOX = 500
MAX_INPUT = 262144
STATE_DB = "/var/ossec/var/fim-tetragon-correlation/state-v2.sqlite3"
ERROR_LOG = "/var/ossec/logs/fim-tetragon-correlation.log"
QUEUE = "/var/ossec/queue/sockets/queue"
SOURCE = "fim_tetragon_correlation"
# Observed names in the supplied lab alerts. Verify readlink on the HOST before
# activation. Do not resolve host executable paths on the manager/container.
LOG = logging.getLogger(SOURCE)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("missing timestamp")
    # Python 3.10 accepts microseconds; Tetragon supplies nanoseconds. Keep the
    # original string as evidence, truncate only the numeric comparison value.
    compatible = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    # Wazuh emits +0000; Python 3.10 needs the offset as +00:00.
    compatible = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", compatible)
    parsed = datetime.fromisoformat(compatible)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.timestamp()


def required(value, label):
    if value is None or str(value) == "":
        raise ValueError("missing " + label)
    return str(value)


def executable(value):
    value = required(value, "executable")
    return BINARY_ALIASES.get(value, value)


def normalize(alert, input_source="unspecified"):
    """Allowlist the exact lab scenario; preserve evidence IDs, not full logs."""
    rule = str(alert.get("rule", {}).get("id", ""))
    agent = alert.get("agent", {})
    if agent.get("id") != AGENT_ID or rule not in {"550", "100801", "100802"}:
        return None
    event = {
        "agent": {k: str(agent.get(k, "")) for k in ("id", "name", "ip")},
        "alert_id": required(alert.get("id"), "alert id"),
        "input_source": input_source,
        "rule": rule,
        "alert_time": required(alert.get("timestamp"), "alert timestamp"),
    }
    event["received_ts"] = timestamp(event["alert_time"])
    if rule == "550":
        sc = alert.get("syscheck", {})
        if (sc.get("path") != FIM_PATH or sc.get("mode") != "whodata"
                or sc.get("event") != "modified"):
            return None
        audit = sc.get("audit", {})
        proc = audit.get("process", {})
        event.update(
            kind="fim", pid=required(proc.get("id"), "FIM PID"),
            ppid=required(proc.get("ppid"), "FIM parent PID"),
            auid=required(audit.get("login_user", {}).get("id"), "Audit login UID"),
            uid=required(audit.get("effective_user", {}).get("id"), "Audit effective UID"),
            login_user=str(audit.get("login_user", {}).get("name") or "unknown"),
            effective_user=str(audit.get("effective_user", {}).get("name") or "unknown"),
            binary=required(proc.get("name"), "Audit binary"),
            time=event["alert_time"], ts=event["received_ts"],
            path=FIM_PATH,
            sha256_before=required(sc.get("sha256_before"), "before hash"),
            sha256_after=required(sc.get("sha256_after"), "after hash"),
        )
        if event["sha256_before"] == event["sha256_after"]:
            return None
    else:
        data = alert.get("data", {})
        kp = data.get("process_kprobe", {})
        proc, parent = kp.get("process", {}), kp.get("parent", {})
        args = kp.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, dict) for a in args):
            raise ValueError("process_kprobe.args must be an array of objects")
        event.update(
            runtime_args=args,
            pid=required(proc.get("pid"), "Tetragon PID"),
            ppid=required(parent.get("pid"), "Tetragon parent PID"),
            auid=required(proc.get("auid"), "Tetragon audit UID"),
            uid=required(proc.get("uid"), "Tetragon effective UID"),
            binary=required(proc.get("binary"), "Tetragon binary"),
            exec_id=required(proc.get("exec_id"), "exec_id"),
            start_time=required(proc.get("start_time"), "process start time"),
            node=required(data.get("node_name"), "Tetragon node"),
            time=required(data.get("time"), "Tetragon event time"),
        )
        event["ts"], event["start_ts"] = timestamp(event["time"]), timestamp(event["start_time"])
        if event["ts"] < event["start_ts"]:
            raise ValueError("event precedes process start")
        if rule == "100801":
            paths = [a.get("file_arg", {}).get("path") for a in args]
            masks = [str(a.get("int_arg")) for a in args]
            if (kp.get("policy_name") != "wazuh-demo-file-read"
                    or kp.get("function_name") != "security_file_permission"
                    or READ_PATH not in paths or "4" not in masks
                    or str(kp.get("return", {}).get("int_arg")) != "0"):
                return None
            event.update(kind="read", path=READ_PATH)
        else:
            socks = [a["sock_arg"] for a in args if "sock_arg" in a]
            eligible = [s for s in socks if s.get("daddr") == DESTINATION
                        and str(s.get("dport")) == str(DESTINATION_PORT)
                        and s.get("protocol") == "IPPROTO_TCP"]
            if (kp.get("policy_name") != "wazuh-demo-network"
                    or kp.get("function_name") != "tcp_connect" or len(eligible) != 1):
                return None
            event.update(kind="network", destination=DESTINATION,
                         port=DESTINATION_PORT, socket_state=eligible[0].get("state", "unknown"))
    for key in ("pid", "ppid", "auid", "uid"):
        if not re.fullmatch(r"[0-9]+", event[key]):
            raise ValueError("non-numeric identity: " + key)
    event["canonical_binary"] = executable(event["binary"])
    event["event_fingerprint"] = fingerprint(event)
    return event


def fingerprint(event):
    """Evidence identity, independent of the unreliable delivered alert ID.

    Keep exact timestamp strings, including nanoseconds. This is not a
    vendor-issued event ID; identical selected evidence is treated as replay.
    """
    excluded = {"agent", "alert_id", "input_source", "alert_time", "received_ts",
                "ts", "start_ts", "event_fingerprint", "login_user", "effective_user"}
    evidence = {k: v for k, v in event.items() if k not in excluded}
    evidence.update(agent_id=event["agent"]["id"], fingerprint_version=2)
    return hashlib.sha256(json.dumps(evidence, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def evidence_reference(event):
    return {"received_alert_id": event["alert_id"],
            "input_source": event["input_source"],
            "alert_id_verified": False,
            "event_fingerprint": event["event_fingerprint"],
            "alert_timestamp": event["alert_time"]}


def same_identity(left, right):
    return (left["agent"]["id"] == right["agent"]["id"]
            and all(left[k] == right[k] for k in ("pid", "ppid", "auid", "uid", "canonical_binary")))


def sequences(events):
    """Arrival order independent. No frequency counter; require three roles.

    FIM binding remains evidence-based: FIM has no Tetragon exec_id. We use its
    alert timestamp, not a timezone-less file mtime, and reject ambiguous
    candidate exec_ids. This is NOT a proof against all possible PID reuse.
    """
    fims = [e for e in events if e["kind"] == "fim"]
    runtime = [e for e in events if e["kind"] != "fim"]
    for fim in fims:
        candidates = [e for e in runtime if same_identity(fim, e)
                      and e["start_ts"] <= fim["ts"] <= e["ts"] <= fim["ts"] + WINDOW]
        identities = {(e["node"], e["exec_id"], e["start_time"]) for e in candidates}
        if len(identities) != 1:
            continue
        reads = sorted((e for e in candidates if e["kind"] == "read"), key=lambda e: e["ts"])
        networks = sorted((e for e in candidates if e["kind"] == "network"), key=lambda e: e["ts"])
        if not reads:
            continue
        eligible = [e for e in networks if e["ts"] >= reads[0]["ts"]]
        if eligible:
            yield fim, reads[0], eligible[0]


def summary(fim, read, network):
    identity = [fim["agent"]["id"], fim["event_fingerprint"], read["node"], read["exec_id"],
                READ_PATH, DESTINATION, DESTINATION_PORT]
    key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
    return {
        "integration": SOURCE,
        "correlation": {
            "id": key, "status": "complete", "scope": "controlled_lab",
            "schema_version": 2,
            "window_seconds": WINDOW,
            "identity_method": "agent_pid_ppid_auid_euid_explicit_binary_alias_time",
            "fim_time_basis": "manager_alert_timestamp",
            "fim_exec_id_directly_observed": False,
            "runtime_identity_method": "same_tetragon_exec_id_node_start_time",
            "agent_id": fim["agent"]["id"],
            "process": {"pid": fim["pid"], "ppid": fim["ppid"],
                        "login_uid": fim["auid"], "effective_uid": fim["uid"],
                        "login_user": fim.get("login_user", "unknown"),
                        "effective_user": fim.get("effective_user", "unknown"),
                        "user_identity_source": "wazuh_fim_whodata",
                        "fim_binary": fim["binary"], "runtime_binary": read["binary"],
                        "exec_id": read["exec_id"], "start_time": read["start_time"]},
            "fim": {**evidence_reference(fim), "rule_id": fim["rule"],
                    "time": fim["time"], "path": fim["path"],
                    "sha256_before": fim["sha256_before"], "sha256_after": fim["sha256_after"]},
            "read": {**evidence_reference(read), "rule_id": read["rule"],
                     "time": read["time"], "path": read["path"],
                     "evidence": "read_permission_granted"},
            "network": {**evidence_reference(network), "rule_id": network["rule"],
                        "time": network["time"], "destination_ip": network["destination"],
                        "destination_port": network["port"], "socket_state": network["socket_state"],
                        "evidence": "tcp_connection_attempt"},
        },
    }


def connect_db(path):
    db = sqlite3.connect(path, timeout=3, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, agent TEXT, pid TEXT, stored REAL, body TEXT)")
    db.execute("CREATE INDEX IF NOT EXISTS event_process ON events(agent,pid)")
    db.execute("CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, stored REAL, agent TEXT, body TEXT, sent INTEGER DEFAULT 0)")
    return db


def ingest(db, event, now=None):
    now = time.time() if now is None else now
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute("DELETE FROM events WHERE stored < ?", (now - RETENTION,))
        db.execute("DELETE FROM outbox WHERE sent=1 AND stored < ?", (now - RETENTION,))
        existing = db.execute("SELECT 1 FROM events WHERE id=?",
                              (event["event_fingerprint"],)).fetchone()
        if not existing and db.execute("SELECT count(*) FROM events").fetchone()[0] >= MAX_EVENTS:
            raise RuntimeError("lab state capacity reached; event not silently evicted")
        db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)",
                   (event["event_fingerprint"], event["agent"]["id"],
                    event["pid"], now, json.dumps(event)))
        rows = db.execute("SELECT body FROM events WHERE agent=? AND pid=?",
                          (event["agent"]["id"], event["pid"])).fetchall()
        for fim, read, network in sequences([json.loads(row[0]) for row in rows]):
            msg = summary(fim, read, network)
            key = msg["correlation"]["id"]
            if db.execute("SELECT 1 FROM outbox WHERE id=?", (key,)).fetchone():
                continue
            if db.execute("SELECT count(*) FROM outbox").fetchone()[0] >= MAX_OUTBOX:
                raise RuntimeError("outbox capacity reached; inspect pending delivery")
            db.execute("INSERT INTO outbox VALUES (?,?,?,?,0)",
                       (key, now, json.dumps(fim["agent"]), json.dumps(msg)))
        db.commit()
        return not bool(existing)
    except Exception:
        db.rollback()
        raise


def queue_message(agent, msg):
    # Wazuh's official v4.14.6 integration transport convention. Keep the
    # endpoint association; do not mistake the Tetragon container for the host.
    if not re.fullmatch(r"[0-9]+", agent["id"]):
        raise ValueError("invalid agent id for queue")
    for key in ("name", "ip"):
        if any(c in agent.get(key, "") for c in "\r\n\x00"):
            raise ValueError("invalid queue identity")
    location = "[{}] ({}) {}".format(agent["id"], agent["name"], agent.get("ip") or "any")
    location = location.replace("|", "||").replace(":", "|:")
    data = ("1:" + location + "->fim-tetragon-correlation:" + json.dumps(msg, separators=(",", ":"))).encode()
    if len(data) > 6000:
        raise ValueError("summary exceeds conservative transport limit")
    return data


def send_queue(agent, msg):
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.connect(QUEUE)
        sock.send(queue_message(agent, msg))


def flush(db, sender):
    # Serialize delivery. Commit AFTER send. A crash between send and commit
    # can repeat the same correlation.id; delivery is NOT exactly-once.
    db.execute("BEGIN IMMEDIATE")
    try:
        for key, agent, body in db.execute("SELECT id,agent,body FROM outbox WHERE sent=0 LIMIT 5").fetchall():
            sender(json.loads(agent), json.loads(body))
            db.execute("UPDATE outbox SET sent=1 WHERE id=?", (key,))
        db.commit()
    except Exception:
        db.rollback()
        raise


def replay(stream):
    """Historical replay, in-memory only. No log files, database files or socket."""
    db = connect_db(":memory:")
    count = 0
    try:
        for line in stream:
            if not line.strip():
                continue
            if len(line.encode()) > MAX_INPUT:
                raise ValueError("input alert too large")
            event = normalize(json.loads(line), input_source="alerts_json_replay")
            if event:
                ingest(db, event, now=0)
                count += 1
        reports = [json.loads(row[0]) for row in db.execute("SELECT body FROM outbox ORDER BY stored,id")]
        for report in reports:
            print(json.dumps(report, indent=2))
        print("REPLAY: {} eligible events; {} correlation(s); no alerts sent.".format(count, len(reports)), file=sys.stderr)
        return 0 if reports else 2
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-stdin", action="store_true")
    parser.add_argument("--flush-pending", action="store_true")
    opts = parser.parse_args()
    if opts.replay_stdin:
        return replay(sys.stdin)
    os.umask(0o077)
    # Deployment must precreate a root-owned 0700 state directory. Fail closed
    # rather than guessing writable locations or silently dropping evidence.
    handler = logging.handlers.RotatingFileHandler(ERROR_LOG, maxBytes=1000000, backupCount=2)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    db = None
    try:
        event = None
        if not opts.flush_pending:
            raw = sys.stdin.buffer.readline(MAX_INPUT + 1)
            if len(raw) > MAX_INPUT:
                raise ValueError("AR message too large")
            message = json.loads(raw)
            if message.get("command") != "add":
                return 0
            incoming = message.get("parameters", {}).get("alert", {})
            LOG.info(
                "AR_INPUT worker_pid=%s agent=%s rule=%s alert=%s alert_time=%s event_time=%s",
                os.getpid(), incoming.get("agent", {}).get("id"),
                incoming.get("rule", {}).get("id"), incoming.get("id"),
                incoming.get("timestamp"), incoming.get("data", {}).get("time"),
            )
            event = normalize(incoming, input_source="active_response")
            if event is None:
                return 0
            now = time.time()
            if not (-5 <= now - event["received_ts"] <= RETENTION):
                raise ValueError("stale/future alert rejected in live mode; use replay for historical tests")
            if abs(event["received_ts"] - event["ts"]) > RETENTION:
                raise ValueError("source event time too far from alert time")
        db = connect_db(STATE_DB)
        if event:
            inserted = ingest(db, event)
        flush(db, send_queue)
        if event:
            LOG.info("processed rule=%s received_alert_id=%s pid=%s event_key=%s inserted=%s",
                     event["rule"], event["alert_id"], event["pid"],
                     event["event_fingerprint"], inserted)
        return 0
    except Exception as exc:
        LOG.error("processing/delivery failed (%s): %s", type(exc).__name__, exc)
        print("fim-tetragon correlation failed; inspect " + ERROR_LOG, file=sys.stderr)
        return 1
    finally:
        if db is not None:
            db.close()


if __name__ == "__main__":
    sys.exit(main())
