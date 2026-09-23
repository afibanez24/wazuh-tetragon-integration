import copy
import itertools
import json
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import fim_tetragon_correlate as c


def fixtures():
    agent = {"id": "001", "name": "example-endpoint", "ip": "127.0.0.1"}
    fim = {"id": "fim-1", "agent": agent, "rule": {"id": "550"},
           "timestamp": "2026-09-22T13:40:41.385+0000", "syscheck": {
               "path": c.FIM_PATH, "mode": "whodata", "event": "modified",
               "sha256_before": "a" * 64, "sha256_after": "b" * 64,
               "audit": {"process": {"id": "4242", "ppid": "4241", "name": "/usr/bin/python3.14"},
                         "login_user": {"id": "1000"}, "effective_user": {"id": "0"}}}}
    read = {"id": "read-1", "agent": agent, "rule": {"id": "100801"},
            "timestamp": "2026-09-22T13:40:44.718+0000", "data": {
                "time": "2026-09-22T13:40:43.374565793Z", "node_name": "example-node",
                "process_kprobe": {
                    "process": {"pid": "4242", "uid": "0", "auid": "1000", "binary": "/usr/bin/python3",
                                "exec_id": "execution-one", "start_time": "2026-09-22T13:40:41.314179811Z"},
                    "parent": {"pid": "4241"}, "policy_name": "wazuh-demo-file-read",
                    "function_name": "security_file_permission", "return": {"int_arg": "0"},
                    "args": [{"file_arg": {"path": c.READ_PATH}}, {"int_arg": 4}]}}}
    duplicate_read = copy.deepcopy(read)
    duplicate_read["id"] = "read-2"
    duplicate_read["data"]["time"] = "2026-09-22T13:40:43.374593338Z"
    network = copy.deepcopy(read)
    network["id"] = "network-1"
    network["rule"]["id"] = "100802"
    network["timestamp"] = "2026-09-22T13:40:46.684+0000"
    network["data"]["time"] = "2026-09-22T13:40:45.411420215Z"
    kp = network["data"]["process_kprobe"]
    kp.pop("return")
    kp.update(policy_name="wazuh-demo-network", function_name="tcp_connect",
              args=[{"sock_arg": {"daddr": c.DESTINATION, "dport": c.DESTINATION_PORT,
                                   "protocol": "IPPROTO_TCP", "state": "TCP_SYN_SENT"}}])
    return copy.deepcopy([fim, read, duplicate_read, network])


class CorrelationTests(unittest.TestCase):
    def test_user_names_come_from_fim(self):
        alerts = fixtures()
        original_key = c.normalize(alerts[0])["event_fingerprint"]
        alerts[0]["syscheck"]["audit"]["login_user"]["name"] = "example-user"
        alerts[0]["syscheck"]["audit"]["effective_user"]["name"] = "root"
        events = [c.normalize(a) for a in alerts]
        self.assertEqual(events[0]["event_fingerprint"], original_key)
        process = c.summary(events[0], events[1], events[3])["correlation"]["process"]
        self.assertEqual(process["login_user"], "example-user")
        self.assertEqual(process["effective_user"], "root")
        self.assertEqual(process["user_identity_source"], "wazuh_fim_whodata")
        self.assertEqual(process["login_uid"], "1000")
        self.assertEqual(process["effective_uid"], "0")

    def test_shared_ar_id_preserves_distinct_events(self):
        _, first, second, _ = fixtures()
        second["id"] = first["id"]
        db = c.connect_db(":memory:")
        try:
            for alert in (first, second):
                self.assertTrue(c.ingest(db, c.normalize(alert), now=0))
            self.assertEqual(db.execute("SELECT count(*) FROM events").fetchone()[0], 2)
        finally:
            db.close()

    def test_id_change_does_not_change_evidence_identity(self):
        for alert in fixtures():
            other = copy.deepcopy(alert)
            other["id"] = "different-delivered-id"
            a = c.normalize(alert, "active_response")
            b = c.normalize(other, "alerts_json_replay")
            self.assertEqual(a["event_fingerprint"], b["event_fingerprint"])
            db = c.connect_db(":memory:")
            try:
                self.assertTrue(c.ingest(db, a, now=0))
                self.assertFalse(c.ingest(db, b, now=0))
            finally:
                db.close()

    def test_nanoseconds_survive_fingerprint(self):
        first = fixtures()[1]
        second = copy.deepcopy(first)
        second["data"]["time"] = "2026-09-22T13:40:43.374565794Z"
        self.assertNotEqual(c.normalize(first)["event_fingerprint"],
                            c.normalize(second)["event_fingerprint"])

    def test_summary_reference_provenance(self):
        alerts = fixtures()
        events = [c.normalize(a, "active_response") for a in alerts]
        report = c.summary(events[0], events[1], events[3])["correlation"]
        for kind in ("fim", "read", "network"):
            self.assertNotIn("alert_id", report[kind])
            self.assertFalse(report[kind]["alert_id_verified"])
            self.assertEqual(report[kind]["input_source"], "active_response")
            self.assertEqual(len(report[kind]["event_fingerprint"]), 64)
        changed = copy.deepcopy(events[0])
        changed["alert_id"] = "incorrect-ar-id"
        self.assertEqual(report["id"], c.summary(changed, events[1], events[3])["correlation"]["id"])

    def test_same_id_different_fim_changes(self):
        first = fixtures()[0]
        second = copy.deepcopy(first)
        second["syscheck"]["sha256_after"] = "c" * 64
        self.assertNotEqual(c.normalize(first)["event_fingerprint"],
                            c.normalize(second)["event_fingerprint"])

    def test_python310_offset_input(self):
        real_datetime = c.datetime
        for source, expected in (
            ("2026-09-22T13:40:41.385+0000", "2026-09-22T13:40:41.385+00:00"),
            ("2026-09-22T15:40:41.385+0200", "2026-09-22T15:40:41.385+02:00"),
            ("2026-09-22T08:40:41.385-0500", "2026-09-22T08:40:41.385-05:00"),
            ("2026-09-22T13:40:41.314179811Z", "2026-09-22T13:40:41.314179+00:00"),
            ("2026-09-22T13:40:41.385+00:00", "2026-09-22T13:40:41.385+00:00"),
        ):
            with patch.object(c, "datetime", wraps=real_datetime) as parser:
                c.timestamp(source)
                parser.fromisoformat.assert_called_once_with(expected)

    def reports(self, alerts):
        db = c.connect_db(":memory:")
        try:
            for alert in alerts:
                event = c.normalize(alert)
                if event:
                    c.ingest(db, event, now=0)
            return [json.loads(row[0]) for row in db.execute("SELECT body FROM outbox")]
        finally:
            db.close()

    def test_complete(self):
        reports = self.reports(fixtures())
        self.assertEqual(len(reports), 1)
        report = reports[0]["correlation"]
        self.assertEqual(report["network"]["destination_port"], 18765)
        self.assertEqual(report["process"]["pid"], "4242")
        self.assertFalse(report["fim_exec_id_directly_observed"])

    def test_every_arrival_order(self):
        for order in itertools.permutations(fixtures()):
            self.assertEqual(len(self.reports(order)), 1)

    def test_replays_do_not_duplicate(self):
        self.assertEqual(len(self.reports(fixtures() * 3)), 1)

    def test_missing_each_required_stage(self):
        for missing in ("550", "100801", "100802"):
            self.assertFalse(self.reports([a for a in fixtures() if a["rule"]["id"] != missing]))

    def test_read_repetition_cannot_replace_network(self):
        f, r, _, _ = fixtures()
        self.assertFalse(self.reports([f] + [r] * 10))

    def test_other_agent(self):
        alerts = fixtures()
        alerts[3]["agent"]["id"] = "003"
        self.assertFalse(self.reports(alerts))

    def test_process_identity_mismatch(self):
        for key, value in (("pid", "999"), ("auid", "999"), ("uid", "999"),
                           ("binary", "/usr/bin/other"), ("exec_id", "other-execution")):
            alerts = fixtures()
            alerts[3]["data"]["process_kprobe"]["process"][key] = value
            self.assertFalse(self.reports(alerts), key)

    def test_parent_mismatch(self):
        alerts = fixtures()
        alerts[3]["data"]["process_kprobe"]["parent"]["pid"] = "999"
        self.assertFalse(self.reports(alerts))

    def test_new_execution_after_fim(self):
        alerts = fixtures()
        alerts[3]["data"]["process_kprobe"]["process"]["start_time"] = "2026-09-22T13:40:44Z"
        self.assertFalse(self.reports(alerts))

    def test_network_outside_window(self):
        alerts = fixtures()
        alerts[3]["data"]["time"] = "2026-09-22T13:42:00Z"
        self.assertFalse(self.reports(alerts))

    def test_network_before_read(self):
        alerts = fixtures()
        alerts[3]["data"]["time"] = "2026-09-22T13:40:42Z"
        self.assertFalse(self.reports(alerts))

    def test_wrong_file(self):
        alerts = fixtures()
        for alert in alerts[1:3]:
            alert["data"]["process_kprobe"]["args"][0]["file_arg"]["path"] = "/etc/passwd"
        self.assertFalse(self.reports(alerts))

    def test_denied_read(self):
        alerts = fixtures()
        for alert in alerts[1:3]:
            alert["data"]["process_kprobe"]["return"]["int_arg"] = "-13"
        self.assertFalse(self.reports(alerts))

    def test_wrong_destination(self):
        alerts = fixtures()
        alerts[3]["data"]["process_kprobe"]["args"][0]["sock_arg"]["daddr"] = "192.0.2.1"
        self.assertFalse(self.reports(alerts))

    def test_missing_identity_fails(self):
        alert = fixtures()[0]
        del alert["syscheck"]["audit"]["login_user"]
        with self.assertRaises(ValueError):
            c.normalize(alert)

    def test_final_rule_not_ingested(self):
        alert = fixtures()[0]
        alert["rule"]["id"] = "100810"
        self.assertIsNone(c.normalize(alert))

    def test_pending_output_survives_delivery_failure(self):
        db = c.connect_db(":memory:")
        for alert in fixtures():
            c.ingest(db, c.normalize(alert), now=0)
        def failure(agent, message):
            raise OSError("test socket unavailable")
        with self.assertRaises(OSError):
            c.flush(db, failure)
        self.assertEqual(db.execute("SELECT sent FROM outbox").fetchone()[0], 0)
        sent = []
        c.flush(db, lambda a, m: sent.append(m))
        c.flush(db, lambda a, m: sent.append(m))
        self.assertEqual(len(sent), 1)
        db.close()

    def test_state_survives_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "state.sqlite3")
            for alert in fixtures():
                db = c.connect_db(path)
                c.ingest(db, c.normalize(alert), now=0)
                db.close()
            db = c.connect_db(path)
            self.assertEqual(db.execute("SELECT count(*) FROM outbox").fetchone()[0], 1)
            db.close()

    def test_expired_evidence_not_used(self):
        db = c.connect_db(":memory:")
        alerts = fixtures()
        c.ingest(db, c.normalize(alerts[0]), now=0)
        for alert in alerts[1:]:
            c.ingest(db, c.normalize(alert), now=c.RETENTION + 1)
        self.assertEqual(db.execute("SELECT count(*) FROM outbox").fetchone()[0], 0)
        db.close()

    def test_queue_agent_identity(self):
        msg = self.reports(fixtures())[0]
        payload = c.queue_message(fixtures()[0]["agent"], msg)
        self.assertTrue(payload.startswith(b"1:[001] (example-endpoint) 127.0.0.1->fim-tetragon-correlation:"))
        self.assertLess(len(payload), 6000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
