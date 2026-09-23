# Validation

## Offline checks first

Run from the repository root with the unmodified example settings:

```bash
PYTHONPATH=scripts python3 -m unittest discover -s tests -v
```

The 32 tests use synthetic fixtures and in-memory or temporary SQLite databases. They do not connect to Wazuh or send signals. They cover positive and incomplete sequences, all arrival orders, identity mismatches, timing constraints, repeated evidence, ambiguous IDs, persisted state and failed output delivery. Containment tests exercise validation, not a live pidfd termination.

Generate a synthetic replay directly from the test fixtures:

```bash
PYTHONPATH=scripts:tests python3 -c 'import json; from test_correlator import fixtures; print("\n".join(json.dumps(a) for a in fixtures()))' |
python3 scripts/fim_tetragon_correlate.py --replay-stdin
```

Expected: four eligible events, one correlation, no alerts sent. Replay exit code 0 means a correlation was produced; 2 means none was produced, not necessarily an execution error.

For `wazuh-logtest`, convert the single positive replay object to one JSON line before piping it to the manager's `/var/ossec/bin/wazuh-logtest`. Expected rule: 100810. `logtest` does not execute Active Response or prove live alert delivery.

## Live positive scenario

Start a loopback-only receiver in a separate endpoint terminal as an ordinary user. Serve only the fictional fixture directory, never your home directory:

```bash
python3 -m http.server 18765 --bind 127.0.0.1 --directory /opt/wazuh-tetragon-demo
```

Confirm the fixture has `audit_enabled=true`; for subsequent runs, deliberately reset only the fictional fixture using `examples/app.conf`, then let that preparatory FIM event settle. From the configured ordinary user's real login session, without prefacing the command with sudo:

```bash
/usr/local/lib/wazuh-runtime-simulation/scenario.py complete
```

The script requests authorized sudo elevation, registers its identity, changes the fictional application setting, reads the synthetic file and attempts loopback HTTP requests. Note the printed PID.

Expected: 550, one or more 100801, 100802, then 100810. With containment enabled and validation successful, expect 100811 with `response.verification=pidfd_exit_observed`. Without containment the scenario exits by its own time limit; this is not a confirmed response. 100812 requires investigation and must not be presented as a successful block.

## Negative scenario

```bash
/usr/local/lib/wazuh-runtime-simulation/scenario.py negative
```

This reads the synthetic file and connects to the receiver without modifying the application configuration. Expected for this PID: 100801 and 100802, no 100810 or 100811. Wait beyond the 60-second correlation window, refresh the dashboard and verify manager logs as well as the indexed alerts.

## Dashboard

Replace the example agent ID and PID:

```text
agent.id:"001" AND (syscheck.audit.process.id:"4242" OR data.process_kprobe.process.pid:"4242" OR data.correlation.process.pid:"4242" OR data.response.pid:"4242")
```

Inspect `rule.id`, `rule.description` and the underlying JSON. FIM exposes `syscheck.audit.login_user` and `syscheck.audit.effective_user`. The correlated result exposes these under `data.correlation.process`, plus paths, hashes, runtime identity, destination and provenance. Inspect 100811's response fields to confirm exit observation.

## Before wider use

Measure manager CPU, memory, queue delay, database I/O and incoming eligible events per second with and without the integration. Successful low-volume tests are not capacity validation. Test negative cases, service restart/recovery and delivery failures in your own deployment. Keep exported live logs and SQLite state out of Git.
