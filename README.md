# Wazuh FIM + Tetragon runtime context

Connect Audit-backed file integrity evidence with eBPF runtime observations, then use Wazuh Active Response to act on a narrowly defined sequence.

This community integration contains the custom scripts, rules, policies and safe test scenario behind the demonstration. Wazuh FIM and Tetragon observe independently; Tetragon does not consume FIM hashes. A custom correlator executed through Active Response on the manager connects their evidence.

## How it works

```text
Linux endpoint                              Wazuh manager
FIM + Audit Who-data ---- rule 550 -------+
Tetragon + eBPF --------- 100801/100802 ----+--> manager Active Response
                                                custom correlation script
                                                SQLite evidence + outbox
                                                         |
                                                  rule 100810
                                                         |
endpoint Active Response <----------------------- response command
verify registered process, SIGTERM, observe exit
                       -------------------------> rule 100811
```

| Rule | Evidence or result |
| --- | --- |
| `550` | Native FIM: changed checksum, path, hashes, login user and effective user through Audit Who-data |
| `100801` | Successful file read-permission check from the selected Tetragon policy |
| `100802` | TCP connection attempt to the selected receiver |
| `100810` | Custom correlated sequence with the original evidence and process identity |
| `100811` | Endpoint response confirmed process exit through a pidfd |
| `100812` | Containment refused, not executed, or exit not confirmed |

The source alerts remain available for investigation. The summary includes fingerprints and provenance, not file contents. Multiple read-permission checks can legitimately produce multiple `100801` alerts.

## Start here

1. Run the [offline tests and replay](docs/VALIDATION.md). This requires no Wazuh instance and sends no signals.
2. Review [settings and installation](docs/INSTALLATION.md). Start with correlation only.
3. Enable endpoint containment only after checking the allowlist and process-registration safeguards.

```bash
PYTHONPATH=scripts python3 -m unittest discover -s tests -v
```

## Repository contents

- `scripts/`: correlator, endpoint response, simulator and shared example settings.
- `policies/`: the two observation-only Tetragon policies used by the scenario.
- `rules/`: Wazuh custom rules. Rule 550 is provided by Wazuh, not redefined here.
- `config/`: configuration fragments, not replacement `ossec.conf` files.
- `examples/`: fictional files for the controlled scenario.
- `tests/`: synthetic fixtures, identity checks, negative cases, deduplication and state/delivery tests.
- `docs/`: deployment, validation and security boundaries.

## Compatibility and scope

The original end-to-end demonstration used Wazuh 4.14.6, Tetragon 1.7.0, Python 3.10 in the manager and Python 3.14 on the Linux endpoint. The public package replaces local identities with examples and centralizes deployment settings. Its unit tests are separate from a live deployment validation.

Python standard-library modules only. Live containment requires Linux, `os.pidfd_open` and `signal.pidfd_send_signal`, a registered simulator and authorized sudo access. Wazuh and Tetragon installation, Audit configuration and kernel compatibility are prerequisites, not provided by this repository.

This is not a general-purpose process killer or a production-ready distributed correlation engine. Read [security and limitations](docs/SECURITY.md) before deployment. It never changes firewall rules or disables Linux Audit.

## Wazuh resources

[Explore Wazuh](https://wazuh.com/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program)

[Explore the Wazuh Ambassadors Program](https://wazuh.com/ambassadors-program/?utm_source=ambassadors&utm_medium=referral&utm_campaign=ambassadors+program)
