# Security boundaries and interpretation

## Evidence is not a verdict

- FIM Who-data attributes a file change to login and effective users. Root modification is not proof of malicious privilege escalation.
- A successful `security_file_permission` check with mask 4 is permission evidence, not proof of transferred bytes. Repeated kernel checks can generate several events.
- `tcp_connect` describes a connection attempt. It does not establish data exfiltration or prove a completed session.
- The fictional `audit_enabled` setting has no effect on Linux Audit or Wazuh.
- The rule 100810 wording describes this elevated-privilege scenario. The correlator matches user IDs across sources but does not independently require login UID to differ from effective UID. If broadening beyond this scenario, change the rule wording or explicitly validate the intended privilege condition.

## Identity and correlation

FIM and runtime observations are joined using agent, PID, parent PID, audit login UID, effective UID, explicitly configured binary alias and time. FIM does not directly observe Tetragon's exec ID. Runtime events must share node, exec ID and start time; ambiguous runtime identities are rejected. The time window is 60 seconds, with FIM's manager alert timestamp as its basis. Delays can cause false negatives.

Fingerprints preserve distinct evidence even if delivered Active Response alert IDs collide. `received_alert_id` is retained as delivered and `alert_id_verified` remains false. Do not treat it as an independently verified lookup key.

## Containment

The endpoint response targets only a root-owned, explicitly registered simulation process. It checks registration age, boot ID, script hash, command line, PID, parent PID, UID, executable and process start identity. A pidfd pins the process so PID reuse cannot redirect the signal. Confirmation requires observing exit after SIGTERM. Unknown or mismatched identities fail closed.

This protects against accidental targeting, not a hostile root user. Root can alter registrations and scripts. Parent directories and settings must remain trusted and not writable by ordinary users. The response is reactive; a first HTTP request can succeed before termination. There is no claim of first-packet prevention.

## Operational limits

Each eligible source alert launches a manager-side Python process. The broad native rule 550 trigger also invokes it for modifications the script later rejects. Narrow routing before production use. SQLite serializes writers; this package has no distributed state, benchmarked production capacity or multi-manager ownership protocol.

State retention is 900 seconds with explicit capacity limits. Unsent outbox entries remain pending. Sending to the local Wazuh socket is not confirmation of indexing. A crash between send and commit can duplicate a correlation. Retry occurs on another eligible invocation or an operator's `--flush-pending` invocation; no background retry service is installed. Monitor delivery failures and preserve state on persistent storage.

## Publication hygiene

This distribution excludes operational logs, databases, registration manifests, original alert exports, SSH details, certificates, tokens, real configuration files and environment-specific deployment scripts. Tests contain example identities and synthetic evidence. Fixture paths and loopback addresses are intentional public examples, not customer inventory.

Do not commit your edited deployment copy, secrets or live alerts. Keep local overrides and exported evidence outside the repository. A `.gitignore` is a convenience, not a security boundary; review the staged diff before every publication.
