# Installation and configuration

Use an isolated Linux test endpoint with a connected Wazuh agent. Back up existing configuration and check custom-rule ID collisions first. Do not overwrite an existing `ossec.conf` with the fragments in this repository.

## 1. Review the shared allowlist

Edit `scripts/scenario_settings.py` before deployment:

| Setting | How to choose it |
| --- | --- |
| `AGENT_ID` | The test agent's actual Wazuh ID, with leading zeros |
| `LOGIN_UID` | `id -u` in the ordinary user's Linux login session, not a root shell |
| `FIM_BINARY` | `readlink -f /usr/bin/python3` on that Linux endpoint |
| `RUNTIME_BINARY` | The binary spelling in Tetragon events, normally `/usr/bin/python3` |

The supplied values are examples. The binary alias is explicit: do not infer the endpoint's Python path from the manager or its container. Keep the loopback destination and fixture paths for the first run. If you change them, update the Tetragon policies and agent configuration too.

Install identical, root-owned copies of `scenario_settings.py` beside each executable. Do not grant ordinary users write access to scripts, settings, or their parent directories.

## 2. Prepare the Linux endpoint

Prerequisites: an active Audit service, a Wazuh agent supporting Audit Who-data, Tetragon exporting one JSON event per line to `/var/log/tetragon/events.json`, and Python with pidfd support for containment. Validate these before changing Wazuh's provider. Do not remove existing Audit rules.

From the repository root on the endpoint:

```bash
sudo install -d -o root -g root -m 755 /opt/wazuh-tetragon-demo
sudo install -o root -g root -m 644 examples/app.conf /opt/wazuh-tetragon-demo/app.conf
sudo install -o root -g root -m 644 examples/customer-demo.txt /opt/wazuh-tetragon-demo/customer-demo.txt
sudo install -d -o root -g root -m 755 /usr/local/lib/wazuh-runtime-simulation
sudo install -d -o root -g root -m 700 /run/wazuh-runtime-simulation
sudo install -o root -g root -m 755 scripts/scenario.py /usr/local/lib/wazuh-runtime-simulation/scenario.py
sudo install -o root -g root -m 644 scripts/scenario_settings.py /usr/local/lib/wazuh-runtime-simulation/scenario_settings.py
sudo install -o root -g wazuh -m 750 scripts/runtime_containment.py /var/ossec/active-response/bin/runtime_containment.py
sudo install -o root -g wazuh -m 640 scripts/scenario_settings.py /var/ossec/active-response/bin/scenario_settings.py
sudo touch /var/ossec/logs/runtime-containment.jsonl
sudo chown root:wazuh /var/ossec/logs/runtime-containment.jsonl
sudo chmod 640 /var/ossec/logs/runtime-containment.jsonl
```

Recreate the `/run` registration directory after reboot. Do not overwrite the simulator while a run is active. Merge `config/agent.xml`: place its directory and Who-data settings inside the existing `syscheck` section, and its log inputs inside `ossec_config`. Preserve unrelated settings. `report_changes` is intended only for these fictional fixtures; it can expose file content when used on real secrets.

Load `policies/*.yaml` using your existing Tetragon deployment's policy-loading mechanism. If using a mounted `tetragon.tp.d` directory, install both files in that mount and verify that both policies are enabled. They observe; they do not enforce blocking. No privileged container deployment template is included.

Validate the agent configuration:

```bash
sudo /var/ossec/bin/wazuh-agentd -t
sudo /var/ossec/bin/wazuh-syscheckd -t
sudo /var/ossec/bin/wazuh-logcollector -t
sudo /var/ossec/bin/wazuh-execd -t
```

Restart the agent through your normal service-management procedure. Verify the Who-data provider initialized successfully, Audit watches exist, and the initial FIM scan finished before testing.

## 3. Install on the manager

For a native manager, from the staged repository root:

```bash
sudo install -d -o root -g root -m 700 /var/ossec/var/fim-tetragon-correlation
sudo install -o root -g wazuh -m 750 scripts/fim_tetragon_correlate.py /var/ossec/active-response/bin/fim_tetragon_correlate.py
sudo install -o root -g wazuh -m 640 scripts/scenario_settings.py /var/ossec/active-response/bin/scenario_settings.py
sudo install -o root -g wazuh -m 640 rules/tetragon_rules.xml /var/ossec/etc/rules/tetragon_rules.xml
sudo install -o root -g wazuh -m 640 rules/fim_tetragon_correlation_rules.xml /var/ossec/etc/rules/fim_tetragon_correlation_rules.xml
sudo install -o root -g wazuh -m 640 rules/runtime_response_rules.xml /var/ossec/etc/rules/runtime_response_rules.xml
```

Only use these target filenames after confirming they are new or backing up and reviewing existing files. If your manager lacks `/var/ossec/framework/python/bin/python3`, select an installed Python 3.10+ interpreter and update the correlator's shebang before installation.

For Docker, stage the same artifacts inside the manager container, apply the same permissions there, and persist scripts, rules and state using the deployment's volumes. Update the Compose-mounted configuration source as well as the effective configuration. Do not publish your full Compose stack, certificates or cluster keys with this project.

Merge `config/manager.xml` for correlation only. The `server` location runs the correlator on the manager. It consumes rules 550, 100801 and 100802, not its own output, so it does not intentionally create a response loop.

```bash
sudo /var/ossec/bin/wazuh-execd -t
sudo /var/ossec/bin/wazuh-analysisd -t
```

Validate the summary through `wazuh-logtest` as described in the validation guide. Restart through your normal manager deployment procedure, then check `wazuh-control status` and `ossec.log`. Preserve ownership `root:wazuh` and mode `640` for `ossec.conf`; copying a root-only configuration can prevent services from starting.

## 4. Opt in to containment

After correlation-only validation, merge `config/manager-containment-opt-in.xml` on the manager, validate and reload it. This second response uses `location=local`: it executes on the originating agent, not the manager. It triggers on 100810 and requires the endpoint script and registration described above.

No allowlist registration means no termination. Do not remove this check to make the demonstration work.

## Rollback

Disable the two added Active Response blocks, validate and reload the manager configuration. Restore backed-up configuration fragments if needed. Unload only these two Tetragon policies through your deployment's normal mechanism. Leave unrelated rules, Audit settings and agents untouched. Keep state/logs for investigation until intentionally retired; do not delete a live database to troubleshoot.
