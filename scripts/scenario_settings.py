"""Reviewed example allowlist. Edit before deployment, then install root-owned.

Keep identical copies beside all three scripts. These are example values,
not discovered inventory. Never populate this file from an untrusted alert.
"""
AGENT_ID = "001"
LOGIN_UID = 1000
BASE = "/opt/wazuh-tetragon-demo"
FIM_PATH = BASE + "/app.conf"
READ_PATH = BASE + "/customer-demo.txt"
DESTINATION = "127.0.0.1"
DESTINATION_PORT = 18765
RUNTIME_BINARY = "/usr/bin/python3"
# Replace with: readlink -f /usr/bin/python3 ON THE LINUX ENDPOINT.
FIM_BINARY = "/usr/bin/python3.14"
BINARY_ALIASES = {RUNTIME_BINARY: FIM_BINARY}
