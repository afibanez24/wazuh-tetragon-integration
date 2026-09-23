#!/usr/bin/python3
"""Synthetic application scenario. Authorized sudo elevation, not an exploit.

Only modifies the established lab fixture and calls a loopback HTTP receiver.
No file contents are transmitted. A maximum duration prevents runaway tests.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid
from urllib.request import ProxyHandler, build_opener
import scenario_settings as settings

SCRIPT = Path('/usr/local/lib/wazuh-runtime-simulation/scenario.py')
STATE = Path('/run/wazuh-runtime-simulation')
BASE = Path(settings.BASE)


def main():
    if len(sys.argv) == 2 and sys.argv[1] in ('complete', 'negative'):
        if os.getuid() != settings.LOGIN_UID or os.geteuid() != settings.LOGIN_UID:
            raise SystemExit('Start as the configured non-root user, without sudo: scenario.py complete|negative')
        mode = sys.argv[1]
        run = uuid.uuid4().hex[:12]
        print(f'INITIAL USER uid={os.getuid()} euid={os.geteuid()} RUN={run}', flush=True)
        print('Requesting authorized sudo elevation; this is not a privilege exploit.', flush=True)
        os.execvp('sudo', ['sudo', '--', settings.RUNTIME_BINARY, str(SCRIPT), '--elevated', mode, run])
    if len(sys.argv) != 4 or sys.argv[1] != '--elevated' or sys.argv[2] not in ('complete', 'negative'):
        raise SystemExit('Usage: scenario.py complete|negative')
    mode, run = sys.argv[2:]
    if len(run) != 12 or any(x not in '0123456789abcdef' for x in run):
        raise SystemExit('Invalid run identifier')
    auid = int(Path('/proc/self/loginuid').read_text())
    if os.getuid() != 0 or os.geteuid() != 0 or auid != settings.LOGIN_UID or os.environ.get('SUDO_UID') != str(settings.LOGIN_UID):
        raise SystemExit('Expected authorized elevation from the configured login UID')
    pid = os.getpid()
    ticks = int(Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19])
    boot = next(int(x.split()[1]) for x in Path('/proc/stat').read_text().splitlines() if x.startswith('btime '))
    state = {'pid': pid, 'ppid': os.getppid(), 'mode': mode, 'run_id': run,
             'script': str(SCRIPT), 'exe': os.readlink('/proc/self/exe'),
             'script_sha256': hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
             'start_ticks': ticks, 'start_epoch': boot + ticks / os.sysconf('SC_CLK_TCK'),
             'created_at': time.time(), 'login_uid': auid, 'effective_uid': os.geteuid(),
             'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    fd = os.open(STATE / f'{pid}.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream)
    print(f'ELEVATED uid={os.getuid()} euid={os.geteuid()} login_uid={auid} PID={pid} RUN={run}', flush=True)
    # User attribution comes from Wazuh FIM Who-data, not a synthetic marker.
    if mode == 'complete':
        config = BASE / 'app.conf'
        content = config.read_text()
        if 'audit_enabled=true' not in content:
            raise SystemExit('Fixture must be prepared with audit_enabled=true before complete run')
        # This setting is fictitious: it does NOT disable Auditd or Wazuh.
        with config.open('w') as stream:
            stream.write(content.replace('audit_enabled=true', 'audit_enabled=false') + f'\n# simulation_run={run}\n')
        print('1. Fictional application audit setting changed to false', flush=True)
        time.sleep(2)
    else:
        print('1. Negative test: configuration unchanged', flush=True)
    data = (BASE / 'customer-demo.txt').read_bytes()
    print(f'2. Synthetic customer file read: {len(data)} bytes; contents NOT transmitted', flush=True)
    time.sleep(2)
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + (75 if mode == 'complete' else 12)
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            with opener.open(f'http://{settings.DESTINATION}:{settings.DESTINATION_PORT}/?simulation_run={run}&attempt={attempt}', timeout=3) as response:
                print(f'3. Controlled receiver attempt={attempt} HTTP={response.status}', flush=True)
        except Exception as exc:
            print(f'3. Request failed: {type(exc).__name__}', flush=True)
        time.sleep(2)
    print('Simulation ended by its own time limit; no containment claimed.', flush=True)


if __name__ == '__main__':
    main()
