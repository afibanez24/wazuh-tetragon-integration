#!/usr/bin/python3
"""Lab-only endpoint AR: terminate the explicitly registered simulator via pidfd.

Never kills arbitrary Python processes, shells, process groups, or remote IPs.
An unknown/stale identity fails closed. No action on file contents or firewall.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import sys
import time
from datetime import datetime, timezone
import scenario_settings as settings

STATE = Path('/run/wazuh-runtime-simulation')
SIMULATOR = Path('/usr/local/lib/wazuh-runtime-simulation/scenario.py')
LOG = Path('/var/ossec/logs/runtime-containment.jsonl')
MAX_INPUT = 262144


def trusted(path, directory=False):
    s = path.lstat()
    wanted = stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)
    if not wanted or s.st_uid != 0 or s.st_mode & 0o022:
        raise ValueError('untrusted root-owned path')


def process_snapshot(pid):
    proc = Path('/proc') / str(pid)
    parts = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    fields = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
    return {
        'pid': pid, 'ppid': int(parts[1]), 'start_ticks': int(parts[19]),
        'uids': [int(x) for x in fields['Uid'].split()],
        'login_uid': int((proc / 'loginuid').read_text()),
        'exe': os.readlink(proc / 'exe'),
        'cmdline': (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
    }


def validate(alert, manifest, snapshot, now):
    if str(alert.get('rule', {}).get('id')) != '100810' or alert.get('agent', {}).get('id') != settings.AGENT_ID:
        raise ValueError('unexpected trigger or agent')
    data = alert.get('data', {})
    c = data.get('correlation', {})
    if (data.get('integration') != 'fim_tetragon_correlation'
            or c.get('status') != 'complete' or c.get('scope') != 'controlled_lab'
            or str(c.get('schema_version')) != '2' or c.get('agent_id') != settings.AGENT_ID):
        raise ValueError('unexpected correlation scope')
    if (c.get('fim', {}).get('path') != settings.FIM_PATH
            or c.get('read', {}).get('path') != settings.READ_PATH
            or c.get('network', {}).get('destination_ip') != settings.DESTINATION
            or str(c.get('network', {}).get('destination_port')) != str(settings.DESTINATION_PORT)):
        raise ValueError('unexpected scenario targets')
    p = c.get('process', {})
    if not 0 <= now - manifest['created_at'] <= 180:
        raise ValueError('expired simulation registration')
    if (manifest.get('mode') != 'complete' or manifest.get('script') != str(SIMULATOR)
            or manifest.get('login_uid') != settings.LOGIN_UID or manifest.get('effective_uid') != 0):
        raise ValueError('unapproved simulation registration')
    expected = [manifest['exe'], str(SIMULATOR), '--elevated', 'complete', manifest['run_id']]
    # argv[0] retains /usr/bin/python3 rather than its resolved symlink target.
    expected[0] = settings.RUNTIME_BINARY
    if (snapshot['cmdline'] != expected or snapshot['exe'] != manifest['exe']
            or snapshot['start_ticks'] != manifest['start_ticks']
            or snapshot['pid'] != manifest['pid'] or snapshot['ppid'] != manifest['ppid']
            or snapshot['uids'] != [0, 0, 0, 0] or snapshot['login_uid'] != settings.LOGIN_UID):
        raise ValueError('live process identity mismatch')
    if (str(snapshot['pid']) != str(p.get('pid')) or str(snapshot['ppid']) != str(p.get('ppid'))
            or str(p.get('login_uid')) != str(settings.LOGIN_UID) or str(p.get('effective_uid')) != '0'
            or p.get('runtime_binary') != settings.RUNTIME_BINARY
            or p.get('fim_binary') != settings.FIM_BINARY or p.get('fim_binary') != manifest['exe']):
        raise ValueError('alert process identity mismatch')
    # Tetragon start_time includes exec timing, proc start ticks fork timing.
    # Restricted simulator only; tolerate the kernel clock/boot-second conversion.
    # Python 3.10 does not accept nanosecond fractions.
    import re
    compatible = re.sub(r'(\.\d{6})\d+', r'\1', p['start_time'].replace('Z', '+00:00'))
    start = datetime.fromisoformat(compatible).timestamp()
    if abs(start - manifest['start_epoch']) > 3:
        raise ValueError('alert start time mismatch')
    return c


def record(status, **fields):
    body = {'integration': 'wazuh_runtime_response', 'scope': 'controlled_lab',
            'time': datetime.now(timezone.utc).isoformat(),
            'response': {'status': status, **fields}}
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        os.write(fd, (json.dumps(body, separators=(',', ':')) + '\n').encode())
    finally:
        os.close(fd)


def main():
    os.umask(0o027)
    fd = None
    context = {}
    try:
        raw = sys.stdin.buffer.readline(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError('oversized AR message')
        message = json.loads(raw)
        if message.get('command') != 'add':
            return 0
        alert = message.get('parameters', {}).get('alert', {})
        c = alert.get('data', {}).get('correlation', {})
        pid = int(c.get('process', {}).get('pid', 0))
        if pid <= 1 or pid == os.getpid():
            raise ValueError('invalid target PID')
        context = {'pid': str(pid), 'correlation_id': str(c.get('id', ''))[:128]}
        trusted(STATE, directory=True)
        trusted(SIMULATOR)
        path = STATE / (str(pid) + '.json')
        trusted(path)
        manifest = json.loads(path.read_text())
        if manifest['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            raise ValueError('boot identity mismatch')
        if manifest['script_sha256'] != hashlib.sha256(SIMULATOR.read_bytes()).hexdigest():
            raise ValueError('simulator changed since registration')
        # A pidfd pins the target task: PID reuse cannot redirect the signal.
        fd = os.pidfd_open(pid)
        validate(alert, manifest, process_snapshot(pid), time.time())
        context['run_id'] = manifest['run_id']
        signal.pidfd_send_signal(fd, signal.SIGTERM)
        ready, _, _ = select.select([fd], [], [], 3)
        if ready:
            record('terminated', action='terminate_registered_simulator',
                   verification='pidfd_exit_observed', signal='SIGTERM', **context)
        else:
            record('unconfirmed', reason='exit_not_observed_within_3s', **context)
        return 0 if ready else 1
    except (FileNotFoundError, ProcessLookupError):
        record('not_executed', reason='registered_process_or_identity_missing', **context)
        return 0
    except Exception as exc:
        record('refused', reason=str(exc)[:200], **context)
        return 1
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    sys.exit(main())
