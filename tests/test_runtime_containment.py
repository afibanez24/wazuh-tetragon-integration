import copy
import unittest
from unittest.mock import patch
import runtime_containment as r


def sample():
    manifest = {'created_at': 100, 'mode': 'complete', 'script': str(r.SIMULATOR),
                'login_uid': 1000, 'effective_uid': 0, 'exe': '/usr/bin/python3.14',
                'run_id': 'abcdef012345', 'start_ticks': 12345, 'pid': 4321,
                'ppid': 4320, 'start_epoch': 100}
    snapshot = {'pid': 4321, 'ppid': 4320, 'start_ticks': 12345,
                'uids': [0, 0, 0, 0], 'login_uid': 1000, 'exe': '/usr/bin/python3.14',
                'cmdline': ['/usr/bin/python3', str(r.SIMULATOR), '--elevated', 'complete', 'abcdef012345']}
    c = {'status': 'complete', 'scope': 'controlled_lab', 'schema_version': '2',
         'agent_id': '001', 'fim': {'path': '/opt/wazuh-tetragon-demo/app.conf'},
         'read': {'path': '/opt/wazuh-tetragon-demo/customer-demo.txt'},
         'network': {'destination_ip': '127.0.0.1', 'destination_port': '18765'},
         'process': {'pid': '4321', 'ppid': '4320', 'login_uid': '1000', 'effective_uid': '0',
                     'runtime_binary': '/usr/bin/python3', 'fim_binary': '/usr/bin/python3.14',
                     'start_time': '1970-01-01T00:01:40.123456789Z'}}
    alert = {'rule': {'id': '100810'}, 'agent': {'id': '001'},
             'data': {'integration': 'fim_tetragon_correlation', 'correlation': c}}
    return alert, manifest, snapshot


class ContainmentTests(unittest.TestCase):
    def test_expected(self):
        a, m, s = sample()
        self.assertEqual(r.validate(a, m, s, 110)['status'], 'complete')

    def test_reject_other_process(self):
        for key, value in [('pid', 4322), ('ppid', 9), ('start_ticks', 12346),
                           ('login_uid', 0), ('uids', [1000]*4), ('exe', '/bin/bash'),
                           ('cmdline', ['/usr/bin/python3', '/tmp/unrelated.py'])]:
            a, m, s = sample()
            s[key] = value
            with self.assertRaises(ValueError, msg=key):
                r.validate(a, m, s, 110)

    def test_reject_negative_and_expired_registration(self):
        a, m, s = sample()
        with self.assertRaises(ValueError):
            r.validate(a, m, s, 400)
        with self.assertRaises(ValueError):
            r.validate(a, m, s, 90)
        m['mode'] = 'negative'
        with self.assertRaises(ValueError):
            r.validate(a, m, s, 110)

    def test_reject_stale_alert_identity(self):
        for key, value in [('pid', '99'), ('ppid', '99'), ('login_uid', '0'),
                           ('effective_uid', '1000'), ('start_time', '1970-01-01T00:02:00Z')]:
            a, m, s = sample()
            a['data']['correlation']['process'][key] = value
            with self.assertRaises(ValueError, msg=key):
                r.validate(a, m, s, 110)

    def test_reject_scope(self):
        a, m, s = sample()
        a['agent']['id'] = '003'
        with self.assertRaises(ValueError):
            r.validate(a, m, s, 110)
        a, m, s = sample()
        a['data']['correlation']['network']['destination_ip'] = '192.0.2.2'
        with self.assertRaises(ValueError):
            r.validate(a, m, s, 110)


if __name__ == '__main__':
    unittest.main()
