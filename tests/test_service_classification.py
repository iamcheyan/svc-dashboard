import unittest
from svcdash.procscan import classify

class ServiceClassificationTest(unittest.TestCase):
    def test_systemd_daemon_is_system_service(self):
        result = classify('0::/system.slice/systemd-resolved.service')
        self.assertEqual(result['scope'], 'system')
        self.assertEqual(result['unit'], 'systemd-resolved.service')

    def test_session_scope_stays_direct(self):
        self.assertEqual(classify('0::/user.slice/session-3.scope')['type'], 'direct')
