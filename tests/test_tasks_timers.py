import subprocess
import unittest
from unittest.mock import patch

from svcdash.tasks import _run_timers


class TimerListTest(unittest.TestCase):
    def test_masked_units_are_not_displayed_or_probed(self):
        listing = subprocess.CompletedProcess([], 0, (
            'old-collector.timer                masked         enabled\n'
            'old-runtime.timer                  masked-runtime enabled\n'
            'svc-dashboard-static-publish.timer enabled        enabled\n'
        ))
        active = subprocess.CompletedProcess([], 0, 'ActiveState=active\n')
        config = subprocess.CompletedProcess([], 0, '')
        with patch('svcdash.tasks.subprocess.run', side_effect=[listing, active, config]) as run:
            timers = _run_timers('user')
        self.assertEqual([timer['name'] for timer in timers], ['svc-dashboard-static-publish'])
        self.assertEqual(run.call_count, 3)
        self.assertIn('svc-dashboard-static-publish.timer', run.call_args_list[1].args[0])
