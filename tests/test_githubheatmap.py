import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from svcdash import githubheatmap as heat


class GitHubCalendarTest(unittest.TestCase):
    def test_failure_keeps_previous_calendar_and_timestamp(self):
        previous={'ok':True,'updated_at':123,'totalContributions':42,'weeks':[{'contributionDays':[]}]}
        with patch.object(heat,'_read_local_snapshot',return_value=previous),patch.object(heat.subprocess,'check_output',side_effect=OSError()):
            result=heat.collect(force=True)
        self.assertEqual(result['totalContributions'],42)
        self.assertEqual(result['updated_at'],123)
        self.assertTrue(result['stale'])

    def test_cache_prevents_unnecessary_github_calls(self):
        import time
        with patch.object(heat,'_read_local_snapshot',return_value={'ok':True,'updated_at':time.time()}),patch.object(heat.subprocess,'check_output') as upstream:
            heat.collect()
        upstream.assert_not_called()

    def test_collect_writes_only_calendar_data(self):
        calendar={'totalContributions':42,'weeks':[{'contributionDays':[{'date':'2026-11-11','contributionCount':2,'weekday':3,'contributionLevel':'FIRST_QUARTILE'}]}]}
        year=heat.datetime.now(heat.timezone.utc).year
        user={'contributionsCollection':{'contributionCalendar':calendar}}
        user.update({f'y{y}':{'contributionCalendar':calendar} for y in range(year-2,year+1)})
        response={'data':{'user':user}}
        with tempfile.TemporaryDirectory() as tmp,patch.object(heat,'PATH',Path(tmp)/'calendar.json'),patch.object(heat.subprocess,'check_output',return_value=json.dumps(response).encode()):
            result=heat.collect(force=True)
            self.assertEqual(result['totalContributions'],42)
            self.assertEqual(result['years'][str(year)]['weeks'],calendar['weeks'])
            self.assertEqual(heat._read_local_snapshot()['weeks'],calendar['weeks'])
