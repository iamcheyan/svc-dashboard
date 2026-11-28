"""Prevent accidental reintroduction of a host-side GitHub collector."""
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
RETIRED = re.compile(
    r'svc-dashboard-(?:activity|github)\.(?:service|timer)'
    r'|(?:refresh_public_activity|collect_github_snapshots|collect_activity)\.py'
    r'|SVC_GITHUB_ACTIVITY_CACHE|public-activity\.json'
)
CLOUD_COLLECTOR = re.compile(r'(?:build_github_snapshot|collect_public_activity)\.py')


class ActionsOnlyTest(unittest.TestCase):
    def test_no_local_github_collector_or_install_instructions(self):
        out = subprocess.check_output(
            ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT)
        findings = set()
        for name in out.decode().split('\0'):
            if not name:
                continue
            path = ROOT / name
            if not path.is_file() or path == Path(__file__).resolve():
                continue
            if RETIRED.search(name):
                findings.add(name)
                continue
            try:
                text = path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
            if RETIRED.search(text):
                findings.add(name)
            if path.suffix in {'.service', '.timer', '.sh', '.socket', '.path'} and CLOUD_COLLECTOR.search(text):
                findings.add(name)
        self.assertEqual(sorted(findings), [], 'GitHub activity collection must stay in GitHub Actions')
