from datetime import datetime, timezone
import unittest
from unittest.mock import patch
import os
import subprocess
import sys
from pathlib import Path

from scripts import collect_public_activity as activity
from svcdash import github


STAMP = '2026-11-27T02:23:49Z'
NOW = datetime.fromisoformat(STAMP).timestamp()


def repo(name, **kw):
    return {'name': name, 'full_name': 'iamcheyan/' + name, 'private': False,
            'pushed_at': STAMP, **kw}


def push(sha, ref='refs/heads/main', actor='iamcheyan', **kw):
    return {'activity_type': 'push', 'ref': ref, 'timestamp': STAMP,
            'actor': {'login': actor}, 'after': sha, **kw}


class PublicActivityTest(unittest.TestCase):
    def test_snapshot_builder_rejects_non_hosted_execution(self):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'build_github_snapshot.py'
        for actions, runner in [('false', ''), ('true', 'self-hosted')]:
            with self.subTest(runner=runner):
                result = subprocess.run([sys.executable, str(script)], capture_output=True,
                                        text=True, timeout=3,
                                        env=dict(os.environ, GITHUB_ACTIONS=actions,
                                                 RUNNER_ENVIRONMENT=runner))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('GitHub-hosted Actions', result.stderr)

    def test_uses_public_repo_activity_and_omits_publisher_refs_and_bots(self):
        sha = '6cd26a1' + 'a' * 33
        blocked = [dict(repo('hidden'), private=True), repo('another', visibility='internal'),
                   dict(repo('elsewhere'), full_name='another/elsewhere')]
        branch = 'refs/heads/feature/trn'
        requests = []

        def get(path, **params):
            requests.append((path, params))
            if path == '/users/iamcheyan/repos':
                return [repo('termtuck'), *blocked], False
            if path == '/repos/iamcheyan/termtuck/activity':
                if params['page'] == 1:
                    return [push('a' * 40, 'refs/heads/gh-pages'),
                            push('b' * 40, 'refs/heads/github-data')], True
                return [push(sha, branch), push(sha, branch),
                        push('c' * 40, actor='github-actions[bot]'),
                        push('d' * 40, actor='other')], False
            if path == '/repos/iamcheyan/termtuck/git/commits/' + sha:
                return {'message': 'Fix terminal paste\n\nDo not copy the body'}, False
            self.fail('Unexpected API request: ' + path)

        data = activity.collect('iamcheyan', get=get, now=NOW)
        self.assertEqual(len(requests), 4)
        self.assertEqual(len(data['events']), 1)
        event = data['events'][0]
        self.assertEqual((event['branch'], event['gid'], event['subject'], event['ts']),
                         ('feature/trn', '6cd26a1', 'Fix terminal paste', NOW))
        self.assertEqual(event['url'], f'https://github.com/iamcheyan/termtuck/commit/{sha}')

    def test_valid_empty_snapshot_stays_empty(self):
        with patch.object(github, 'read_snapshot', return_value={
            'ok': True, 'activity': {'ok': True, 'events': []},
        }):
            self.assertEqual(github.github_events(), [])

    def test_snapshot_failure_does_not_collect_from_another_source(self):
        with patch.object(github, 'read_snapshot', return_value={'ok': False}):
            self.assertEqual(github.github_events(), [])

    def test_backend_formats_push_timestamp_in_server_timezone(self):
        with patch.object(github, 'read_snapshot', return_value={
            'ok': True, 'activity': {'ok': True, 'events': [{'ts': NOW}]},
        }):
            row, = github.github_events()
        want = datetime.fromtimestamp(NOW, timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')
        self.assertEqual(row['time'], want)
