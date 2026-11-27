#!/usr/bin/env python3
"""Refresh a public-only activity cache using the local GitHub account."""
import json
import base64
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts.collect_public_activity import collect


def publish_activity(data):
    """Update the public data branch without replacing its other snapshots."""
    url = 'https://api.github.com/repos/iamcheyan/svc-dashboard/contents/github-snapshots.json'
    headers = {'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
               'Accept': 'application/vnd.github+json', 'User-Agent': 'svc-dashboard-activity'}
    for attempt in range(2):
        with urllib.request.urlopen(urllib.request.Request(url + '?ref=github-data', headers=headers), timeout=15) as response:
            entry = json.load(response)
        snapshot = json.loads(base64.b64decode(entry['content']))
        if snapshot.get('activity', {}).get('events') == data['events']:
            return
        snapshot['activity'] = data
        body = json.dumps({'message': 'Update public activity snapshot', 'branch': 'github-data',
                           'sha': entry['sha'], 'content': base64.b64encode(
                               json.dumps(snapshot, ensure_ascii=False, separators=(',', ':')).encode()).decode()}).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers, method='PUT'), timeout=20):
                return
        except urllib.error.HTTPError as exc:
            if exc.code != 409 or attempt:
                raise


def main():
    if not os.environ.get('GH_TOKEN'):
        os.environ['GH_TOKEN'] = subprocess.check_output(
            ['gh', 'auth', 'token'], text=True, timeout=10).strip()
    data = collect(os.environ.get('SVC_GITHUB_LOGIN', 'iamcheyan'))
    path = Path(os.environ.get('SVC_GITHUB_ACTIVITY_CACHE', '/home/tetsuya/.cache/svc-dashboard/public-activity.json'))
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    tmp.chmod(0o644)
    tmp.replace(path)
    print(f"Refreshed {len(data['events'])} public push events")
    publish_activity(data)


if __name__ == '__main__':
    main()
