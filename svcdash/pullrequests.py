"""Authored upstream PR snapshots. GitHub credentials stay in the user collector."""
import json
import os
from pathlib import Path
import subprocess
import time

PATH = Path(os.environ.get('SVC_PR_CACHE', '/home/tetsuya/.cache/svc-dashboard/pullrequests.json'))
QUERY = '''query($q:String!,$cursor:String){search(query:$q,type:ISSUE,first:20,after:$cursor){issueCount pageInfo{hasNextPage endCursor} nodes{... on PullRequest{number title url state isDraft updatedAt createdAt mergedAt reviewDecision mergeable additions deletions comments{totalCount} repository{nameWithOwner isPrivate owner{login}} commits(last:1){nodes{commit{statusCheckRollup{state}}}}}}}}'''


def classify(pr):
    if pr.get('state') == 'MERGED': return 'merged'
    if pr.get('state') == 'CLOSED': return 'closed'
    if pr.get('isDraft'): return 'draft'
    if pr.get('reviewDecision') == 'CHANGES_REQUESTED' or pr.get('ci') in ('FAILURE', 'ERROR') or pr.get('mergeable') == 'CONFLICTING': return 'action'
    if pr.get('reviewDecision') == 'APPROVED' and pr.get('ci') not in ('PENDING', 'EXPECTED') and pr.get('mergeable') == 'MERGEABLE': return 'ready'
    return 'review'


def _read_local_snapshot(public=False):
    try:
        data = json.loads(PATH.read_text())
    except (OSError, ValueError):
        return {'ok': False, 'items': [], 'error': 'unavailable'}
    if public:
        data['items'] = [p for p in data.get('items', []) if not p.get('private')]
    data['stale'] = time.time() - data.get('updated_at', 0) > 900
    return data


def read_snapshot(public=False):
    from .github_snapshots import read_snapshot as read_github_snapshot
    remote = read_github_snapshot()
    if remote.get('ok') is not True or 'pullrequests' not in remote:
        return _read_local_snapshot(public=public)
    data = dict(remote['pullrequests'])
    if public:
        data['items'] = [p for p in data.get('items', []) if not p.get('private')]
    data['stale'] = time.time() - data.get('updated_at', 0) > 900
    return data


def collect(force=False):
    previous = _read_local_snapshot()
    if not force and previous.get('ok') and time.time() - previous.get('updated_at', 0) < 300:
        return previous
    def gh(args):
        return json.loads(subprocess.check_output(['gh', *args], timeout=60, stderr=subprocess.PIPE))
    try:
        login = os.environ.get('SVC_GITHUB_LOGIN') or gh(['api', 'user'])['login']
        items, cursor = [], None
        while True:
            args = ['api', 'graphql', '-f', 'query='+QUERY, '-f', f'q=is:pr author:{login} -user:{login} sort:updated-desc']
            if cursor: args += ['-f', 'cursor='+cursor]
            response = gh(args)
            if response.get('errors'): raise ValueError('GitHub query failed')
            result = response['data']['search']
            for p in result['nodes']:
                repo = p.pop('repository')
                commits = p.pop('commits')['nodes']
                rollup = commits[-1]['commit'].get('statusCheckRollup') if commits else None
                p.update(repo=repo['nameWithOwner'], private=repo['isPrivate'], ci=(rollup or {}).get('state'), comments=p['comments']['totalCount'])
                p['category'] = classify(p)
                items.append(p)
            if not result['pageInfo']['hasNextPage'] or len(items) >= 1000: break
            cursor = result['pageInfo']['endCursor']
        data = {'ok': True, 'login': login, 'updated_at': time.time(), 'items': items, 'truncated': result['pageInfo']['hasNextPage']}
    except Exception:
        data = dict(previous, stale=True, error='sync_failed')
        # Keep the last successful timestamp and data; never replace failures with zero.
    PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False))
    tmp.replace(PATH)
    return data
