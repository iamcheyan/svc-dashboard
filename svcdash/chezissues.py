"""GitHub is the source of truth for the chezmoi checklist and discussion."""
import json
import os
from pathlib import Path
import subprocess
import time
from svcdash.privacy import sanitize_text

REPO = 'iamcheyan/chezmoi'
PATH = Path(os.environ.get('SVC_ISSUES_CACHE', '/home/tetsuya/.cache/svc-dashboard/chezmoi-issues.json'))
QUERY = '''query($cursor:String){repository(owner:"iamcheyan",name:"chezmoi"){issues(first:20,after:$cursor,orderBy:{field:UPDATED_AT,direction:DESC}){pageInfo{hasNextPage endCursor} nodes{number title body url state stateReason createdAt updatedAt closedAt author{login} labels(first:100){nodes{name}} assignees(first:100){nodes{login}} milestone{title} comments(first:100){pageInfo{hasNextPage} nodes{body url createdAt updatedAt author{login}}}}}}}'''


def _read_local_snapshot(public=False):
    try:
        d = json.loads(PATH.read_text())
    except (OSError, ValueError):
        return {'ok': False, 'repo': REPO, 'items': []}
    d['stale'] = bool(d.get('error')) or time.time() - d.get('updated_at', 0) > 900
    if public:
        d['items'] = public_items(d.get('items', []))
    return d


def read_snapshot(public=False):
    from .github_snapshots import read_snapshot as read_github_snapshot
    remote = read_github_snapshot()
    if remote.get('ok') is not True or 'chezmoiIssues' not in remote:
        return _read_local_snapshot(public=public)
    d = dict(remote['chezmoiIssues'])
    d['publicSnapshot'] = True
    d['stale'] = bool(d.get('error')) or time.time() - d.get('updated_at', 0) > 900
    if public:
        d['items'] = public_items(d.get('items', []))
    return d


def public_items(items):
    result = []
    for i in items:
        if {s.lower() for s in i.get('labels', [])} & {'private', 'secret', 'no-publish'}:
            continue
        result.append({'title': sanitize_text(i.get('title', ''), mask_ips=True, mask_paths=True),
                       'excerpt': sanitize_text(i.get('body', '')[:240], mask_ips=True, mask_paths=True),
                       'state': i.get('state', 'OPEN')})
    return result


def collect(force=False):
    old = _read_local_snapshot()
    if not force and old.get('ok') and not old.get('error') and time.time() - old.get('updated_at', 0) < 300:
        return old
    def gh(args):
        return json.loads(subprocess.check_output(['gh', *args], timeout=60, stderr=subprocess.PIPE))
    try:
        items, cursor = [], None
        while True:
            args = ['api', 'graphql', '-f', 'query='+QUERY]
            if cursor: args += ['-f', 'cursor='+cursor]
            response = gh(args)
            if response.get('errors'): raise ValueError('GitHub query failed')
            result = response['data']['repository']['issues']
            for i in result['nodes']:
                comments = i['comments']
                if comments['pageInfo']['hasNextPage']:
                    pages = gh(['api', '--paginate', '--slurp', f'repos/{REPO}/issues/{i["number"]}/comments?per_page=100'])
                    i['comments'] = [{'body': c['body'], 'url': c['html_url'], 'createdAt': c['created_at'], 'updatedAt': c['updated_at'], 'author': {'login': (c.get('user') or {}).get('login', '')}} for page in pages for c in page]
                else:
                    i['comments'] = comments['nodes']
                i['labels'] = [l['name'] for l in i['labels']['nodes']]
                i['assignees'] = [a['login'] for a in i['assignees']['nodes']]
                items.append(i)
            if not result['pageInfo']['hasNextPage']: break
            cursor = result['pageInfo']['endCursor']
        d = {'ok': True, 'repo': REPO, 'updated_at': time.time(), 'items': items}
    except Exception:
        d = dict(old, stale=True, error='sync_failed')
    PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = PATH.with_suffix('.tmp')
    tmp.write_text(json.dumps(d, ensure_ascii=False))
    tmp.chmod(0o600)
    tmp.replace(PATH)
    return d
