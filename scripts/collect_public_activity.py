"""Build the public push timeline from GitHub repository Activity, not Atom."""
from datetime import datetime
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from svcdash.privacy import sanitize_text

WINDOW = 7 * 86400
MAX_EVENTS = 100
AUTOMATED_REFS = {'refs/heads/gh-pages', 'refs/heads/github-data'}


def github_get(path, **params):
    url = 'https://api.github.com' + path + '?' + urllib.parse.urlencode(params)
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'svc-dashboard-snapshot'}
    auth = os.environ.get('GH_TOKEN')
    if auth:
        headers['Authorization'] = 'Bearer ' + auth
    try:
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=12)
    except urllib.error.HTTPError as exc:
        # The Actions installation token may not have access to other repos.
        if not auth or exc.code not in (403, 404) or exc.headers.get('X-RateLimit-Remaining') == '0':
            raise
        del headers['Authorization']
        response = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=12)
    with response:
        return json.load(response), 'rel="next"' in response.headers.get('Link', '')


def timestamp(value):
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return 0


def collect(owner, *, get=github_get, now=None):
    if not re.fullmatch(r'[A-Za-z0-9-]+', owner):
        raise ValueError('Invalid GitHub login')
    now = time.time() if now is None else now
    cutoff = now - WINDOW
    events = {}
    for page in range(1, 11):
        repos, more = get(f'/users/{owner}/repos', type='owner', sort='pushed', direction='desc',
                          per_page=100, page=page)
        if not isinstance(repos, list):
            raise ValueError('Invalid repository response')
        for repo in repos:
            if timestamp(repo.get('pushed_at')) < cutoff or repo.get('private') is not False:
                continue
            name = repo.get('name', '')
            full_name = f'{owner}/{name}'
            if (repo.get('visibility', 'public') != 'public' or repo.get('full_name') != full_name
                    or not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in {'.', '..'}):
                continue
            path = '/repos/' + full_name
            for activity_page in range(1, 11):
                rows, next_page = get(path + '/activity', time_period='week', per_page=100, page=activity_page)
                if not isinstance(rows, list):
                    raise ValueError('Invalid repository activity response')
                for row in rows:
                    ref, sha = row.get('ref') or '', row.get('after') or ''
                    ts = timestamp(row.get('timestamp'))
                    if (row.get('activity_type') not in {'push', 'force_push', 'branch_creation'}
                            or (row.get('actor') or {}).get('login') != owner
                            or ref in AUTOMATED_REFS or not ref.startswith('refs/heads/')
                            or ts < cutoff or not re.fullmatch(r'[0-9a-f]{40}', sha)
                            or sha == '0' * 40):
                        continue
                    branch = ref.removeprefix('refs/heads/')
                    key = (full_name, ref, sha)
                    if key in events and events[key]['ts'] >= ts:
                        continue
                    events[key] = {'ts': ts, 'gid': sha[:7], 'sha': sha, 'short_sha': sha[:7],
                                   'name': name, 'repo': name, 'branch': sanitize_text(branch),
                                   'author': owner, 'kind': 'commit', 'src': 'github', 'origin': 'github',
                                   'url': f'https://github.com/{full_name}/commit/{sha}', 'files': []}
                if not next_page:
                    break
        if not more or not repos or timestamp(repos[-1].get('pushed_at')) < cutoff:
            break

    recent = sorted(events.values(), key=lambda e: (-e['ts'], e['url'], e['branch']))[:MAX_EVENTS]
    subjects = {}
    for index, event in enumerate(recent):
        url = event['url'].removeprefix('https://github.com/')
        full_name, sha = url.split('/commit/')
        key = (full_name, sha)
        if index < 25 and key not in subjects:
            try:
                commit, _ = get(f'/repos/{full_name}/git/commits/{sha}')
                lines = (commit.get('message') or '').splitlines()
                subjects[key] = sanitize_text(lines[0])[:240] if lines else ''
            except (urllib.error.URLError, OSError, ValueError):
                # A push can reference an object that GitHub no longer serves after a force-push.
                subjects[key] = ''
        subject = subjects.get(key) or f"Push · {event['branch']}"
        event.update(subject=subject, text=subject)
    return {'ok': True, 'updated_at': now, 'events': recent}
