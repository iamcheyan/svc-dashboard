"""Cached GitHub contribution calendar; credentials stay in the local collector."""
import json
import os
from pathlib import Path
import subprocess
import time
from datetime import datetime, timezone

PATH=Path(os.environ.get('SVC_GITHUB_CACHE', '/home/tetsuya/.cache/svc-dashboard/github-contributions.json'))
FIELDS='totalContributions weeks { contributionDays { date contributionCount contributionLevel weekday } }'


def _query(now):
    years=range(now.year-2, now.year+1)
    calendars=' '.join(
        f'y{year}: contributionsCollection(from:"{year}-01-01T00:00:00Z", to:"{year}-12-31T23:59:59Z") {{ contributionCalendar {{ {FIELDS} }} }}'
        for year in years)
    return f'query {{ user(login:"iamcheyan") {{ contributionsCollection {{ contributionCalendar {{ {FIELDS} }} }} {calendars} }} }}'


def _read_local_snapshot():
    try:data=json.loads(PATH.read_text())
    except (OSError,ValueError):return {'ok':False,'weeks':[]}
    data['stale']=time.time()-data.get('updated_at',0)>900
    return data


def read_snapshot():
    from .github_snapshots import read_snapshot as read_github_snapshot
    remote = read_github_snapshot()
    if remote.get('ok') is not True or 'githubContributions' not in remote:
        return _read_local_snapshot()
    data = dict(remote['githubContributions'])
    local = _read_local_snapshot()
    years = dict(local.get('years') or {}) if local.get('ok') else {}
    years.update(data.get('years') or {})
    # The rolling calendar covers every day of the current year. Use the more
    # recent snapshot to keep this year's count fresh even with an older cache.
    year = str(datetime.now(timezone.utc).year)
    if data.get('updated_at', 0) >= local.get('updated_at', 0):
        weeks = [{'contributionDays': [d for d in w.get('contributionDays', [])
                                      if d.get('date', '').startswith(year + '-')]} for w in data.get('weeks', [])]
        weeks = [w for w in weeks if w['contributionDays']]
        if weeks and weeks[0]['contributionDays'][0]['date'] == year + '-01-01':
            years[year] = {'weeks': weeks, 'totalContributions': sum(
                d.get('contributionCount', 0) for w in weeks for d in w['contributionDays'])}
    if years:
        data['years'] = years
    data['stale']=time.time()-data.get('updated_at',0)>900
    return data


def collect(force=False):
    previous=_read_local_snapshot()
    if not force and previous.get('ok') and time.time()-previous.get('updated_at',0)<60:return previous
    try:
        now=datetime.now(timezone.utc)
        raw=subprocess.check_output(['gh','api','graphql','-f','query='+_query(now)],timeout=45,stderr=subprocess.PIPE)
        response=json.loads(raw)
        if response.get('errors'):raise ValueError('GitHub query failed')
        user=response['data']['user']
        calendar=user['contributionsCollection']['contributionCalendar']
        if not calendar.get('weeks'):raise ValueError('Empty calendar')
        years={str(y):user[f'y{y}']['contributionCalendar'] for y in range(now.year-2,now.year+1)}
        if any(not cal.get('weeks') for cal in years.values()):raise ValueError('Empty annual calendar')
        data={'ok':True,'login':'iamcheyan','updated_at':time.time(),**calendar,'years':years}
    except Exception:return dict(previous,stale=True)
    PATH.parent.mkdir(parents=True,exist_ok=True)
    tmp=PATH.with_suffix('.tmp-'+str(os.getpid()))
    tmp.write_text(json.dumps(data));tmp.replace(PATH)
    return data
