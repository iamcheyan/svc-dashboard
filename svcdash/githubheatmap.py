"""Cached GitHub contribution calendar; credentials stay in the local collector."""
import json
import os
from pathlib import Path
import subprocess
import time

PATH=Path(os.environ.get('SVC_GITHUB_CACHE', '/home/tetsuya/.cache/svc-dashboard/github-contributions.json'))
QUERY='''query { user(login:"iamcheyan") { contributionsCollection { contributionCalendar { totalContributions weeks { contributionDays { date contributionCount contributionLevel weekday } } } } } }'''


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
    data['stale']=time.time()-data.get('updated_at',0)>900
    return data


def collect(force=False):
    previous=_read_local_snapshot()
    if not force and previous.get('ok') and time.time()-previous.get('updated_at',0)<60:return previous
    try:
        raw=subprocess.check_output(['gh','api','graphql','-f','query='+QUERY],timeout=45,stderr=subprocess.PIPE)
        response=json.loads(raw)
        if response.get('errors'):raise ValueError('GitHub query failed')
        calendar=response['data']['user']['contributionsCollection']['contributionCalendar']
        if not calendar.get('weeks'):raise ValueError('Empty calendar')
        data={'ok':True,'login':'iamcheyan','updated_at':time.time(),**calendar}
    except Exception:return dict(previous,stale=True)
    PATH.parent.mkdir(parents=True,exist_ok=True)
    tmp=PATH.with_suffix('.tmp-'+str(os.getpid()))
    tmp.write_text(json.dumps(data));tmp.replace(PATH)
    return data
