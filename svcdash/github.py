"""Read public push activity published by GitHub Actions."""
import time

from svcdash.github_snapshots import read_snapshot


def github_events(total=60):
    """Return recent public pushes, with timestamps formatted for the local dashboard."""
    activity = read_snapshot().get('activity') or {}
    if activity.get('ok') is not True:
        return []
    return [dict(event, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['ts'])))
            for event in activity['events'][:total]]
