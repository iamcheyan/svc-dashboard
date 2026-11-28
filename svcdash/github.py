"""Read public push activity published by GitHub Actions."""
import time

from svcdash.github_snapshots import read_snapshot


def github_events(total=60):
    """Read the public snapshot only; never collect activity on this host."""
    activity = read_snapshot().get('activity')
    if not isinstance(activity, dict) or activity.get('ok') is not True:
        return []
    events = activity.get('events')
    if not isinstance(events, list):
        return []
    return [dict(event, time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['ts'])))
            for event in events[:total]]
