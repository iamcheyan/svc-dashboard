#!/usr/bin/env python3
"""Build the public GitHub-only snapshot used by svc-dashboard."""
import json
import os
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

def main():
    from svcdash.githubheatmap import collect as collect_heatmap, _read_local_snapshot as read_heatmap
    from svcdash.pullrequests import collect as collect_prs, _read_local_snapshot as read_prs

    collect_heatmap()
    collect_prs()

    payload = {
        "ok": True,
        "updated_at": time.time(),
        "githubContributions": read_heatmap(),
        "pullrequests": read_prs(public=True),
        "chezmoiIssues": {"ok": False, "repo": "iamcheyan/chezmoi",
                           "updated_at": time.time(), "items": [],
                           "error": "private_repository_unavailable"},
    }
    output = pathlib.Path(os.environ.get("SVC_GITHUB_SNAPSHOT_OUTPUT", "github-snapshots.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    temporary.replace(output)
    print(f"snapshot={output} prs={len(payload['pullrequests'].get('items', []))} issues={len(payload['chezmoiIssues'].get('items', []))}")


if __name__ == "__main__":
    main()
