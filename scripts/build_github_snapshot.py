#!/usr/bin/env python3
"""Build the public GitHub-only snapshot used by svc-dashboard."""
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ISSUES_QUERY = '''query($cursor:String){repository(owner:"iamcheyan",name:"chezmoi"){issues(first:100,after:$cursor,orderBy:{field:UPDATED_AT,direction:DESC}){pageInfo{hasNextPage endCursor} nodes{title body state labels(first:100){nodes{name}}}}}}'''


def collect_public_issues():
    from svcdash.privacy import sanitize_text

    items, cursor = [], None
    truncated = False
    while True:
        args = ["gh", "api", "graphql", "-f", "query=" + ISSUES_QUERY]
        if cursor:
            args += ["-f", "cursor=" + cursor]
        raw = subprocess.check_output(args, timeout=60, stderr=subprocess.PIPE)
        response = json.loads(raw)
        if response.get("errors"):
            raise RuntimeError("GitHub issue query failed")
        result = response["data"]["repository"]["issues"]
        for issue in result["nodes"]:
            labels = {x["name"].strip().lower() for x in issue["labels"]["nodes"]}
            if labels & {"private", "secret", "no-publish"}:
                continue
            title = sanitize_text(issue.get("title", ""), mask_ips=True, mask_paths=True).strip()
            if not title:
                continue
            body = sanitize_text((issue.get("body") or "")[:240], mask_ips=True, mask_paths=True).strip()
            items.append({"title": title[:160], "excerpt": body[:220], "state": issue.get("state", "OPEN")})
        if not result["pageInfo"]["hasNextPage"]:
            break
        cursor = result["pageInfo"]["endCursor"]
    return {"ok": True, "repo": "iamcheyan/chezmoi", "updated_at": time.time(),
            "items": items, "truncated": truncated}


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
        "chezmoiIssues": collect_public_issues(),
    }
    output = pathlib.Path(os.environ.get("SVC_GITHUB_SNAPSHOT_OUTPUT", "github-snapshots.json"))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    temporary.replace(output)
    print(f"snapshot={output} prs={len(payload['pullrequests'].get('items', []))} issues={len(payload['chezmoiIssues'].get('items', []))}")


if __name__ == "__main__":
    main()
