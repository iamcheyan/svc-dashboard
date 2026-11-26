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

def collect_public_issues():
    from svcdash.privacy import sanitize_text

    pages = json.loads(subprocess.check_output(
        ["gh", "api", "--paginate", "--slurp",
         "repos/iamcheyan/chezmoi/issues?state=all&per_page=100"],
        timeout=60, stderr=subprocess.PIPE))
    items = []
    for page in pages:
        for issue in page:
            if "pull_request" in issue:
                continue
            labels = {str(x.get("name") or "").strip().lower() for x in issue.get("labels", [])}
            if labels & {"private", "secret", "no-publish"}:
                continue
            title = sanitize_text(issue.get("title", ""), mask_ips=True, mask_paths=True).strip()
            if not title:
                continue
            body = sanitize_text((issue.get("body") or "")[:240], mask_ips=True, mask_paths=True).strip()
            items.append({"title": title[:160], "excerpt": body[:220],
                          "state": str(issue.get("state") or "open").upper()})
    return {"ok": True, "repo": "iamcheyan/chezmoi", "updated_at": time.time(), "items": items}


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
