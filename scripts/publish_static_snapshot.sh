#!/usr/bin/env bash
set -Eeuo pipefail

# 本机数据 → 脱敏静态站点 → gh-pages。
# 设计目标：可被 systemd timer 重复调用；内容不变时不产生 GitHub Pages 构建。
REPO_DIR="${SVC_DASHBOARD_DIR:-/home/tetsuya/development/svc-dashboard}"
CNAME="${SVC_DASHBOARD_CNAME:-svc.iamcheyan.com}"
STATE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/svc-dashboard-static"
LOCK_FILE="${XDG_RUNTIME_DIR:-/tmp}/svc-dashboard-static-publish.lock"

mkdir -p "$STATE_DIR"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[static-publish] another run is already active; skip"
  exit 0
fi

if [[ ! -f "$REPO_DIR/dashboard.py" ]]; then
  echo "[static-publish] repository not found: $REPO_DIR" >&2
  exit 1
fi

REMOTE_URL=$(git -C "$REPO_DIR" remote get-url origin)
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/svc-static-publish.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT

echo "[static-publish] collecting and sanitizing snapshot"
python3 - "$REPO_DIR" "$WORK_DIR" "$CNAME" <<'PY'
import os, sys
repo_dir, output_dir, cname = sys.argv[1:]
sys.path.insert(0, repo_dir)
from svcdash.export import export_static
export_static(output_dir, lang="zh", cname=cname)
PY

HASH=$(find "$WORK_DIR" -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sha256sum \
  | awk '{print $1}')
LAST_HASH_FILE="$STATE_DIR/last-published.sha256"

if [[ "${SVC_DASHBOARD_FORCE:-0}" != "1" && -s "$LAST_HASH_FILE" \
      && "$(<"$LAST_HASH_FILE")" == "$HASH" ]]; then
  echo "[static-publish] snapshot unchanged; no push"
  exit 0
fi

git -C "$WORK_DIR" init -q
git -C "$WORK_DIR" checkout -q -b gh-pages
git -C "$WORK_DIR" config user.name "svc-dashboard static publisher"
git -C "$WORK_DIR" config user.email "svc-dashboard@noreply.local"
git -C "$WORK_DIR" add -A
git -C "$WORK_DIR" commit -q -m "Update sanitized static snapshot $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git -C "$WORK_DIR" remote add origin "$REMOTE_URL"

echo "[static-publish] pushing changed snapshot to origin/gh-pages"
git -C "$WORK_DIR" push -q -f origin gh-pages
printf '%s\n' "$HASH" > "$LAST_HASH_FILE"
echo "[static-publish] published successfully"
