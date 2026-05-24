#!/usr/bin/env bash
# Build all CSP images and push to Docker Hub.
#
# Configure target via .env at the repo root (copy from .env.example):
#   IMAGE_REPO=124000pk/yieldpk
#   TAG_API=csp-api-0.1.0
#   TAG_WORKER=csp-worker-0.1.0
#   TAG_WEB=csp-web-0.1.0
#
# Usage:
#   scripts/build-and-push.sh             # build + push api/worker/web for current arch
#   scripts/build-and-push.sh --build     # build only, no push
#   scripts/build-and-push.sh --multiarch # buildx for linux/amd64,linux/arm64 (requires buildx)
#   scripts/build-and-push.sh api         # only one service
#
# Compatible with bash 3.2 (macOS default) - uses case statements rather
# than associative arrays.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a
else
  echo "WARN: no .env at $ROOT, falling back to environment"
fi

: "${IMAGE_REPO:?set IMAGE_REPO in .env, e.g. 124000pk/yieldpk}"
TAG_API="${TAG_API:-csp-api-dev}"
TAG_WORKER="${TAG_WORKER:-csp-worker-dev}"
TAG_WEB="${TAG_WEB:-csp-web-dev}"

mode="push"
target=""
multiarch=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)     mode="build"; shift ;;
    --push)      mode="push"; shift ;;
    --multiarch) multiarch=1; shift ;;
    api|worker|web) target="$1"; shift ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

# Resolve service -> (context, tag) via case statement (bash 3.2 portable).
# API uses project-root context so the agent/ directory is reachable from
# its Dockerfile; worker / web use their own subdirs.
ctx_for() {
  case "$1" in
    api)    echo "." ;;
    worker) echo "./worker" ;;
    web)    echo "./web" ;;
    *) echo "unknown service: $1" >&2; return 2 ;;
  esac
}

dockerfile_for() {
  case "$1" in
    api)    echo "api/Dockerfile" ;;
    worker) echo "" ;;   # default Dockerfile in ./worker
    web)    echo "" ;;   # default Dockerfile in ./web
    *) echo "unknown service: $1" >&2; return 2 ;;
  esac
}

tag_for() {
  case "$1" in
    api)    echo "$TAG_API" ;;
    worker) echo "$TAG_WORKER" ;;
    web)    echo "$TAG_WEB" ;;
    *) echo "unknown service: $1" >&2; return 2 ;;
  esac
}

services="api worker web"
[[ -n "$target" ]] && services="$target"

if [[ $multiarch -eq 1 ]]; then
  command -v docker >/dev/null || { echo "docker required"; exit 1; }
  # Idempotent: try to switch to it; if missing, create.
  if ! docker buildx use csp-multi >/dev/null 2>&1; then
    docker buildx create --name csp-multi --driver docker-container --use
  fi
  echo "  using buildx: $(docker buildx inspect --bootstrap 2>/dev/null | head -1)"
fi

for svc in $services; do
  ctx="$(ctx_for "$svc")"
  tag="$(tag_for "$svc")"
  dockerfile="$(dockerfile_for "$svc")"
  ref="${IMAGE_REPO}:${tag}"
  fflag=""
  [[ -n "$dockerfile" ]] && fflag="-f $dockerfile"
  echo
  echo "==========> $svc  ->  $ref   (mode=$mode$([[ $multiarch -eq 1 ]] && echo ", multiarch"))"
  echo "             ctx=$ctx ${fflag}"
  if [[ $multiarch -eq 1 ]]; then
    pushflag="--load"
    [[ "$mode" == "push" ]] && pushflag="--push"
    docker buildx build \
      --platform linux/amd64,linux/arm64 \
      $fflag \
      -t "$ref" \
      "$pushflag" \
      "$ctx"
  else
    docker build $fflag -t "$ref" "$ctx"
    if [[ "$mode" == "push" ]]; then
      docker push "$ref"
    fi
  fi
done

echo
echo "OK done. Images:"
for svc in $services; do
  tag="$(tag_for "$svc")"
  echo "  ${IMAGE_REPO}:${tag}"
done
