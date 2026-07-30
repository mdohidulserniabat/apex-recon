#!/usr/bin/env bash
# run-docker.sh — build the image once, then run apex-recon anywhere.
# Output lands in ./out on your host. Usage:  ./run-docker.sh target.com --full
set -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="apex-recon:latest"

if ! command -v docker >/dev/null 2>&1; then
  echo "[x] Docker is not installed. Install Docker first: https://docs.docker.com/engine/install/" >&2
  exit 1
fi

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[+] Building $IMAGE (first time only, takes a few minutes)..."
  docker build -t "$IMAGE" "$HERE"
fi

mkdir -p "$PWD/out"
INPUT_MOUNTS=()
INPUT_ENV=()
if [[ -n "${SCOPE_FILE:-}" ]]; then
  [[ -f "$SCOPE_FILE" ]] || { echo "[x] SCOPE_FILE cannot be read: $SCOPE_FILE" >&2; exit 1; }
  INPUT_MOUNTS+=( -v "$SCOPE_FILE:/inputs/scope.txt:ro" )
  INPUT_ENV+=( -e SCOPE_FILE=/inputs/scope.txt )
fi
if [[ -n "${AUTH_URLS_FILE:-}" ]]; then
  [[ -f "$AUTH_URLS_FILE" ]] || { echo "[x] AUTH_URLS_FILE cannot be read: $AUTH_URLS_FILE" >&2; exit 1; }
  INPUT_MOUNTS+=( -v "$AUTH_URLS_FILE:/inputs/authenticated-urls.txt:ro" )
  INPUT_ENV+=( -e AUTH_URLS_FILE=/inputs/authenticated-urls.txt )
fi
docker run --rm -it \
  -v "$PWD/out:/out" \
  "${INPUT_MOUNTS[@]}" \
  -e RATE_LIMIT -e CONCURRENCY -e HTTPX_THREADS \
  -e AUTH_COOKIE -e AUTH_HEADER -e AUTH_HEADER2 \
  -e INTERACTSH_SERVER -e TELEGRAM_BOT_TOKEN -e TELEGRAM_CHAT_ID -e GITHUB_TOKEN \
  -e NUCLEI_PROFILE -e NUCLEI_SEVERITIES -e UPDATE_NUCLEI_TEMPLATES \
  -e MAX_ACTIVE_URLS \
  "${INPUT_ENV[@]}" \
  -e JWT_WORDLIST -e RACE_TARGETS \
  "$IMAGE" "$@"
