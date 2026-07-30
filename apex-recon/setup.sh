#!/usr/bin/env bash
# setup.sh — installs tools, wordlists, configs. Idempotent, multi-distro best-effort.
# A single tool failing is NON-fatal; run again anytime. ⚠️ Needs internet.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

ok "Installing prerequisites"
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y || true
  sudo apt-get install -y golang-go jq curl git python3 python3-pip pipx unzip libpcap-dev chromium massdns dnsutils ncat bc sqlmap coreutils \
    || sudo apt-get install -y golang-go jq curl git python3 python3-pip pipx unzip bc sqlmap coreutils || true
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y golang jq curl git python3 python3-pip pipx unzip libpcap-devel nmap-ncat bc sqlmap coreutils || true
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --noconfirm go jq curl git python python-pip python-pipx unzip libpcap nmap bc sqlmap coreutils || true
elif command -v brew >/dev/null 2>&1; then
  brew install go jq curl git python pipx bc sqlmap || true
else
  warn "No known package manager. Install manually: go, jq, curl, git, python3, bc, sqlmap."
fi

# pipx is installed via the system package manager above (apt/dnf/pacman/brew).
# On modern Debian/Ubuntu, `pip install --user pipx` fails under PEP-668
# (externally-managed environment), so we do NOT use pip for pipx here.
# Fallback only if the package manager didn't provide pipx:
if ! command -v pipx >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  python3 -m pip install --user pipx --break-system-packages 2>/dev/null \
    || python3 -m pip install --user pipx 2>/dev/null || true
fi
command -v pipx >/dev/null 2>&1 && pipx ensurepath 2>/dev/null || true

if ! command -v go >/dev/null 2>&1; then
  warn "Go not found. Install Go >=1.21 (https://go.dev/dl/) then re-run this script."
  exit 1
fi

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin"

# Keep the repository's curated parameter patterns available to gf.  Do not
# overwrite operator-maintained patterns; re-running setup only fills missing
# files and makes the scanner's xss/sqli/ssrf/etc. buckets reproducible.
GF_CONFIG_DIR="${GF_CONFIG_DIR:-$HOME/.gf}"
if [[ -d "$SCRIPT_DIR/gf-patterns" ]]; then
  mkdir -p "$GF_CONFIG_DIR"
  for pattern in "$SCRIPT_DIR"/gf-patterns/*.json; do
    [[ -f "$pattern" ]] || continue
    cp -n "$pattern" "$GF_CONFIG_DIR/" 2>/dev/null || true
  done
  ok "GF patterns available in $GF_CONFIG_DIR (existing files preserved)"
fi

ok "Installing Go tools (a failure just skips that tool)"
GO_TOOLS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/projectdiscovery/katana/cmd/katana@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
  github.com/projectdiscovery/alterx/cmd/alterx@latest
  github.com/owasp-amass/amass/v4/cmd/amass@master
  github.com/tomnomnom/assetfinder@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/tomnomnom/anew@latest
  github.com/tomnomnom/gf@latest
  github.com/tomnomnom/qsreplace@latest
  github.com/tomnomnom/unfurl@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/hahwul/dalfox/v2@latest
  github.com/PentestPad/subzy@latest
  github.com/sensepost/gowitness@latest
  github.com/ffuf/ffuf/v2@latest
  github.com/BishopFox/jsluice/cmd/jsluice@latest
  github.com/d3mondev/puredns/v2@latest
  github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
  github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
  github.com/sa7mon/s3scanner/cmd/s3scanner@latest
  github.com/gwen001/github-subdomains@latest
  github.com/projectdiscovery/chaos-client/cmd/chaos@latest
)
for mod in "${GO_TOOLS[@]}"; do
  ok "go install ${mod%@*}"
  go install -v "$mod" || warn "failed: $mod (skipped)"
done

ok "Installing Python tools"

# graphql-cop has no setup.py/pyproject.toml — clone + pip install deps
ok "Installing graphql-cop (clone + pip)"
if [[ ! -d "$HOME/graphql-cop" ]]; then
  git clone --depth 1 https://github.com/dolevf/graphql-cop.git "$HOME/graphql-cop" 2>/dev/null || true
fi
if [[ -f "$HOME/graphql-cop/requirements.txt" ]]; then
  pip3 install --break-system-packages -r "$HOME/graphql-cop/requirements.txt" 2>/dev/null \
    || pip3 install -r "$HOME/graphql-cop/requirements.txt" 2>/dev/null || true
  ln -sf "$HOME/graphql-cop/graphql-cop.py" "$GOPATH/bin/graphql-cop" 2>/dev/null \
    || sudo ln -sf "$HOME/graphql-cop/graphql-cop.py" /usr/local/bin/graphql-cop 2>/dev/null || true
  chmod +x "$HOME/graphql-cop/graphql-cop.py" 2>/dev/null || true
fi

if command -v pipx >/dev/null 2>&1; then
  pipx install clairvoyance || true
  pipx install git+https://github.com/r0oth3x49/ghauri.git || true
  pipx install trufflehog || true
  pipx install git+https://github.com/initstring/cloud_enum.git || true
  pipx install arjun || true
  pipx install git-dumper || true
  ln -sf ~/.local/bin/cloud_enum ~/.local/bin/cloud-enum 2>/dev/null || true
  ln -sf "$GOPATH/bin/s3scanner" "$GOPATH/bin/S3Scanner" 2>/dev/null || true
fi

if ! command -v massdns >/dev/null 2>&1; then
  ok "Building massdns (needed by puredns)"
  git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null \
    && make -C /tmp/massdns >/dev/null 2>&1 \
    && sudo cp /tmp/massdns/bin/massdns /usr/local/bin/ 2>/dev/null || warn "massdns skipped (puredns will fall back to dnsx)"
fi

ok "Installing websocat (WebSocket / CSWSH audit support)"
if ! command -v websocat >/dev/null 2>&1; then
  # Pinned to a known-good release. `latest/download/...` occasionally 404s when
  # release asset names change; pinning keeps this reproducible.
  WEBSOCAT_VER="v1.14.1"
  ARCH_WS="$(uname -m)"
  case "$ARCH_WS" in
    x86_64|amd64)         WS_ASSET="websocat.x86_64-unknown-linux-musl" ;;
    aarch64|arm64)        WS_ASSET="websocat.aarch64-unknown-linux-musl" ;;
    *)                    WS_ASSET="" ;;
  esac
  if [[ -n "$WS_ASSET" ]]; then
    curl -fsSL -o /tmp/websocat "https://github.com/vi/websocat/releases/download/${WEBSOCAT_VER}/${WS_ASSET}" \
      && chmod +x /tmp/websocat \
      && sudo mv /tmp/websocat /usr/local/bin/websocat \
      || warn "websocat install skipped (optional, only used by Step 31 WebSocket audit)"
  else
    warn "websocat: no prebuilt binary for arch '$ARCH_WS' — skipping (optional, only used by Step 31)"
  fi
fi

ok "Installing custom nuclei templates -> ~/nuclei-templates/custom/"
mkdir -p "$HOME/nuclei-templates/custom"
cp "$SCRIPT_DIR"/nuclei-templates/custom/*.yaml "$HOME/nuclei-templates/custom/" 2>/dev/null || true
command -v nuclei >/dev/null 2>&1 && nuclei -update-templates 2>/dev/null || true

ok "Installing gf patterns -> ~/.gf/"
mkdir -p "$HOME/.gf"
cp "$SCRIPT_DIR"/gf-patterns/*.json "$HOME/.gf/" 2>/dev/null || true

ok "Setting up wordlists (SecLists & JWT wordlists)"
mkdir -p "$HOME/bugbounty/wordlists/dns" "$HOME/bugbounty/wordlists/content" "$HOME/bugbounty/wordlists/jwt"
[[ -d "$HOME/SecLists" ]] || git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$HOME/SecLists" 2>/dev/null || true
cp "$HOME/SecLists/Discovery/DNS/dns-Jhaddix.txt" "$HOME/bugbounty/wordlists/dns/best-dns-wordlist.txt" 2>/dev/null || true
cp "$HOME/SecLists/Discovery/Web-Content/raft-medium-directories.txt" "$HOME/bugbounty/wordlists/content/raft-medium-directories.txt" 2>/dev/null || true
printf 'secret\npassword\n123456\nadmin\nchangeme\nkey\ntest\njwt_secret\nsuper_secret\nmy_secret\ndefault\ntoken\napi_key\napplication_secret\nhs256_key\nsigning_key\nmaster_key\nprivate_key\napp_secret\nqwerty\nletmein\nwelcome\nmonkey\ndragon\npassword1\nabc123\nsecret123\nroot\ntoor\nadmin123\npassw0rd\n' > "$HOME/bugbounty/wordlists/jwt/common-secrets.txt"

ok "Installing apex-recon.sh -> ~/bugbounty/"
mkdir -p "$HOME/bugbounty"
cp "$SCRIPT_DIR/apex-recon.sh" "$HOME/bugbounty/apex-recon.sh"
chmod +x "$HOME/bugbounty/apex-recon.sh"

if ! grep -q 'go/bin' "$HOME/.bashrc" 2>/dev/null; then
  { echo 'export GOPATH=$HOME/go'; echo 'export PATH=$PATH:$HOME/go/bin'; } >> "$HOME/.bashrc"
fi

echo
ok "Verifying install (doctor):"
"$HOME/bugbounty/apex-recon.sh" --check || true
echo
ok "Done. If PATH just changed:  source ~/.bashrc"
ok "Then run:  cd ~/bugbounty && ./apex-recon.sh target.com --full"
