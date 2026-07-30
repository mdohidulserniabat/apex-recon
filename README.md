# Apex Recon — Advanced Bug Bounty Recon & Vuln-Triage Framework

> ⚠️ **LEGAL / SCOPE WARNING**
> Use this ONLY on assets you own or have **explicit written authorization** to test
> (bug bounty program scope, signed pentest contract, etc.). Unauthorized scanning is
> illegal in most countries. The active modes (`--full`, `--active-brute`, dalfox,
> ffuf, OOB injection) send intrusive traffic — keep them OFF unless the program
> allows active testing.

---

## 📁 Folder structure

```
apex-recon/
├── apex-recon.sh                 # main pipeline (34 stages)
├── setup.sh                      # installs all tools + copies configs into place
├── README.md                     # this file
├── gf-patterns/                  # copy to ~/.gf/
│   ├── xss.json
│   ├── ssrf.json
│   ├── sqli.json
│   ├── lfi.json
│   ├── redirect.json
│   ├── ssti.json
│   ├── rce.json
│   └── idor.json
└── nuclei-templates/
    └── custom/                   # copy to ~/nuclei-templates/custom/
        ├── csp-weakness.yaml
        ├── exposed-sensitive-files.yaml
        ├── open-redirect.yaml
        ├── error-sqli-detect.yaml
        └── takeover-fingerprint.yaml
```

Where things end up after `setup.sh`:

```
~/bugbounty/apex-recon.sh              # the script you run
~/.gf/*.json                           # gf patterns
~/nuclei-templates/custom/*.yaml       # your custom templates
~/bugbounty/wordlists/dns/...          # DNS brute wordlist
~/bugbounty/wordlists/content/...      # content-discovery wordlist
recon_<target>_<UTCstamp>/             # per-run output (created where you run)
```

---

## 🚀 Install (one command)

```bash
unzip apex-recon-toolkit.zip
cd apex-recon
chmod +x setup.sh apex-recon.sh
./setup.sh                 # installs Go/Python tools, SecLists, copies configs
```

Add Go bin to your PATH (if setup.sh didn't):

```bash
echo 'export GOPATH=$HOME/go'        >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Manual install (if you skip setup.sh)

```bash
# copy configs
mkdir -p ~/.gf ~/nuclei-templates/custom
cp gf-patterns/*.json ~/.gf/
cp nuclei-templates/custom/*.yaml ~/nuclei-templates/custom/
nuclei -update-templates
```

---

## 🧪 Usage

```bash
# Safe / passive-leaning run (default)
./apex-recon.sh target.com

# Full run: active checks, OOB SSRF, GraphQL introspection, screenshots, ffuf, Dalfox
./apex-recon.sh target.com --full

# Full + active DNS bruteforce (LOUD — authorized only)
./apex-recon.sh target.com --full --active-brute
```

### Scope and authenticated seeds

```bash
# One authorized root or wildcard domain per line, e.g. example.com or *.example.com
export SCOPE_FILE="$PWD/scope.txt"

# URLs captured after login; merged into crawl seeds after scope validation
export AUTH_URLS_FILE="$PWD/authenticated-urls.txt"
./apex-recon.sh example.com --full
```

### Optional API keys (better subdomain coverage)

`GITHUB_TOKEN` enables `github-subdomains`; `CHAOS_KEY` enables ProjectDiscovery
Chaos. The scan works without them, but those two sources are skipped when their
respective key is absent. Create tokens only from the provider's official
dashboard, use the minimum access needed, and give them an expiry date. Never
put a real token in this README, a command-history screenshot, a Git commit, or
Telegram.

```bash
# Current shell only (recommended for a one-off authorized scan)
export GITHUB_TOKEN="github_pat_..."
export CHAOS_KEY="..."

./apex-recon.sh example.com --full --active-brute
```

For GitHub, create a fine-grained personal access token in **Settings →
Developer settings → Personal access tokens**. Restrict its resource owner and
repository access as much as possible; an organization may require approval.
For Chaos, sign in to ProjectDiscovery Cloud and copy the API key from
**Settings → API Key**.

To retain the variables across new Bash sessions, add the following lines to
`~/.bashrc` (replace the placeholders locally), then open a new terminal or run
`source ~/.bashrc`:

```bash
export GITHUB_TOKEN="github_pat_..."
export CHAOS_KEY="..."
```

For Docker, pass existing environment variables without putting their values in
the command line:

```bash
docker run --rm -it -v "$PWD/out:/out" \
  -e GITHUB_TOKEN -e CHAOS_KEY \
  apex-recon example.com --full --active-brute
```

The run writes `burp/targets.txt`, `burp/urls-prioritized.txt`, and
`validation/high-confidence-queue.txt` for manual reproduction and triage.

### Authenticated scanning

```bash
export AUTH_COOKIE="session=eyJhbGci...; csrftoken=abc123"
export AUTH_HEADER="Authorization: Bearer eyJ..."
# optional 2nd header:
export AUTH_HEADER2="X-Api-Key: 8f3c..."
./apex-recon.sh app.target.com --full
```

### Blind SSRF / OOB (interactsh)

```bash
# default public server oast.pro; or self-host:
export INTERACTSH_SERVER="oob.yourdomain.com"
./apex-recon.sh target.com --full
# check callbacks:  recon_*/oob/interactions.jsonl
```

> **Note:** the default `oast.pro` is a shared public server operated by a third
> party. Injected payloads and any callback metadata (source IPs, timing,
> target-derived tokens) transit that infrastructure. For engagements with strict
> confidentiality requirements (private bounty programs, client pentests, NDAs),
> self-host your own interactsh server and set `INTERACTSH_SERVER` to it instead
> of relying on the public default.

### Telegram notifications

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_CHAT_ID="987654321"
```

### Tunables (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `RATE_LIMIT` | 150 | requests/sec cap |
| `CONCURRENCY` | 25 | worker concurrency |
| `HTTPX_THREADS` | 50 | httpx threads |
| `NUCLEI_CONCURRENCY` | `CONCURRENCY` | Nuclei worker concurrency |
| `NUCLEI_BULK_SIZE` | 50 | Nuclei targets per batch |
| `NUCLEI_TIMEOUT` | 20 | Per-request Nuclei timeout in seconds |
| `NUCLEI_RETRIES` | 2 | Nuclei retry count for transient failures |
| `NUCLEI_PROFILE` | balanced | `full` runs all installed official templates; use only where authorized |
| `NUCLEI_SEVERITIES` | low,medium,high,critical | Nuclei severities; info is excluded by default |
| `MAX_ACTIVE_URLS` | 800 | cap for prioritized Dalfox/SQLi targets |
| `UPDATE_NUCLEI_TEMPLATES` | false | set `true` to update templates during a run |
| `SCOPE_FILE` | empty | authorized root/wildcard scope list |
| `AUTH_URLS_FILE` | empty | in-scope authenticated crawl seeds |
| `WORDLIST_DNS` | SecLists dns-Jhaddix | DNS brute list |
| `WORDLIST_CONTENT` | raft-medium-directories | ffuf list |
| `INTERACTSH_SERVER` | oast.pro | OOB server |
| `OOB_SETUP_TIMEOUT` | 45 | Seconds to wait for Interactsh payload registration |
| `HTTP_TIMEOUT` | 20 | Per-request timeout for active HTTP checks, in seconds |
| `HTTP_CONNECT_TIMEOUT` | 10 | HTTP connection timeout, in seconds |
| `BUCKET_TIMEOUT` | 20 | Per-request cloud-storage probe timeout, in seconds |

---

## 🔎 Pipeline stages

1. Subdomain & ASN/CIDR enumeration (subfinder/assetfinder/amass/github-subdomains + mapcidr)
2. DNS resolution + permutation (dnsx, alterx/puredns brute in `--active-brute`)
3. Live HTTP probe + tech-stack fingerprinting (httpx, auth-aware)
4. Subdomain takeover detection (nuclei + subzy + custom fingerprints)
5. Port discovery (naabu, optional)
6. Interactsh OOB listener + blind-SSRF injection (`--full`)
7. Comprehensive URL + JS discovery (katana/gau/wayback, scope-filtered)
8. Param discovery + gf vuln bucketing + SSRF payload injection
9. JavaScript analysis (jsluice secrets + endpoints)
10. GraphQL discovery + introspection + graphql-cop audit
11. Advanced CSP evaluation, bypass surface detection + exploit chain
12. Security header audit (HSTS, X-Content-Type-Options, Referrer-Policy, cookie flags)
13. Screenshots (gowitness, `--full`)
14. Content discovery (ffuf, auth-aware, `--full`)
15. Cloud storage bucket permutation + public-access enumeration (S3/GCS/Azure)
16. Nuclei CVE + misconfig + exposure (auth + OOB-aware)
17. Active XSS (dalfox, auth-aware, `--full`)
18. Active SQLi (`--full`)
19. Client & server prototype pollution detection
20. JWT / auth token security analysis (alg:none, weak-secret brute)
21. CORS misconfiguration (advanced origin bypass)
22. Open redirect (advanced filter-bypass vectors)
23. SSTI — server-side template injection (multi-engine vectors)
24. LFI / path traversal (WAF-evading, multi-OS vectors)
25. CRLF injection (`--full`)
26. Host header injection & IP spoofing (multi-header vectors)
27. 403 bypass (headers, methods, path tricks)
28. Web cache poisoning & cache deception
29. Race condition detection (parallel request bursting)
30. HTTP request smuggling (CL-TE / TE-CL desync detection)
31. WebSocket security audit (CSWSH & handshake vulnerabilities)
32. Next.js deep security & route module (RSC, middleware bypass, image optimizer)
33. AI / LLM endpoint discovery & audit
34. Summary + diff scanning + interactive HTML report + Telegram notify

Output lands in `recon_<target>_<UTCstamp>/`; start at `summary.txt` or `report.html`.

---

## ⚠️ Safety notes

- `--active-brute`, `ffuf`, `dalfox`, and OOB injection generate **intrusive** traffic. Only enable inside authorized active-testing scope.
- Respect program rate-limit rules; lower `RATE_LIMIT`/`CONCURRENCY` if asked.
- The gf/nuclei findings are **candidates**, not confirmed bugs — always manually verify before reporting.
- Never point authenticated cookies/headers at a domain you don't control the account on.

---

## 🐳 Option B: Docker (runs identically on ANY Linux/macOS — recommended)

No tool-install headaches. All tools are baked into the image.

```bash
unzip apex-recon-toolkit.zip
cd apex-recon
chmod +x run-docker.sh

# Build once (few minutes), then run anywhere. Output -> ./out on your host
./run-docker.sh target.com --full
```

Manual Docker (same thing):

```bash
docker build -t apex-recon .
docker run --rm -it -v "$PWD/out:/out" apex-recon target.com --full
# authenticated / OOB / telegram via -e:
docker run --rm -it -v "$PWD/out:/out" \
  -e AUTH_COOKIE="session=..." -e INTERACTSH_SERVER="oob.you.com" \
  apex-recon app.target.com --full
```

Results appear in `./out/recon_target.com_<stamp>/`.

---

## 🩺 Troubleshooting / "it stopped" checklist

The script is now **fail-safe**: any single tool that is missing, errors, or
returns empty is skipped — it will NOT halt the whole run.

1. **Check what's installed** (no target needed):
   ```bash
   ./apex-recon.sh --check
   ```
   `[MISS]` on a CORE tool = run `./setup.sh` (or use Docker). `[ -- ]` on an
   OPTIONAL tool just means that stage is auto-skipped.

2. **Watch the live log** while it runs:
   ```bash
   ./apex-recon.sh target.com --full 2>&1 | tee run.txt
   # or, from another shell:
   tail -f recon_*/logs/run.log
   ```

3. **Nothing found?** Even with zero subdomains, the apex domain itself is
   always scanned, so you still get httpx/nuclei/gf output.

4. **DNS empty?** If `puredns` has no `massdns`, the script auto-falls back to
   `dnsx`. Docker handles this for you.

5. Still stuck on a specific stage? Send the last few lines of
   `recon_*/logs/run.log`.

### What changed for robustness
- Removed `set -e`/`-u` (kept `pipefail`) — benign non-zero exits no longer kill the run; works on old bash too.
- Added `--check` doctor + a single clear preflight message (no mid-run death on a missing tool).
- puredns → dnsx DNS fallback; apex domain always included.
- Dockerfile with every tool preinstalled for identical behaviour anywhere.
