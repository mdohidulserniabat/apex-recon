# apex-recon toolkit v2 — all tools preinstalled. Runs identically on any host with Docker.
# Build:  docker build -t apex-recon .
# Run:    docker run --rm -it -v "$PWD/out:/out" apex-recon target.com --full
FROM golang:1.26-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev build-essential && rm -rf /var/lib/apt/lists/*
ENV GOBIN=/tools GOFLAGS=-buildvcs=false CGO_ENABLED=1
RUN mkdir -p /tools && \
    for m in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
      github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
      github.com/projectdiscovery/alterx/cmd/alterx@latest \
      github.com/projectdiscovery/chaos-client/cmd/chaos@latest \
      github.com/owasp-amass/amass/v4/cmd/amass@master \
      github.com/tomnomnom/assetfinder@latest \
      github.com/tomnomnom/waybackurls@latest \
      github.com/tomnomnom/anew@latest \
      github.com/tomnomnom/gf@latest \
      github.com/tomnomnom/qsreplace@latest \
      github.com/tomnomnom/unfurl@latest \
      github.com/lc/gau/v2/cmd/gau@latest \
      github.com/hahwul/dalfox/v2@latest \
      github.com/PentestPad/subzy@latest \
      github.com/sensepost/gowitness@latest \
      github.com/ffuf/ffuf/v2@latest \
      github.com/BishopFox/jsluice/cmd/jsluice@latest \
      github.com/d3mondev/puredns/v2@latest \
      github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest \
      github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest \
      github.com/sa7mon/s3scanner@latest \
      github.com/gwen001/github-subdomains@latest ; do \
      echo ">> installing $m" ; \
      go install -v "$m" || { echo "!! retry $m (transient?)" ; sleep 3 ; go install -v "$m" ; } || echo "!! skipped $m" ; \
    done && \
    # Clean Go build/module cache to save ~5-8GB disk during Docker build
    go clean -cache -modcache && rm -rf /root/.cache /tmp/*
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /tools v3.96.0

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl jq git python3 python3-pip pipx chromium libpcap0.8 \
      sqlmap dnsutils nmap ncat bc openssl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /tools/ /usr/local/bin/
ENV PATH="/root/.local/bin:${PATH}"
# Chromium needs --no-sandbox when running as root inside Docker
ENV CHROMIUM_FLAGS="--no-sandbox --disable-gpu --disable-dev-shm-usage"
ENV CHROME_PATH="/usr/bin/chromium"
# graphql-cop has no setup.py/pyproject.toml — must clone + pip install deps
RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop && \
    pip3 install --break-system-packages -r /opt/graphql-cop/requirements.txt && \
    ln -sf /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop && \
    chmod +x /usr/local/bin/graphql-cop || true

RUN pipx install clairvoyance || true ; \
    pipx install git+https://github.com/r0oth3x49/ghauri.git || true ; \
    pipx install git+https://github.com/initstring/cloud_enum.git || true ; \
    pipx install arjun || true ; \
    pipx install git-dumper || true ; \
    ln -sf /usr/local/bin/s3scanner /usr/local/bin/S3Scanner 2>/dev/null || true ; \
    ln -sf /root/.local/bin/cloud_enum /root/.local/bin/cloud-enum 2>/dev/null || true

# Install websocat (WebSocket testing) — upstream repo is vi/websocat
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "amd64" ]; then \
      curl -fsSL -o /usr/local/bin/websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl && \
      chmod +x /usr/local/bin/websocat ; \
    fi || echo "websocat: skipped (optional)"

COPY nuclei-templates/custom/ /root/nuclei-templates/custom/
COPY gf-patterns/ /root/.gf/
COPY apex-recon.sh /usr/local/bin/apex-recon
COPY nuclei-templates /usr/local/bin/nuclei-templates
RUN chmod +x /usr/local/bin/apex-recon && (nuclei -update-templates || true)

# Wordlists: DNS, content discovery, JWT secrets
RUN mkdir -p /root/bugbounty/wordlists/dns \
             /root/bugbounty/wordlists/content \
             /root/bugbounty/wordlists/jwt \
             /root/bugbounty/wordlists/buckets && \
    curl -fsSL -o /root/bugbounty/wordlists/dns/best-dns-wordlist.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt" && \
    curl -fsSL -o /root/bugbounty/wordlists/content/raft-medium-directories.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" && \
    printf 'secret\npassword\n123456\nadmin\nchangeme\nkey\ntest\njwt_secret\nsuper_secret\nmy_secret\ndefault\ntoken\napi_key\napplication_secret\nhs256_key\nsigning_key\nmaster_key\nprivate_key\napp_secret\nqwerty\nletmein\nwelcome\nmonkey\ndragon\npassword1\nabc123\nsecret123\nroot\ntoor\nadmin123\npassw0rd\n' > /root/bugbounty/wordlists/jwt/common-secrets.txt

WORKDIR /out
# ---------------------------------------------------------------------------
# Final pass: whatever failed to install above (usually a transient network
# blip) gets ONE more attempt here, then the full tool inventory is printed
# into the build log so any still-missing tool is immediately visible.
# NOTE: Go tools live in the build stage (no Go toolchain here), so a Go tool
# that failed both build-stage attempts can't be retried at this layer — the
# inventory will flag it as MISS so you can rebuild. Python/curl tools CAN be
# retried here. This RUN never fails the build (best-effort).
# ---------------------------------------------------------------------------
RUN set +e ; \
    for spec in "clairvoyance=clairvoyance" \
                "ghauri=git+https://github.com/r0oth3x49/ghauri.git" \
                "cloud_enum=git+https://github.com/initstring/cloud_enum.git" \
                "arjun=arjun" \
                "git-dumper=git-dumper" ; do \
      bin="${spec%%=*}" ; pkg="${spec#*=}" ; \
      command -v "$bin" >/dev/null 2>&1 || { echo ">> retry pipx $bin" ; pipx install "$pkg" || true ; } ; \
    done ; \
    command -v trufflehog >/dev/null 2>&1 || { echo ">> retry trufflehog" ; \
      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        | sh -s -- -b /usr/local/bin v3.96.0 || true ; } ; \
    command -v websocat >/dev/null 2>&1 || { echo ">> retry websocat" ; \
      A=$(dpkg --print-architecture) ; \
      if [ "$A" = "amd64" ]; then \
        curl -fsSL -o /usr/local/bin/websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl \
          && chmod +x /usr/local/bin/websocat || true ; \
      fi ; } ; \
    command -v graphql-cop >/dev/null 2>&1 || { echo ">> retry graphql-cop" ; \
      git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop 2>/dev/null ; \
      pip3 install --break-system-packages -r /opt/graphql-cop/requirements.txt 2>/dev/null ; \
      ln -sf /opt/graphql-cop/graphql-cop.py /usr/local/bin/graphql-cop ; chmod +x /usr/local/bin/graphql-cop || true ; } ; \
    ln -sf /usr/local/bin/s3scanner /usr/local/bin/S3Scanner 2>/dev/null || true ; \
    ln -sf /root/.local/bin/cloud_enum /root/.local/bin/cloud-enum 2>/dev/null || true ; \
    echo "================= apex-recon image tool inventory =================" ; \
    miss=0 ; \
    for t in subfinder dnsx httpx katana nuclei naabu interactsh-client alterx chaos amass \
             assetfinder waybackurls anew gf qsreplace unfurl gau dalfox subzy gowitness \
             ffuf jsluice puredns crlfuzz mapcidr s3scanner S3Scanner github-subdomains trufflehog \
             clairvoyance ghauri cloud_enum cloud-enum arjun git-dumper graphql-cop \
             curl jq git python3 chromium sqlmap dig nmap ncat bc websocat openssl timeout ; do \
      if command -v "$t" >/dev/null 2>&1 ; then echo "  ok   $t" ; else echo "  MISS $t" ; miss=$((miss+1)) ; fi ; \
    done ; \
    echo "=================  missing: $miss  =================" ; true

ENTRYPOINT ["apex-recon"]
