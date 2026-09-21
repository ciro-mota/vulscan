FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS builder

RUN apk add \
    ca-certificates \
    nmap \
    nmap-scripts \
    wget --no-cache

WORKDIR /vulscan

COPY vulscan.nse .

RUN wget -q -O known_exploited_vulnerabilities.csv https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv && \
    wget -q -O files_exploits.csv https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv

FROM chainguard/wolfi-base:latest@sha256:1d95114038f76513a9ace6fca107d5582b08c65981f81f61cb56bf7fd2ef216d AS vulscan-distroless

LABEL org.opencontainers.image.title="Vulscan"
LABEL org.opencontainers.image.description="Advanced vulnerability scanning with Nmap NSE."
LABEL org.opencontainers.image.authors="Ciro Mota <github.com/ciro-mota> (@ciro-mota)"
LABEL org.opencontainers.image.url="https://github.com/ciro-mota/vulscan"
LABEL org.opencontainers.image.documentation="https://github.com/ciro-mota/vulscan/README.md"
LABEL org.opencontainers.image.source="https://github.com/ciro-mota/vulscan"

COPY --from=builder /usr/share/nmap/nse_main.lua /usr/share/nmap/
COPY --from=builder /usr/share/nmap/scripts/ /usr/share/nmap/scripts/
COPY --from=builder /usr/share/nmap/nselib/ /usr/share/nmap/nselib/
COPY --from=builder /vulscan /usr/share/nmap/scripts/vulscan

RUN apk add --no-cache nmap \
    libcap \
    libcap-utils \
    libxslt \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /scan

ENTRYPOINT ["nmap"]
CMD ["--help"]