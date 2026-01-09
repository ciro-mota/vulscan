FROM alpine:3.23 AS builder

RUN apk add \
    nmap \
    nmap-scripts \
    wget --no-cache

WORKDIR /vulscan

COPY vulscan.nse .

RUN wget -q https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv && \
    wget -q https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv

FROM cgr.dev/chainguard/wolfi-base:latest AS vulscan-distroless

LABEL org.opencontainers.image.title="Vulscan"
LABEL org.opencontainers.image.description="Advanced vulnerability scanning with Nmap NSE."
LABEL org.opencontainers.image.authors="Ciro Mota <github.com/ciro-mota> (@ciro-mota)"
LABEL org.opencontainers.image.url="https://github.com/ciro-mota/vulscan"
LABEL org.opencontainers.image.documentation="https://github.com/ciro-mota/vulscan/README.md"
LABEL org.opencontainers.image.source="https://github.com/ciro-mota/vulscan"

COPY --from=builder /usr/share/nmap/nse_main.lua /usr/share/nmap/
COPY --from=builder /usr/share/nmap/scripts /usr/share/nmap/
COPY --from=builder /usr/share/nmap/nselib /usr/share/nmap/
COPY --from=builder /vulscan /usr/share/nmap/scripts/vulscan

RUN apk add --no-cache nmap \
    libcap \
    libcap-utils \
    libxslt \
    && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /scan

ENTRYPOINT ["nmap"]
CMD ["--help"]