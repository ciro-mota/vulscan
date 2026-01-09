# Vulscan-Nmap - Vulnerability Scanning with Nmap

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/ciro-mota/vulscan/docker-publish.yml?style=for-the-badge&logo=github)
![Docker Image Size](https://img.shields.io/docker/image-size/ciromota/vulscan-nmap/latest?style=for-the-badge&logo=Linux-Containers)

## 📖 Introduction

Vulscan-Nmap is a module which enhances `Nmap` to find vulnerability in systems. The `-sV` option enables version detection per service, which is used to identify potential flaws according to the detected product versions. The vulnerability data is looked up in updated offline databases.

## ⚠️ Disclaimer

> [!NOTE]
> This is a fork of the [scipag/vulscan](https://github.com/scipag/vulscan) project, which is no longer actively maintained. This version includes significant modifications and updated vulnerability databases.

This vulnerability scanning tool relies on:
- Nmap's version detection accuracy
- Completeness of vulnerability databases
- Pattern matching accuracy

The existence of potential flaws is not verified through additional scanning or exploitation techniques. Results should be validated manually.

## 🗄️ Vulnerability Databases

This containerized version uses up-to-date vulnerability public databases from official sources:

* **CISA KEV** (Known Exploited Vulnerabilities) - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
* **Exploit-DB** - https://www.exploit-db.com

These databases are automatically downloaded during the Docker image build process, ensuring you always have recent vulnerability data.

> [!IMPORTANT]
> An image is automatically generated every Monday to ensure that the databases are always up-to-date in the image.

## 📋 Requirements

- Docker or Podman.
- `--privileged` flag (required for Nmap network scanning capabilities).

## 🚀 Quick Start

### Docker Usage

**Basic scan (terminal output):**

```bash
docker container run -it --privileged vulscan-nmap -sV --script=vulscan/vulscan.nse example.com
```

**Scan with HTML report and without terminal output:**

```bash
mkdir -p ~/reports && docker run --rm --privileged -v ~/reports:/scan \
  --entrypoint /bin/sh vulscan-nmap -c \
  'nmap -sV --script=vulscan/vulscan.nse -oX /scan/report.xml "$@" > /dev/null && \
   xsltproc /scan/report.xml -o /scan/report.html && \
   rm /scan/report.xml && \
   echo "Report saved: ~/reports/report.html"' \
  _ 192.168.1.100
```

> [!TIP]
> Change `example.com` and/or `192.168.1.100` to the desired target.

### Docker Compose

```bash
TARGET=192.168.1.100 docker-compose up -d
```

## 🔨 Custom Build

- Uncomment line 5 in `docker-compose.yml` for build and run:

```bash
docker buildx build -t vulscan-nmap .
```

## ⚙️ Script Arguments

### Version Detection

Disable additional version matching (may reduce false-positives):

```bash
--script-args vulscanversiondetection=0
```

### Show All Matches

Display all vulnerability matches (may increase false-positives):

```bash
--script-args vulscanshowall=1
```

### Interactive Mode

Override version detection results for each port:

```bash
--script-args vulscaninteractive=1
```

### Output Formats

Use predefined report structures:

```bash
--script-args vulscanoutput=details
--script-args vulscanoutput=listid
--script-args vulscanoutput=listlink
--script-args vulscanoutput=listtitle
```

Custom output format:

```bash
--script-args vulscanoutput='[{id}] {title} - {link}\n'
```

**Available template variables:**
* `{id}` - Vulnerability ID
* `{title}` - Vulnerability title
* `{matches}` - Number of matches
* `{product}` - Matched product string(s)
* `{version}` - Matched version string(s)
* `{link}` - Link to vulnerability database entry
* `\n` - Newline
* `\t` - Tab

![vulscan-nmap in a terminal execution](/assets/vulscan-terminal.png)