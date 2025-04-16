# MoshenaSec: A Comprehensive Cybersecurity Toolkit

MoshenaSec is a modular command-line toolkit for cybersecurity professionals, penetration testers, and bug bounty hunters. It provides a collection of tools for reconnaissance, threat intelligence, log analysis, phishing detection, and digital hygiene checks.

## Features

### 1. Recon & OSINT CLI Aggregator
- Combines tools like shodan, whois, crt.sh, dnsdumpster, and more
- Provides keyword search, email address scrapers, metadata extractors
- Colorized output and export to JSON/HTML

### 2. Threat Intel Feed CLI
- Fetches daily threat feeds from AlienVault OTX, MISP, AbuseIPDB, etc.
- Cross-references IPs/domains/files with known indicators
- Includes a local database that syncs for offline analysis
- CLI alert system for log monitoring

### 3. Log File Threat Detector
- Ingests .log, .pcap, .json, .csv files
- Runs regex/sigmatch to identify common threats (e.g., SQLi, brute force, CVE indicators)
- Lightweight, no ELK needed

### 4. Phishing Link Analyzer
- Analyzes URLs or emails
- Performs domain reputation checks, IP history, HTML deobfuscation
- Identifies suspicious patterns and phishing indicators

### 5. Digital Hygiene Toolkit
- Checks for exposed .git folders
- Identifies default admin portals
- Detects weak headers (X-Frame, CSP, etc.)
- Finds sensitive endpoints (e.g., /env, /debug, /backup.zip)

## Installation

### Debian/Ubuntu

\`\`\`bash
sudo dpkg -i moshenasec_1.0.0_all.deb
sudo apt-get install -f
\`\`\`

### Manual Installation

\`\`\`bash
git clone https://github.com/moshenasec/moshenasec.git
cd moshenasec
pip install -r requirements.txt
python setup.py install
\`\`\`

## Usage

### Reconnaissance

\`\`\`bash
moshenasec recon --domain example.com --all
moshenasec recon --ip 8.8.8.8 --shodan
moshenasec recon --email admin@example.com
\`\`\`

### Threat Intelligence

\`\`\`bash
moshenasec intel --fetch
moshenasec intel --check 192.168.1.1
moshenasec intel --alert
\`\`\`

### Log File Analysis

\`\`\`bash
moshenasec logdetect --file /var/log/apache2/access.log
moshenasec logdetect --directory /var/log --pattern "CVE-2021-44228"
\`\`\`

### Phishing Analysis

\`\`\`bash
moshenasec phishing --url https://suspicious-site.com
moshenasec phishing --file urls.txt --screenshot
\`\`\`

### Digital Hygiene

\`\`\`bash
moshenasec hygiene --target example.com --all
moshenasec hygiene --target example.com --git --headers
\`\`\`

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
\`\`\`

Finally, let's create a LICENSE file:
