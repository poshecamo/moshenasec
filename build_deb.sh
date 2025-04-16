#!/bin/bash

# Build Debian package for MoshenaSec

# Check if fpm is installed
if ! command -v fpm &> /dev/null; then
    echo "Error: fpm is not installed. Please install it first."
    echo "You can install it with: gem install fpm"
    exit 1
fi

# Create a temporary directory for the package
TEMP_DIR=$(mktemp -d)
PKG_DIR="$TEMP_DIR/moshenasec"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/python3/dist-packages/moshenasec"
mkdir -p "$PKG_DIR/usr/share/doc/moshenasec"
mkdir -p "$PKG_DIR/usr/share/man/man1"

# Copy files
cp -r modules "$PKG_DIR/usr/lib/python3/dist-packages/moshenasec/"
cp moshenasec.py "$PKG_DIR/usr/lib/python3/dist-packages/moshenasec/"
cp README.md "$PKG_DIR/usr/share/doc/moshenasec/"
cp LICENSE "$PKG_DIR/usr/share/doc/moshenasec/"

# Create the executable script
cat > "$PKG_DIR/usr/bin/moshenasec" << 'EOF'
#!/bin/bash
python3 /usr/lib/python3/dist-packages/moshenasec/moshenasec.py "$@"
EOF
chmod +x "$PKG_DIR/usr/bin/moshenasec"

# Create man page
cat > "$PKG_DIR/usr/share/man/man1/moshenasec.1" << 'EOF'
.TH MOSHENASEC 1 "April 2023" "MoshenaSec 1.0.0" "User Commands"
.SH NAME
moshenasec \- A comprehensive cybersecurity toolkit for penetration testing
.SH SYNOPSIS
.B moshenasec
[\fICOMMAND\fR] [\fIOPTIONS\fR]
.SH DESCRIPTION
MoshenaSec is a modular cybersecurity toolkit designed for penetration testing and security assessments.
.SH COMMANDS
.TP
.B recon
Reconnaissance and OSINT tools
.TP
.B intel
Threat intelligence feed aggregator
.TP
.B logdetect
Log file threat detector
.TP
.B phishing
Phishing link analyzer
.TP
.B hygiene
Digital hygiene toolkit
.SH OPTIONS
.TP
.B \-h, \-\-help
Show help message and exit
.TP
.B \-v, \-\-version
Show version information
.SH EXAMPLES
.TP
moshenasec recon --domain example.com
.TP
moshenasec intel --fetch
.TP
moshenasec logdetect --file /var/log/apache2/access.log
.TP
moshenasec phishing --url https://suspicious-site.com
.TP
moshenasec hygiene --target example.com --all
.SH AUTHOR
MoshenaSec Team <info@moshenasec.com>
.SH COPYRIGHT
Copyright \(co 2023 MoshenaSec Team
EOF
gzip -9 "$PKG_DIR/usr/share/man/man1/moshenasec.1"

# Create the Debian package
fpm -s dir -t deb -C "$TEMP_DIR" \
    --name moshenasec \
    --version 1.0.0 \
    --architecture all \
    --depends python3 \
    --depends python3-requests \
    --depends python3-colorama \
    --depends python3-dnspython \
    --depends python3-whois \
    --depends python3-tldextract \
    --maintainer "MoshenaSec Team <info@moshenasec.com>" \
    --description "A comprehensive cybersecurity toolkit for penetration testing" \
    --url "https://github.com/moshenasec/moshenasec" \
    --license MIT \
    --category security

# Clean up
rm -rf "$TEMP_DIR"

echo "Debian package created: moshenasec_1.0.0_all.deb"
