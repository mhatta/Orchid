#!/bin/sh
#
# Download Tor's current geoip database (IPv4 ranges to country codes) to
# data/geoip, where Orchid finds it when it runs in this directory.
#
# Tor makes the file from the IPFire Location database
# (https://location.ipfire.org/, CC BY-SA 4.0).
#
# Usage: tools/update-geoip.sh [output file]

set -eu

URL=https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/config/geoip
OUT=${1:-data/geoip}

mkdir -p "$(dirname "$OUT")"
tmp="$OUT.tmp.$$"
trap 'rm -f "$tmp"' EXIT

curl -fsSL -o "$tmp" "$URL"

# Sanity check: the file has a few hundred thousand "LOW,HIGH,CC" lines
lines=$(grep -c '^[0-9][0-9]*,[0-9][0-9]*,..$' "$tmp" || true)
if [ "$lines" -lt 100000 ]; then
    echo "$URL does not look like a geoip file ($lines ranges)" >&2
    exit 1
fi

mv "$tmp" "$OUT"
trap - EXIT
echo "Wrote $OUT ($lines ranges)"
