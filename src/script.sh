#!/bin/sh

if ! (set -o pipefail 2>/dev/null); then
  # dash does not support pipefail
  set -efx
else
  set -efx -o pipefail
fi

# bash does not expand alias by default for non-interactive script
if [ -n "$BASH_VERSION" ]; then
  shopt -s expand_aliases
fi

## Use GNU grep, busybox grep is not as performant
DISTRO=""
if [ -f "/etc/os-release" ]; then
  . "/etc/os-release"
  DISTRO="$ID"
fi

check_grep() {
  if [ -z "$(grep --help | grep 'GNU')" ]; then
    if [ -x "/usr/bin/grep" ]; then
      alias grep="/usr/bin/grep"
      check_grep
    else
      if [ "$DISTRO" = "alpine" ]; then
        echo "Please install GNU grep 'apk add grep'"
      else
        echo "GNU grep not found"
      fi
      exit 1
    fi
  fi
}
check_grep

if command -v bun &> /dev/null; then
  alias node="bun"
fi
node --version


rm -rf "tmp/"
mkdir -p "tmp/"
cd "tmp/"


# Prepare datasets
curl -L "https://api.chongluadao.vn/v2/blacklistdomains" -o "blacklistdomains.json"

# Extract tracking links
node "../src/script.js"

# Cleanup
cat "domains-raw.txt" | \
# exclude false positives
grep -F -vf "../src/exclude.txt" | \
sort -u > "domains.txt"

## Merge malware domains and URLs
CURRENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FIRST_LINE="! Title: VN Malicious Domains Blocklist\n! Description: Block malicious domains targeting Vietnamese users"
SECOND_LINE="! Updated: $CURRENT_TIME"
THIRD_LINE="! Expires: 1 day (update frequency)"
FOURTH_LINE="! Homepage: https://gitlab.com/malware-filter/vn-badsite-filter"
FIFTH_LINE="! License: https://gitlab.com/malware-filter/vn-badsite-filter#license"
SIXTH_LINE="! Source: https://api.chongluadao.vn/v2/blacklistdomains"
COMMENT_UBO="$FIRST_LINE\n$SECOND_LINE\n$THIRD_LINE\n$FOURTH_LINE\n$FIFTH_LINE\n$SIXTH_LINE"

mkdir -p "../public/"

cat "domains.txt" | \
sort | \
sed "1i $COMMENT_UBO" > "../public/vn-badsite-filter.txt"


# Adguard Home
cat "domains.txt" | \
sort | \
sed -e "s/^/||/g" -e "s/$/^/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard Home)/" > "../public/vn-badsite-filter-agh.txt"


# Adguard browser extension
cat "domains.txt" | \
sort | \
sed -e "s/^/||/g" -e "s/$/\$all/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard)/" > "../public/vn-badsite-filter-ag.txt"


# Vivaldi
cat "domains.txt" | \
sort | \
sed -e "s/^/||/g" -e "s/$/\$document/g" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (Vivaldi)/" > "../public/vn-badsite-filter-vivaldi.txt"


## Hash comment
# awk + head is a workaround for sed prepend
COMMENT=$(printf "$COMMENT_UBO" | sed "s/^!/#/g" | awk '{printf "%s\\n", $0}' | head -c -2)

cat "domains.txt" | \
sort | \
sed "1i $COMMENT" > "../public/vn-badsite-filter-domains.txt"


## Hosts file blocklist
cat "domains.txt" | \
sed "s/^/0.0.0.0 /g" | \
sed "1i $COMMENT" | \
sed "1s/Domains/Hosts/" > "../public/vn-badsite-filter-hosts.txt"


## Dnsmasq-compatible blocklist
cat "domains.txt" | \
sed "s/^/address=\//g" | \
sed "s/$/\/0.0.0.0/g" | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/dnsmasq Blocklist/" > "../public/vn-badsite-filter-dnsmasq.conf"


## BIND-compatible blocklist
cat "domains.txt" | \
sed 's/^/zone "/g' | \
sed 's/$/" { type master; notify no; file "null.zone.file"; };/g' | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/BIND Blocklist/" > "../public/vn-badsite-filter-bind.conf"


## DNS Response Policy Zone (RPZ)
CURRENT_UNIX_TIME="$(date +%s)"
RPZ_SYNTAX="\n\$TTL 30\n@ IN SOA rpz.malware-filter.gitlab.io. hostmaster.rpz.malware-filter.gitlab.io. $CURRENT_UNIX_TIME 86400 3600 604800 30\n NS localhost.\n"

cat "domains.txt" | \
sed "s/$/ CNAME ./g" | \
sed '1 i\'"$RPZ_SYNTAX"'' | \
sed "1i $COMMENT" | \
sed "s/^#/;/g" | \
sed "1s/Blocklist/RPZ Blocklist/" > "../public/vn-badsite-filter-rpz.conf"


## Unbound-compatible blocklist
cat "domains.txt" | \
sed 's/^/local-zone: "/g' | \
sed 's/$/" always_nxdomain/g' | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/Unbound Blocklist/" > "../public/vn-badsite-filter-unbound.conf"


## dnscrypt-proxy blocklists
# name-based
cat "domains.txt" | \
sed "1i $COMMENT" | \
sed "1s/Domains/Names/" > "../public/vn-badsite-filter-dnscrypt-blocked-names.txt"

# IPv4-based
cat "domains.txt" | \
sort | \
grep -E "^([0-9]{1,3}[\.]){3}[0-9]{1,3}$" | \
sed "1i $COMMENT" | \
sed "1s/Domains/IPs/" > "../public/vn-badsite-filter-dnscrypt-blocked-ips.txt"


## IE blocklist
COMMENT_IE="msFilterList\n$COMMENT\n: Expires=1\n#"

cat "domains.txt" | \
sed "s/^/-d /g" | \
sed "1i $COMMENT_IE" | \
sed "2s/Domains Blocklist/Hosts Blocklist (IE)/" > "../public/vn-badsite-filter.tpl"


set +x

## Snort & Suricata rulesets
rm -f "../public/vn-badsite-filter-snort2.rules" \
  "../public/vn-badsite-filter-snort3.rules" \
  "../public/vn-badsite-filter-suricata.rules" \
  "../public/vn-badsite-filter-splunk.csv"

SID="500000001"
while read DOMAIN; do
  SN_RULE="alert tcp \$HOME_NET any -> \$EXTERNAL_NET [80,443] (msg:\"vn-badsite-filter malicious website detected\"; flow:established,from_client; content:\"GET\"; http_method; content:\"$DOMAIN\"; content:\"Host\"; http_header; classtype:attempted-recon; sid:$SID; rev:1;)"

  SN3_RULE="alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:\"vn-badsite-filter malicious website detected\"; http_header:field host; content:\"$DOMAIN\",nocase; classtype:attempted-recon; sid:$SID; rev:1;)"

  SR_RULE="alert http \$HOME_NET any -> \$EXTERNAL_NET any (msg:\"vn-badsite-filter malicious website detected\"; flow:established,from_client; http.method; content:\"GET\"; http.host; content:\"$DOMAIN\"; classtype:attempted-recon; sid:$SID; rev:1;)"

  SP_RULE="\"$DOMAIN\",\"\",\"vn-badsite-filter malicious website detected\",\"$CURRENT_TIME\""

  echo "$SN_RULE" >> "../public/vn-badsite-filter-snort2.rules"
  echo "$SN3_RULE" >> "../public/vn-badsite-filter-snort3.rules"
  echo "$SR_RULE" >> "../public/vn-badsite-filter-suricata.rules"
  echo "$SP_RULE" >> "../public/vn-badsite-filter-splunk.csv"

  SID=$(( $SID + 1 ))
done < "domains.txt"


set -x

sed -i "1i $COMMENT" "../public/vn-badsite-filter-snort2.rules"
sed -i "1s/Blocklist/Snort2 Ruleset/" "../public/vn-badsite-filter-snort2.rules"

sed -i "1i $COMMENT" "../public/vn-badsite-filter-snort3.rules"
sed -i "1s/Blocklist/Snort3 Ruleset/" "../public/vn-badsite-filter-snort3.rules"

sed -i "1i $COMMENT" "../public/vn-badsite-filter-suricata.rules"
sed -i "1s/Blocklist/Suricata Ruleset/" "../public/vn-badsite-filter-suricata.rules"

sed -i -e "1i $COMMENT" -e '1i "host","path","message","updated"' "../public/vn-badsite-filter-splunk.csv"
sed -i "1s/Blocklist/Splunk Lookup/" "../public/vn-badsite-filter-splunk.csv"


cd ../
