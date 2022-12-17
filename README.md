# VN Malicious Domains Blocklist

- Formats
  - [URL-based](#url-based)
  - [Domain-based](#domain-based)
  - [Hosts-based](#hosts-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [URL-based (AdGuard)](#url-based-adguard)
  - [URL-based (Vivaldi)](#url-based-vivaldi)
  - [Dnsmasq](#dnsmasq)
  - [BIND zone](#bind)
  - [RPZ](#response-policy-zone)
  - [Unbound](#unbound)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Tracking Protection List (IE)](#tracking-protection-list-ie)
  - [Snort2](#snort2)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
  * [Splunk](#splunk)
- [Compressed version](#compressed-version)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

A blocklist of malicious (malware, scam, phishing) websites that are targeting Vietnamese users. Sourced from [api.chongluadao.vn](https://chongluadao.vn).

There are multiple formats available, refer to the appropriate section according to the program used:

- uBlock Origin (uBO) -> [URL-based](#url-based) section (recommended)
- Pi-hole -> [Domain-based](#domain-based) or [Hosts-based](#hosts-based) section
- AdGuard Home -> [Domain-based (AdGuard Home)](#domain-based-adguard-home) or [Hosts-based](#hosts-based) section
- AdGuard (browser extension) -> [URL-based (AdGuard)](#url-based-adguard)
- Vivaldi -> [URL-based (Vivaldi)](#url-based-vivaldi)
- [Hosts](#hosts-based)
- [Dnsmasq](#dnsmasq)
- BIND -> BIND [zone](#bind) or [RPZ](#response-policy-zone)
- [Unbound](#unbound)
- [dnscrypt-proxy](#dnscrypt-proxy)
- Internet Explorer -> [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Snort2](#snort2)
- [Snort3](#snort3)
- [Suricata](#suricata)
- [Splunk](#splunk)

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [phishing-filter](https://gitlab.com/malware-filter/phishing-filter)
- [pup-filter](https://gitlab.com/malware-filter/pup-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)

## URL-based

Import the following URL into uBO to subscribe:

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter.txt
- https://malware-filter.pages.dev/vn-badsite-filter.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter.txt

</details>

**AdGuard Home** users should use [this blocklist](#domain-based-adguard-home).

## URL-based (AdGuard)

Import the following URL into AdGuard browser extensions to subscribe (includes online and **offline** malicious websites):

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-ag.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-ag.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-ag.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-ag.txt
- https://malware-filter.pages.dev/vn-badsite-filter-ag.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-ag.txt

</details>

## URL-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the following URL into Vivaldi's **Tracker Blocking Sources** to subscribe (includes online and **offline** malicious websites):

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-vivaldi.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-vivaldi.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-vivaldi.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-vivaldi.txt
- https://malware-filter.pages.dev/vn-badsite-filter-vivaldi.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-vivaldi.txt

</details>

## Domain-based

This blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-domains.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-domains.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-domains.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-domains.txt
- https://malware-filter.pages.dev/vn-badsite-filter-domains.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-domains.txt

</details>

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-agh.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-agh.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-agh.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-agh.txt
- https://malware-filter.pages.dev/vn-badsite-filter-agh.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-agh.txt

</details>

## Hosts-based

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-hosts.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-hosts.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-hosts.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-hosts.txt
- https://malware-filter.pages.dev/vn-badsite-filter-hosts.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-hosts.txt

</details>

## Dnsmasq

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/dnsmasq/vn-badsite-filter-dnsmasq.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnsmasq to use the blocklist:

`printf "\nconf-file=/usr/local/etc/dnsmasq/vn-badsite-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf`

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-dnsmasq.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-dnsmasq.conf
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-dnsmasq.conf
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-dnsmasq.conf
- https://malware-filter.pages.dev/vn-badsite-filter-dnsmasq.conf
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-dnsmasq.conf

</details>

## BIND

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/bind/vn-badsite-filter-bind.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure BIND to use the blocklist:

`printf '\ninclude "/usr/local/etc/bind/vn-badsite-filter-bind.conf";\n' >> /etc/bind/named.conf`

Add this to "/etc/bind/null.zone.file" (skip this step if the file already exists):

```
$TTL    86400   ; one day
@       IN      SOA     ns.nullzone.loc. ns.nullzone.loc. (
               2017102203
                    28800
                     7200
                   864000
                    86400 )
                NS      ns.nullzone.loc.
                A       0.0.0.0
@       IN      A       0.0.0.0
*       IN      A       0.0.0.0
```

Zone file is derived from [here](https://github.com/tomzuu/blacklist-named/blob/master/null.zone.file).

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-bind.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-bind.conf
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-bind.conf
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-bind.conf
- https://malware-filter.pages.dev/vn-badsite-filter-bind.conf
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-bind.conf

</details>

## Response Policy Zone

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-rpz.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-rpz.conf
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-rpz.conf
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-rpz.conf
- https://malware-filter.pages.dev/vn-badsite-filter-rpz.conf
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-rpz.conf

</details>

## Unbound

This blocklist includes domains only.

Save the rulesets to "/usr/local/etc/unbound/vn-badsite-filter-unbound.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Unbound to use the blocklist:

`printf '\n  include: "/usr/local/etc/unbound/vn-badsite-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf`

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-unbound.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-unbound.conf
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-unbound.conf
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-unbound.conf
- https://malware-filter.pages.dev/vn-badsite-filter-unbound.conf
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-unbound.conf

</details>

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_names]
+  blocked_names_file = '/etc/dnscrypt-proxy/vn-badsite-filter-dnscrypt-blocked-names.txt'

[blocked_ips]
+  blocked_ips_file = '/etc/dnscrypt-proxy/vn-badsite-filter-dnscrypt-blocked-ips.txt'
```

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-names.txt
- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-names.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-names.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-names.txt
- https://malware-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-names.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-names.txt

- https://curbengh.github.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt
- https://malware-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-ips.txt
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-ips.txt

</details>

## Tracking Protection List (IE)

This blocklist includes domains only. Supported in Internet Explorer 9+.

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.tpl

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter.tpl
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter.tpl
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter.tpl
- https://malware-filter.pages.dev/vn-badsite-filter.tpl
- https://vn-badsite-filter.pages.dev/vn-badsite-filter.tpl

</details>

## Snort2

Not compatible with [Snort3](#snort3).

Save the ruleset to "/etc/snort/rules/vn-badsite-filter-snort2.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/urlhaus-filter-snort2-online.rules\n" >> /etc/snort/snort.conf`

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-snort2.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-snort2.rules
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-snort2.rules
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-snort2.rules
- https://malware-filter.pages.dev/vn-badsite-filter-snort2.rules
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-snort2.rules

</details>

## Snort3

Not compatible with [Snort2](#snort2).

Save the ruleset to "/etc/snort/rules/vn-badsite-filter-snort3.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

```diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/vn-badsite-filter-snort3.rules'
}
```

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-snort3.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-snort3.rules
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-snort3.rules
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-snort3.rules
- https://malware-filter.pages.dev/vn-badsite-filter-snort3.rules
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-snort3.rules

</details>

## Suricata

Save the ruleset to "/etc/suricata/rules/vn-badsite-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - vn-badsite-filter-suricata.rules
```

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-suricata.rules
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-suricata.rules
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-suricata.rules
- https://malware-filter.pages.dev/vn-badsite-filter-suricata.rules
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-suricata.rules

</details>

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/9.0.2/Knowledge/Aboutlookupsandfieldactions). This ruleset includes online URLs only.

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`. Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) or [Getwatchlist](https://splunkbase.splunk.com/app/635) app for auto-update.

- https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-splunk.csv

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/vn-badsite-filter-splunk.csv
- https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-splunk.csv
- https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-splunk.csv
- https://malware-filter.pages.dev/vn-badsite-filter-splunk.csv
- https://vn-badsite-filter.pages.dev/vn-badsite-filter-splunk.csv

</details>

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt.br

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.

## License

[Creative Commons Zero v1.0 Universal](LICENSE.md)

[api.chongluadao.vn](https://chongluadao.vn) (operated by Hieu Minh Ngo): [CC0](https://creativecommons.org/publicdomain/zero/1.0/)
