# VN Malicious Domains Blocklist

- Formats
  - [URL-based](#url-based)
  - [Domain-based](#domain-based)
  - [Wildcard asterisk](#wildcard-asterisk)
  - [Hosts-based](#hosts-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [URL-based (AdGuard)](#url-based-adguard)
  - [URL-based (Vivaldi)](#url-based-vivaldi)
  - [Dnsmasq](#dnsmasq)
  - [BIND zone](#bind)
  - [RPZ](#response-policy-zone)
  - [Unbound](#unbound)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Snort2](#snort2)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
  - [Splunk](#splunk)
  - [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Compressed version](#compressed-version)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

A blocklist of malicious (malware, scam, phishing) websites that are targeting Vietnamese users. Sourced from [api.chongluadao.vn](https://chongluadao.vn).

| Client | mirror 1 | mirror 2 | mirror 3 | mirror 4 | mirror 5 | mirror 6 |
| --- | --- | --- | --- | --- | --- | --- |
| [uBlock Origin](#url-based) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter.txt) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter.txt) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter.txt) | [link](https://malware-filter.pages.dev/vn-badsite-filter.txt) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter.txt) |
| [AdGuard Home/Pi-hole](#domain-based-adguard-home) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-agh.txt) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-agh.txt) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-agh.txt) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-agh.txt) | [link](https://malware-filter.pages.dev/vn-badsite-filter-agh.txt) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-agh.txt) |
| [AdGuard (browser extension)](#ip-based-adguard)  | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-ag.txt) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-ag.txt) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-ag.txt) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-ag.txt) | [link](https://malware-filter.pages.dev/vn-badsite-filter-ag.txt) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-ag.txt) |
| [Vivaldi/Brave](#url-based-vivaldi) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-vivaldi.txt) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-vivaldi.txt) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-vivaldi.txt) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-vivaldi.txt) | [link](https://malware-filter.pages.dev/vn-badsite-filter-vivaldi.txt) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-vivaldi.txt) |
| [Hosts](#hosts-based) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-hosts.txt) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-hosts.txt) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-hosts.txt) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-hosts.txt) | [link](https://malware-filter.pages.dev/vn-badsite-filter-hosts.txt) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-hosts.txt) |
| [Dnsmasq](#dnsmasq) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-dnsmasq.conf) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-dnsmasq.conf) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-dnsmasq.conf) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-dnsmasq.conf) | [link](https://malware-filter.pages.dev/vn-badsite-filter-dnsmasq.conf) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-dnsmasq.conf) |
| BIND [zone](#bind) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-bind.conf) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-bind.conf) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-bind.conf) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-bind.conf) | [link](https://malware-filter.pages.dev/vn-badsite-filter-bind.conf) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-bind.conf) |
| BIND [RPZ](#response-policy-zone) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-rpz.conf) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-rpz.conf) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-rpz.conf) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-rpz.conf) | [link](https://malware-filter.pages.dev/vn-badsite-filter-rpz.conf) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-rpz.conf) |
| [dnscrypt-proxy](#dnscrypt-proxy) | [names.txt](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-names.txt), [ips.txt](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://curbengh.github.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-names.txt), [ips.txt](https://curbengh.github.io/malware-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-names.txt), [ips.txt](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-names.txt), [ips.txt](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://malware-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-names.txt), [ips.txt](https://malware-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://vn-badsite-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-names.txt), [ips.txt](https://vn-badsite-filter.pages.dev/vn-badsite-filter-dnscrypt-blocked-ips.txt) |
| [blocky](#wildcard-asterisk) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-wildcard.txt) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-wildcard.txt) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-wildcard.txt) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-wildcard.txt) | [link](https://malware-filter.pages.dev/vn-badsite-filter-wildcard.txt) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-wildcard.txt) |
| [Snort2](#snort2) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-snort2.rules) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-snort2.rules) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-snort2.rules) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-snort2.rules) | [link](https://malware-filter.pages.dev/vn-badsite-filter-snort2.rules) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-snort2.rules) |
| [Snort3](#snort3) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-snort3.rules) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-snort3.rules) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-snort3.rules) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-snort3.rules) | [link](https://malware-filter.pages.dev/vn-badsite-filter-snort3.rules) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-snort3.rules) |
| [Suricata](#suricata) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-suricata.rules) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-suricata.rules) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-suricata.rules) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-suricata.rules) | [link](https://malware-filter.pages.dev/vn-badsite-filter-suricata.rules) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-suricata.rules) |
| [Splunk](#splunk) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter-splunk.csv) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter-splunk.csv) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter-splunk.csv) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter-splunk.csv) | [link](https://malware-filter.pages.dev/vn-badsite-filter-splunk.csv) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter-splunk.csv) |
| [Internet Explorer](#tracking-protection-list-ie) | [link](https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.tpl) | [link](https://curbengh.github.io/malware-filter/vn-badsite-filter.tpl) | [link](https://curbengh.github.io/vn-badsite-filter/vn-badsite-filter.tpl) | [link](https://malware-filter.gitlab.io/vn-badsite-filter/vn-badsite-filter.tpl) | [link](https://malware-filter.pages.dev/vn-badsite-filter.tpl) | [link](https://vn-badsite-filter.pages.dev/vn-badsite-filter.tpl) |

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [phishing-filter](https://gitlab.com/malware-filter/phishing-filter)
- [pup-filter](https://gitlab.com/malware-filter/pup-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)

## URL-based

Import the URL into uBO to subscribe.

**AdGuard Home** users should use [this blocklist](#domain-based-adguard-home).

## URL-based (AdGuard)

Import the following URL into AdGuard browser extensions to subscribe.

## URL-based (Vivaldi)

For Vivaldi, blocking level must be at least "Block Trackers". Import the URL into Vivaldi's **Tracker Blocking Sources** to subscribe.

For Brave, "Trackers & ads blocking" must be set to Aggressive. Import it under Shields > Content filtering > Add custom filter lists.

## Domain-based

This blocklist includes domains and IP addresses.

## Wildcard asterisk

This blocklist includes domains and IP addresses.

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses. Also compatible with Pi-hole.

## Hosts-based

This blocklist includes domains only.

## Dnsmasq

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/dnsmasq/vn-badsite-filter-dnsmasq.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnsmasq to use the blocklist:

`printf "\nconf-file=/usr/local/etc/dnsmasq/vn-badsite-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf`

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

## Response Policy Zone

This blocklist includes domains only.

## Unbound

This blocklist includes domains only.

Save the rulesets to "/usr/local/etc/unbound/vn-badsite-filter-unbound.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Unbound to use the blocklist:

`printf '\n  include: "/usr/local/etc/unbound/vn-badsite-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf`

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_names]
+  blocked_names_file = '/etc/dnscrypt-proxy/vn-badsite-filter-dnscrypt-blocked-names.txt'

[blocked_ips]
+  blocked_ips_file = '/etc/dnscrypt-proxy/vn-badsite-filter-dnscrypt-blocked-ips.txt'
```

## Snort2

Not compatible with [Snort3](#snort3).

Save the ruleset to "/etc/snort/rules/vn-badsite-filter-snort2.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/urlhaus-filter-snort2-online.rules\n" >> /etc/snort/snort.conf`

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

## Suricata

Save the ruleset to "/etc/suricata/rules/vn-badsite-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - vn-badsite-filter-suricata.rules
```

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/9.0.2/Knowledge/Aboutlookupsandfieldactions). This ruleset includes online URLs only.

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`.

Or use [malware-filter add-on](https://splunkbase.splunk.com/app/6970) to install this lookup and optionally auto-update it.

Columns:

| host | path | message | updated |
| --- | --- | --- | --- |
| example.com  | | vn-badsite-filter malicious website detected | 2022-12-21T12:34:56Z |
| example2.com | /some-path | vn-badsite-filter malicious website detected | 2022-12-21T12:34:56Z |

## Tracking Protection List (IE)

This blocklist includes domains and IP addresses. Supported in Internet Explorer 9+. [Install guide](https://superuser.com/a/550539)

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt.br
- Zstd: https://malware-filter.gitlab.io/malware-filter/vn-badsite-filter.txt.zstd

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.

## Repository Mirrors

https://gitlab.com/curben/blog#repository-mirrors

## License

[Creative Commons Zero v1.0 Universal](LICENSE-CC0.md) and [MIT License](LICENSE)

[api.chongluadao.vn](https://chongluadao.vn) (operated by Hieu Minh Ngo): [CC0](https://creativecommons.org/publicdomain/zero/1.0/)
