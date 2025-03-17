import { createInterface } from 'node:readline'
import { createWriteStream } from 'node:fs'

const snort2 = createWriteStream('../public/vn-badsite-filter-snort2.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const snort3 = createWriteStream('../public/vn-badsite-filter-snort3.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const suricata = createWriteStream('../public/vn-badsite-filter-suricata.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const splunk = createWriteStream('../public/vn-badsite-filter-splunk.csv', {
  encoding: 'utf8',
  flags: 'a'
})

let sid = 500000001

for await (const domain of createInterface({ input: process.stdin })) {
  snort2.write(`alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"vn-badsite-filter malicious website detected"; flow:established,from_client; content:"GET"; http_method; content:"${domain}"; content:"Host"; http_header; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  snort3.write(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"vn-badsite-filter malicious website detected"; http_header:field host; content:"${domain}",nocase; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  suricata.write(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"vn-badsite-filter malicious website detected"; flow:established,from_client; http.method; content:"GET"; http.host; content:"${domain}"; classtype:attempted-recon; sid:${sid} rev:1;)\n`)
  splunk.write(`"$${domain}","","vn-badsite-filter malicious website detected","${process.env.CURRENT_TIME}"\n`)

  sid++
}

snort2.close()
snort3.close()
suricata.close()
splunk.close()
