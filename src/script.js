'use strict'

import { dirname, join } from 'node:path'
import { readFile, rm, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const { parse } = JSON

// __dirname is src/
const outputFile = join(__dirname, '../tmp/domains-raw.txt')
await rm(outputFile, { force: true })
const domainsPath = join(__dirname, '../tmp/blacklistdomains.json')

const domainsStr = await readFile(domainsPath)
const domainsArray = parse(domainsStr)

const domains = new Set()

for (const { url } of domainsArray) {
  let domain = ''
  if (URL.canParse(url)) {
    const urlObj = new URL(url)

    domain = urlObj.hostname
  } else {
    const urlArray = url.split('/')
    if (urlArray.length >= 3) domain = urlArray[2]
  }
  if (domain.length >= 1) {
    domains.add(domain
      .replace(/^\*\./, '')
      .replace(/\\/g, '')
      .replace(/^www\./, '')
    )
  }
}

await writeFile(outputFile, Array.from(domains).join('\n'))
