'use strict'

import { dirname, join } from 'node:path'
import { readFile, rm, writeFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const { parse } = JSON

const f = async () => {
  // __dirname is src/
  const outputFile = join(__dirname, '../tmp/domains-raw.txt')
  await rm(outputFile, { force: true })
  const domainsPath = join(__dirname, '../tmp/blacklistdomains.json')
  const linksPath = join(__dirname, '../tmp/blacklistlinks.json')

  const domainsStr = await readFile(domainsPath)
  const domainsArray = parse(domainsStr)
  const linksStr = await readFile(linksPath)
  const linksArray = parse(linksStr)

  const domains = new Set()

  for (const { url } of domainsArray) {
    let parsedUrl = new URL('http://example.com')
    try {
      parsedUrl = new URL(url.replace(/\*\./g, ''))
    } catch {
      continue
    }
    const domain = parsedUrl.hostname.replace(/\\/g, '').replace(/^www\./, '')
    domains.add(domain)
  }
  for (const { url } of linksArray) {
    let parsedUrl = new URL('http://example.com')
    try {
      parsedUrl = new URL(url)
    } catch {
      continue
    }
    const domain = parsedUrl.hostname.replace(/\\/g, '').replace(/^www\./, '')
    domains.add(domain)
  }

  await writeFile(outputFile, Array.from(domains).join('\n'))
}

f()
