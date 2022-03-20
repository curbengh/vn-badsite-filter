'use strict'

const { join } = require('path')
const { appendFile, readdir, readFile, rm, writeFile } = require('fs/promises')
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
    const parsedUrl = new URL(url)
    const domain = parsedUrl.hostname.replace(/\\/g, '').replace(/^(\*|www)\./, '')
    domains.add(domain)
  }
  for (const { url } of linksArray) {
    const parsedUrl = new URL(url)
    const domain = parsedUrl.hostname.replace(/\\/g, '').replace(/^www\./, '')
    domains.add(domain)
  }

  await writeFile(outputFile, Array.from(domains).join('\n'))
}

f()
