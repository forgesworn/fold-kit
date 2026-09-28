#!/usr/bin/env node
// Browser bundle check: esbuild each entry with --platform=browser, assert
// no `node:` import survives the bundle, and check a size budget (minified,
// and gzip). See EXTRACTION.md for the extraction this check belongs to.
//
// Run after `npm run build` (needs dist/ to exist).
import { existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import * as esbuild from 'esbuild'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const distIndex = join(root, 'dist', 'index.js')
const distLane = join(root, 'dist', 'lane.js')

if (!existsSync(distIndex) || !existsSync(distLane)) {
  console.error('bundle-check: dist/ is missing - run `npm run build` first')
  process.exit(1)
}

// Budgets are about 25% headroom over what the current build measures
// (index: 35.8 KB minified / 11.0 KB gzip; lane: 0.9 KB / 0.5 KB), tight
// enough to catch an accidental dependency or a bundled peer, loose enough
// not to fail on ordinary code growth.
const BUDGETS_KB = {
  index: { minified: 45, gzip: 14 },
  lane: { minified: 1.2, gzip: 0.7 },
}

let failed = false

for (const [name, entry] of [['index', distIndex], ['lane', distLane]]) {
  const result = esbuild.buildSync({
    entryPoints: [entry],
    bundle: true,
    minify: true,
    platform: 'browser',
    format: 'esm',
    write: false,
    // These are the peer dependencies; a real consumer supplies its own
    // copy (see README "Peer dependencies"), so they are not bundled here -
    // this check is about the kit's OWN code plus its one direct dependency
    // (@scure/base), not the whole dependency graph.
    external: ['nostr-tools', 'nostr-tools/*', '@noble/hashes/*', '@noble/curves/*'],
    logLevel: 'silent',
  })
  const code = result.outputFiles[0].text
  const minifiedKB = Buffer.byteLength(code, 'utf8') / 1024
  const gzipKB = gzipSync(code).length / 1024

  const nodeImports = [...code.matchAll(/from\s*["']node:[a-z/]+["']/g)].map((m) => m[0])
  if (nodeImports.length > 0) {
    failed = true
    console.error(`FAIL: ${name} bundle carries a node: import: ${nodeImports.join(', ')}`)
  }

  const budget = BUDGETS_KB[name]
  const overMinified = minifiedKB > budget.minified
  const overGzip = gzipKB > budget.gzip
  if (overMinified || overGzip) failed = true
  console.log(
    `${overMinified || overGzip ? 'FAIL' : 'ok  '} ${name}: minified ${minifiedKB.toFixed(1)} KB (budget ${budget.minified} KB), gzip ${gzipKB.toFixed(1)} KB (budget ${budget.gzip} KB)`,
  )
}

if (failed) {
  console.error('\nbundle-check: failed')
  process.exit(1)
}
console.log('\nbundle-check: no node: imports, both entries within budget')
