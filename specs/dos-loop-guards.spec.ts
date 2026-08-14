import * as assert from 'node:assert'
import { test } from 'node:test'
import { imageSize } from '../lib/index'

// Regression guards for CVE-2025-71329 (JXL/HEIF) and CVE-2025-71330 (ICNS):
// crafted container files with zero-length boxes/entries used to spin the
// parser loops forever. Each parse must return (or throw) quickly instead.
const withinBudget = (fn: () => void) => {
  const start = process.hrtime.bigint()
  try {
    fn()
  } catch {
    // a parse error is fine — a hang is not
  }
  const ms = Number(process.hrtime.bigint() - start) / 1e6
  assert.ok(ms < 250, `parsing took ${ms.toFixed(1)}ms — possible infinite loop`)
}

test('JXL: jxlp box with size 0 does not hang (CVE-2025-71329)', () => {
  const buf = Buffer.concat([
    Buffer.from([0, 0, 0, 12]),
    Buffer.from('JXL '),
    Buffer.from([0x0d, 0x0a, 0x87, 0x0a]),
    Buffer.from([0, 0, 0, 0]), // box size 0
    Buffer.from('jxlp'),
  ])
  withinBudget(() => imageSize(new Uint8Array(buf)))
})

test('ICNS: entry length 0 does not hang (CVE-2025-71330)', () => {
  const buf = Buffer.concat([
    Buffer.from('icns'),
    Buffer.from([0, 0, 0, 64]),
    Buffer.from('il32'),
    Buffer.from([0, 0, 0, 0]), // entry length 0
  ])
  withinBudget(() => imageSize(new Uint8Array(buf)))
})

test('HEIF: meta box with size 0 does not hang (CVE-2025-71329)', () => {
  const buf = Buffer.concat([
    Buffer.from([0, 0, 0, 20]),
    Buffer.from('ftyp'),
    Buffer.from('heic'),
    Buffer.from([0, 0, 0, 0, 0, 0, 0, 0]),
    Buffer.from([0, 0, 0, 0]), // meta box size 0
    Buffer.from('meta'),
  ])
  withinBudget(() => imageSize(new Uint8Array(buf)))
})
