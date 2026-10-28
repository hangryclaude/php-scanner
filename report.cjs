#!/usr/bin/env node
// report.cjs — summarise ledger.jsonl (and the per-site findings) into a table.
//
// Usage: node report.cjs [--ledger=ledger.jsonl] [--reports=reports] [--json] [--csv]
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const arg = (n, d) => { const h = argv.find((a) => a.startsWith(`--${n}=`)); return h ? h.split('=').slice(1).join('=') : d; };
const LEDGER = arg('ledger', 'ledger.jsonl');
const REPORTS = arg('reports', 'reports');
const asJson = argv.includes('--json');
const asCsv = argv.includes('--csv');

if (!fs.existsSync(LEDGER)) { console.error(`no ${LEDGER} yet — run run-all.cjs first`); process.exit(2); }

// latest record wins (a recheck appends rather than rewrites)
const byApex = new Map();
for (const line of fs.readFileSync(LEDGER, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  try { const r = JSON.parse(line); byApex.set(r.apex, r); } catch {}
}
const rows = [...byApex.values()].sort((a, b) => {
  const score = (r) => Object.values(r.agents || {}).reduce((s, a) => s + (a.confirmed || 0), 0);
  return score(b) - score(a) || a.apex.localeCompare(b.apex);
});

// which rules were *candidates* across the run
const ruleCount = {};
for (const r of rows) {
  const f = path.join(REPORTS, `${r.apex.replace(/[^a-z0-9.-]/gi, '_')}.findings.json`);
  if (!fs.existsSync(f)) continue;
  try {
    for (const x of JSON.parse(fs.readFileSync(f, 'utf8')).findings || []) {
      ruleCount[x.rule] = (ruleCount[x.rule] || 0) + 1;
    }
  } catch {}
}

const tally = { sites: rows.length, vulnerable: 0, unproven: 0, clean: 0, failed: 0, confirmed: 0, unconfirmed: 0 };
for (const r of rows) {
  tally[r.verdict === 'vulnerable' ? 'vulnerable' : r.status === 'failed' ? 'failed' : r.verdict === 'clean' ? 'clean' : 'unproven']++;
  for (const a of Object.values(r.agents || {})) { tally.confirmed += a.confirmed || 0; tally.unconfirmed += a.unconfirmed || 0; }
}

if (asJson) {
  console.log(JSON.stringify({ tally, rules: ruleCount, rows }, null, 2));
  process.exit(0);
}
if (asCsv) {
  console.log('apex,url,verdict,findings,claude,codex,grok');
  for (const r of rows) {
    const g = (k) => (r.agents?.[k]?.confirmed ?? '');
    console.log([r.apex, r.url, r.verdict || r.status, r.findings, g('claude'), g('codex'), g('grok')]
      .map((v) => (String(v ?? '').includes(',') ? `"${v}"` : v)).join(','));
  }
  process.exit(0);
}

console.log(`\n${'SITE'.padEnd(34)} ${'CAND'.padEnd(5)} ${'CLAUDE'.padEnd(7)}${'CODEX'.padEnd(7)}${'GROK'.padEnd(6)} VERDICT`);
console.log('-'.repeat(78));
for (const r of rows) {
  const g = (k) => String(r.agents?.[k]?.confirmed ?? '-');
  console.log(`${(r.apex || '').slice(0, 33).padEnd(34)} ${String(r.findings ?? 0).padEnd(5)} ` +
    `${g('claude').padEnd(7)}${g('codex').padEnd(7)}${g('grok').padEnd(6)} ${r.verdict || r.status}`);
}
console.log('-'.repeat(78));
console.log(`${tally.sites} sites · ${tally.vulnerable} proven · ${tally.unproven} unproven · ${tally.clean} clean · ${tally.failed} failed`);
console.log(`${tally.confirmed} agent-confirmed findings (${tally.unconfirmed} refuted attempts)`);
const rules = Object.entries(ruleCount).sort((a, b) => b[1] - a[1]);
if (rules.length) console.log(`candidate rules: ${rules.map(([k, v]) => `${k}×${v}`).join(', ')}`);
