#!/usr/bin/env node
// run-all.cjs — drive the whole live pipeline over a target list, resumably.
//
//   discover.cjs  -> targets.jsonl
//   probe.cjs     -> findings per target (zero tokens)
//   pentest.cjs   -> claude + codex + grok prove them with curl
//
// Usage: node run-all.cjs [--targets=targets.jsonl] [--agents=claude,codex,grok]
//                          [--limit=0] [--only=apex,apex] [--recheck]
//
// Everything is appended to ledger.jsonl, so a crash / ctrl-c just resumes:
// a target already marked done is skipped unless --recheck is passed.
const { execFile, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const argv = process.argv.slice(2);
const arg = (n, d) => { const h = argv.find((a) => a.startsWith(`--${n}=`)); return h ? h.split('=').slice(1).join('=') : d; };
const TARGETS = arg('targets', 'targets.jsonl');
const LEDGER = arg('ledger', 'ledger.jsonl');
const AGENTS = arg('agents', 'claude,codex,grok');
const LIMIT = parseInt(arg('limit', '0'), 10);
const ONLY = (arg('only', '') || '').split(',').filter(Boolean);
const RECHECK = argv.includes('--recheck');
const REPORTS = arg('reports', 'reports');
const TIMEOUT_MIN = parseInt(arg('timeout', '25'), 10);

fs.mkdirSync(REPORTS, { recursive: true });

const done = new Set();
if (fs.existsSync(LEDGER) && !RECHECK) {
  for (const line of fs.readFileSync(LEDGER, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try { const r = JSON.parse(line); if (r.status === 'done') done.add(r.apex); } catch {}
  }
}

function runNode(script, args, opts = {}) {
  return new Promise((res) => {
    const cp = spawn('node', [path.join(__dirname, script), ...args], { cwd: __dirname, env: process.env });
    let stdout = '', stderr = '';
    const timer = setTimeout(() => { try { cp.kill('SIGKILL'); } catch {} }, (opts.timeoutMin || TIMEOUT_MIN) * 60000);
    cp.stdout.on('data', (c) => { stdout += c; if (stdout.length > 8e6) stdout = stdout.slice(-8e6); });
    cp.stderr.on('data', (c) => { stderr += c; if (stderr.length > 2e6) stderr = stderr.slice(-2e6); });
    cp.on('close', (code) => { clearTimeout(timer); res({ code, stdout, stderr }); });
    if (opts.input) { cp.stdin.write(opts.input); cp.stdin.end(); } else cp.stdin.end();
  });
}

const counts = (report) => {
  // Agents phrase the summary differently ("Final count: 1 confirmed, 0 unconfirmed"
  // vs "1 confirmed, 0 unconfirmed, 0 safe/not-testable"), so match the shape, not
  // the prefix.
  const tail = /(\d+)\s*CONFIRMED,\s*(\d+)\s*UNCONFIRMED/i.exec(report);
  if (tail) return { confirmed: +tail[1], unconfirmed: +tail[2] };
  // Fallback: count finding lines — they carry a rule id (XSS.LIVE, CMD.001 …).
  const sectionCount = (label) => {
    const re = new RegExp(`${label}[^\\n]*\\n([\\s\\S]*?)(?=\\n(?:CONFIRMED|UNCONFIRMED|SAFE/NOT-TESTABLE)[^\\n]*\\n|$)`, 'i');
    const m = re.exec(report);
    if (!m) return 0;
    // Count FINDING lines only: a rule id at the start of a line, not one merely
    // mentioned mid-sentence (agents love citing a rule id inside their evidence).
    return (m[1].match(/^\s*(?:[-*]\s*)?\[?[A-Z][A-Z0-9]{2,}\.[A-Z0-9.]+/gm) || []).length;
  };
  return { confirmed: sectionCount('CONFIRMED'), unconfirmed: sectionCount('UNCONFIRMED') };
};

(async () => {
  const targets = fs.readFileSync(TARGETS, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    .filter((t) => !ONLY.length || ONLY.includes(t.apex))
    .filter((t) => !done.has(t.apex));
  const todo = LIMIT > 0 ? targets.slice(0, LIMIT) : targets;
  console.error(`\n${todo.length} targets to run (${done.size} already done)\n`);

  const summary = { done: 0, clean: 0, failed: 0, confirmed: 0, unconfirmed: 0 };
  for (const [i, t] of todo.entries()) {
    const slug = t.apex.replace(/[^a-z0-9.-]/gi, '_');
    const findingsFile = path.join(REPORTS, `${slug}.findings.json`);
    const reportFile = path.join(REPORTS, `${slug}.pentest.md`);
    const started = new Date().toISOString();
    const rec = { apex: t.apex, url: t.url, started, findings: 0, agents: {}, status: 'running' };

    process.stderr.write(`[${i + 1}/${todo.length}] ${t.apex} … probe `);

    // ---- 1. probe (free, deterministic) -----------------------------------
    let probe;
    try {
      probe = await runNode('probe.cjs', [t.url, '--json', `--out=${findingsFile}`], { timeoutMin: 10 });
      const data = JSON.parse(fs.readFileSync(findingsFile, 'utf8'));
      rec.findings = (data.findings || []).length;
      rec.notes = data.notes || [];
    } catch (e) {
      rec.status = 'failed';
      rec.error = 'probe: ' + e.message;
      process.stderr.write(`probe failed\n`);
      fs.appendFileSync(LEDGER, JSON.stringify(rec) + '\n');
      summary.failed++;
      continue;
    }

    if (rec.findings === 0) {
      rec.status = 'done';
      rec.verdict = 'clean';
      process.stderr.write(`clean (no candidates)\n`);
      fs.appendFileSync(LEDGER, JSON.stringify(rec) + '\n');
      summary.clean++;
      summary.done++;
      continue;
    }
    process.stderr.write(`${rec.findings} candidates → pentest(${AGENTS}) `);

    // ---- 2. pentest (agents prove it) --------------------------------------
    const pentest = await runNode('pentest.cjs', [t.url, `--agents=${AGENTS}`], {
      input: fs.readFileSync(findingsFile, 'utf8'),
    });
    fs.writeFileSync(reportFile, pentest.stdout + (pentest.stderr ? `\n\n--- stderr ---\n${pentest.stderr}` : ''));
    rec.report = reportFile;

    // Per-agent verdicts. pentest.cjs prints a "=====" / "CLAUDE (exit 0)" /
    // "=====" header, then the report in the NEXT chunk — so attribute every
    // chunk that follows a header to that agent until the next one turns up.
    let current = null;
    for (const block of pentest.stdout.split(/={20,}/)) {
      const m = /^\s*(CLAUDE|CODEX|GROK)\b/im.exec(block);
      if (m) { current = m[1].toLowerCase(); rec.agents[current] = { confirmed: 0, unconfirmed: 0 }; continue; }
      if (!current) continue;
      const c = counts(block);
      if (c.confirmed || c.unconfirmed) rec.agents[current] = c;
    }
    for (const c of Object.values(rec.agents)) {
      summary.confirmed += c.confirmed;
      summary.unconfirmed += c.unconfirmed;
    }

    rec.status = 'done';
    rec.verdict = Object.values(rec.agents).some((a) => a.confirmed > 0) ? 'vulnerable' : 'unproven';
    rec.finished = new Date().toISOString();
    fs.appendFileSync(LEDGER, JSON.stringify(rec) + '\n');
    summary.done++;
    const per = Object.entries(rec.agents).map(([k, v]) => `${k}:${v.confirmed}c/${v.unconfirmed}u`).join(' ');
    process.stderr.write(`→ ${rec.verdict} (${per || 'no agent output'})\n`);
  }

  console.error(`\ndone ${summary.done} (clean ${summary.clean}, failed ${summary.failed}) · ` +
    `confirmed ${summary.confirmed} · unconfirmed ${summary.unconfirmed}\nledger: ${LEDGER}\n`);
})();
