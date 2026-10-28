#!/usr/bin/env node
// discover.cjs — harvest live PHP URLs (from urlscan.io's public search API, no key),
// then verify each one is up and actually PHP before adding it to the target list.
//
// Usage: node discover.cjs [--count=100] [--out=targets.jsonl] [--min=0]
//
// One target per apex domain (politeness: you don't want to hammer one host 40 times),
// and it keeps the first URL per domain that has something to attack — a query string
// or a form — falling back to the bare page if that's all the domain has.
const { execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const argv = process.argv.slice(2);
const arg = (name, def) => {
  const hit = argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.split('=').slice(1).join('=') : def;
};
const COUNT = parseInt(arg('count', '100'), 10);
const OUT = arg('out', 'targets.jsonl');
const UA = arg('ua', 'php-scanner/1.0 (+https://github.com/hangryclaude/php-scanner; authorised-testing)');
const CONCURRENCY = parseInt(arg('concurrency', '6'), 10);
const CACHE = arg('cache', 'targets');

// Diversify by query so we don't get 100 WordPress malware droppers from one crawler.
// Each entry is [urlscan query, human label].
const QUERIES = [
  ['filename:index.php', 'php index'],
  ['filename:index.php AND page.domain:*.com', 'php index .com'],
  ['filename:index.php AND page.domain:*.co.uk', 'php index .co.uk'],
  ['filename:index.php AND page.domain:*.de', 'php index .de'],
  ['filename:index.php AND page.domain:*.it', 'php index .it'],
  ['filename:index.php AND page.domain:*.org', 'php index .org'],
  ['filename:index.php AND page.domain:*.nl', 'php index .nl'],
  ['filename:index.php AND page.domain:*.au', 'php index .au'],
  ['filename:contact.php', 'contact form'],
  ['filename:search.php', 'search form'],
  ['filename:login.php', 'login form'],
  ['filename:product.php', 'product page'],
  ['filename:detail.php', 'detail page'],
  ['filename:list.php', 'list page'],
  ['filename:id.php', 'id page'],
  ['filename:view.php', 'view page'],
  ['filename:page.php', 'page param'],
  ['filename:index.php AND page.url:*?*', 'php with query string'],
  ['filename:default.php', 'default.php'],
  ['filename:home.php', 'home.php'],
  ['filename:main.php', 'main.php'],
  ['filename:news.php', 'news page'],
  ['filename:blog.php', 'blog page'],
  ['filename:shop.php', 'shop page'],
  ['filename:cart.php', 'cart page'],
  ['filename:register.php', 'register form'],
  ['filename:signup.php', 'signup form'],
  ['filename:checkout.php', 'checkout form'],
  ['filename:download.php', 'download param'],
  ['filename:redirect.php', 'redirect param'],
  ['filename:profile.php', 'profile page'],
  ['filename:admin.php', 'admin page'],
  ['filename:item.php', 'item page'],
  ['filename:index.php AND page.domain:*.br', 'php .br'],
  ['filename:index.php AND page.domain:*.fr', 'php .fr'],
  ['filename:index.php AND page.domain:*.es', 'php .es'],
  ['filename:index.php AND page.domain:*.pl', 'php .pl'],
  ['filename:index.php AND page.domain:*.ru', 'php .ru'],
  ['filename:index.php AND page.domain:*.jp', 'php .jp'],
  ['filename:index.php AND page.domain:*.in', 'php .in'],
  ['filename:index.php AND page.domain:*.id', 'php .id'],
  ['filename:index.php AND page.domain:*.gr', 'php .gr'],
  ['filename:other.php', 'other.php'],
  ['filename:single.php', 'single page'],
  ['filename:category.php', 'category page'],
  ['filename:article.php', 'article page'],
  ['filename:event.php', 'event page'],
  ['filename:index.php AND page.domain:*.ch', 'php .ch'],
  ['filename:index.php AND page.domain:*.at', 'php .at'],
  ['filename:index.php AND page.domain:*.se', 'php .se'],
  ['filename:index.php AND page.domain:*.cz', 'php .cz'],
  ['filename:index.php AND page.domain:*.pt', 'php .pt'],
  ['filename:index.php AND page.domain:*.be', 'php .be'],
  ['filename:index.php AND page.domain:*.mx', 'php .mx'],
  ['filename:index.php AND page.domain:*.co', 'php .co'],
  ['filename:ajax.php', 'ajax endpoint'],
  ['filename:api.php', 'api endpoint'],
];

// urlscan caps how deep search_after will page, so walk time slices instead —
// each window is a different set of scans, not just the newest 400 again.
for (const [from, to] of [[1, 0], [3, 1], [7, 3], [14, 7], [30, 14]]) {
  for (const name of ['index.php', 'contact.php', 'product.php', 'login.php', 'news.php', 'page.php']) {
    QUERIES.push([`filename:${name} AND date:[now-${from}d TO now-${to}d]`, `${name} ${from}-${to}d`]);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function run(cmd, args, opts = {}) {
  return new Promise((res) => {
    execFile(cmd, args, { maxBuffer: 32e6, timeout: opts.timeout || 20000 }, (e, stdout) => {
      res({ code: e ? (e.code || 1) : 0, stdout: stdout || '', stderr: (e && e.stderr) || '' });
    });
  });
}

async function search(query, size, searchAfter) {
  const qs = new URLSearchParams({ q: query, size: String(size) });
  if (searchAfter) qs.set('search_after', searchAfter);
  const r = await run('curl', ['-sS', '-m', '25', `https://urlscan.io/api/v1/search/?${qs}`]);
  try { return JSON.parse(r.stdout); } catch { return { results: [] }; }
}

function normalise(u, pageDomain) {
  let url = u.trim();
  if (!/^https?:\/\//.test(url)) url = 'https://' + url;
  try {
    const p = new URL(url);
    p.hash = '';
    return { url: p.toString(), host: p.host, path: p.pathname, query: p.search };
  } catch { return null; }
}

// Fetch once, keep the body so the probe stage doesn't re-hit the site.
async function probeLive(url, dir) {
  const hdrFile = path.join(dir, 'headers.txt');
  const bodyFile = path.join(dir, 'body.html');
  const r = await run('curl', [
    '-sSL', '-m', '20', '--max-redirs', '4', '-A', UA,
    '-D', hdrFile, '-o', bodyFile, '-w', '%{http_code} %{url_effective} %{size_download} %{content_type}',
    url,
  ], { timeout: 30000 });
  const [code, finalUrl, size, ctype] = r.stdout.trim().split(' ');
  let headers = '';
  try { headers = fs.readFileSync(hdrFile, 'utf8'); } catch {}
  let body = '';
  try { body = fs.readFileSync(bodyFile, 'utf8'); } catch {}
  const poweredBy = (headers.match(/^x-powered-by:\s*PHP\/([\d.]+)/im) || [])[1] || '';
  const server = (headers.match(/^server:\s*(.+)$/im) || [])[1]?.trim() || '';
  const phpCookie = /PHPSESSID=/i.test(headers);
  const isPhp = !!poweredBy || phpCookie || /\.php(\?|$)/i.test(finalUrl || url);
  const title = (body.match(/<title[^>]*>([^<]{0,120})/i) || [])[1]?.trim() || '';
  const forms = (body.match(/<form[\s>]/gi) || []).length;
  const inputs = (body.match(/<input[\s>]/gi) || []).length;
  const links = (body.match(/<a[\s>][^>]*href=['"][^'"]*\?/gi) || []).length;
  const sha = crypto.createHash('sha1').update(body).digest('hex');
  return {
    status: parseInt(code, 10), finalUrl, bytes: parseInt(size, 10) || 0, ctype,
    phpVersion: poweredBy, server, phpCookie, isPhp,
    title, forms, inputs, queryLinks: links,
    sha, dir: path.relative(process.cwd(), dir),
  };
}

async function pool(items, n, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  }));
  return out;
}

(async () => {
  fs.mkdirSync(CACHE, { recursive: true });
  const seenApex = new Set();
  const seenSha = new Set();
  const candidates = [];
  // Top-up runs must not re-add what we already have.
  let existing = 0;
  if (fs.existsSync(OUT)) {
    for (const line of fs.readFileSync(OUT, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try { const t = JSON.parse(line); seenApex.add(t.apex); seenSha.add(t.sha); existing++; } catch {}
    }
  }
  const want = Math.max(0, COUNT - existing);
  if (existing) process.stderr.write(`${existing} already in ${OUT}, topping up ${want}\n`);
  if (!want) { process.stderr.write('nothing to do\n'); return; }

  // ---- 1. gather candidate URLs -------------------------------------------
  for (const [query, label] of QUERIES) {
    if (candidates.length >= want * 6) break;
    let searchAfter = null;
    for (let page = 0; page < 4; page++) {
      const j = await search(query, 100, searchAfter);
      const results = j.results || [];
      if (!results.length) break;
      for (const r of results) {
        const apex = r.page?.apexDomain || r.task?.apexDomain;
        if (!apex || seenApex.has(apex)) continue;
        seenApex.add(apex);
        const n = normalise(r.task?.url || r.page?.url || '', apex);
        if (!n) continue;
        candidates.push({ ...n, apex, via: label, seenAt: r.task?.time });
      }
      searchAfter = results[results.length - 1].sort?.join(',');
      if (!searchAfter) break;
      await sleep(1200); // be nice to urlscan
    }
    process.stderr.write(`  ${label}: ${candidates.length} candidates\n`);
  }
  process.stderr.write(`\n${candidates.length} unique-domain candidates; verifying live...\n`);

  // Prefer URLs that already carry a query string — those are the ones with
  // something to tamper with — then anything with a .php path.
  candidates.sort((a, b) => (b.query ? 1 : 0) - (a.query ? 1 : 0));

  // ---- 2. verify in batches until we have COUNT live PHP targets ------------
  const targets = [];
  const dead = { unreachable: 0, notPhp: 0, dupe: 0 };
  const BATCH = CONCURRENCY * 3;

  for (let start = 0; start < candidates.length && targets.length < want; start += BATCH) {
    const batch = candidates.slice(start, start + BATCH);
    const checked = await pool(batch, CONCURRENCY, async (c) => {
      const dir = path.join(CACHE, c.apex.replace(/[^a-z0-9.-]/gi, '_'));
      fs.mkdirSync(dir, { recursive: true });
      const live = await probeLive(c.url, dir);
      return { ...c, ...live };
    });
    for (const t of checked) {
      if (targets.length >= want) break;
      if (!t.status || t.status >= 400) { dead.unreachable++; continue; }
      if (!t.isPhp) { dead.notPhp++; continue; }
      if (t.bytes < 400) { dead.unreachable++; continue; }
      if (seenSha.has(t.sha)) { dead.dupe++; continue; } // parked/error-page clones
      seenSha.add(t.sha);
      targets.push({
        url: t.finalUrl || t.url, apex: t.apex, via: t.via, seenAt: t.seenAt,
        status: t.status, phpVersion: t.phpVersion, server: t.server, phpCookie: t.phpCookie,
        title: t.title, forms: t.forms, inputs: t.inputs, queryLinks: t.queryLinks,
        query: t.query, dir: t.dir, sha: t.sha, discoveredAt: new Date().toISOString(),
      });
      fs.appendFileSync(OUT, JSON.stringify(targets[targets.length - 1]) + '\n');
      process.stderr.write(`  + ${existing + targets.length}/${COUNT} ${t.apex}${t.query ? ' (has params)' : ''} ${t.status} ${t.forms}f/${t.inputs}i\n`);
    }
    await sleep(300);
  }

  process.stderr.write(`\n${targets.length} live PHP targets -> ${OUT}\n`);
  process.stderr.write(`dropped: ${dead.unreachable} unreachable, ${dead.notPhp} not-php, ${dead.dupe} duplicate-pages\n`);
})();
