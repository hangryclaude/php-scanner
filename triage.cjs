#!/usr/bin/env node
// Triage php-scanner findings with a FREE side AI (Ollama/local first, via ~/Tools/lib/ai.cjs).
// Usage: php scanner.php <path> --json | node triage.cjs
const os = require('os');
process.env.AI_PREFER_FREE = process.env.AI_PREFER_FREE || '0'; // side AI = real Claude via Max plan ($0 marginal), no tokens here
const ai = require(os.homedir() + '/Tools/lib/ai.cjs');

function readStdin() {
  return new Promise((res) => {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (raw += c));
    process.stdin.on('end', () => res(raw));
  });
}

(async () => {
  const data = JSON.parse(await readStdin());
  const prompt = `You are a PHP security auditor. Below are static-analysis findings from a small website.
Filter out false positives, rank the REAL exploitable vulnerabilities (highest first), and for each give:
rule, file:line, why it's exploitable, and a one-line exploit sketch (GET/POST example).
End with a count of confirmed vulns. Be terse.

${JSON.stringify(data.findings)}`;

  const reply = await ai.ask(prompt, {
    system: 'You are a terse security auditor.',
    tier: 'smart', maxTokens: 2000, temperature: 0.1,
  });
  console.log(reply);
})().catch((e) => { console.error('triage failed:', e.message); process.exit(1); });
