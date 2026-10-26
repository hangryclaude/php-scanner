#!/usr/bin/env node
// Triage php-scanner findings with a side AI (zero tokens in your coding session).
// AI routing, best available wins:
//   1. ~/Tools/lib/ai.cjs  — local-first stack (Ollama → free tiers → paid), if installed
//   2. `claude` CLI        — fallback so a fresh clone works out of the box
// Usage: php scanner.php <path> --json | node triage.cjs
const os = require('os');
const fs = require('fs');
const { execFile } = require('child_process');

function readStdin() {
  return new Promise((res) => {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (raw += c));
    process.stdin.on('end', () => res(raw));
  });
}

function askViaLocalStack(prompt, ai) {
  process.env.AI_PREFER_FREE = process.env.AI_PREFER_FREE || '0';
  return ai.ask(prompt, {
    system: 'You are a terse security auditor.',
    tier: 'smart', maxTokens: 2000, temperature: 0.1,
  });
}

function askViaClaudeCli(prompt) {
  return new Promise((res, rej) => {
    execFile('claude', ['-p', prompt, '--model', 'sonnet'], { maxBuffer: 20e6 },
      (e, stdout) => (e ? rej(e) : res(stdout.trim())));
  });
}

(async () => {
  const data = JSON.parse(await readStdin());
  const prompt = `You are a PHP security auditor. Below are static-analysis findings from a small website.
Filter out false positives, rank the REAL exploitable vulnerabilities (highest first), and for each give:
rule, file:line, why it's exploitable, and a one-line exploit sketch (GET/POST example).
End with a count of confirmed vulns. Be terse.

${JSON.stringify(data.findings)}`;

  const localStack = os.homedir() + '/Tools/lib/ai.cjs';
  const reply = fs.existsSync(localStack)
    ? await askViaLocalStack(prompt, require(localStack))
    : await askViaClaudeCli(prompt);
  console.log(reply);
})().catch((e) => { console.error('triage failed:', e.message); process.exit(1); });
