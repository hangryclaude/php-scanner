# php-scanner — agent instructions (Claude Code & Codex)

This repo is a PHP vulnerability pipeline. When the user asks to "scan", "find vulns",
"pentest", or "hack" a PHP site/codebase, use these tools — do not eyeball the code yourself.

## Tools

| Command | What it does |
|---|---|
| `php scanner.php <path> [--json] [--min-severity=low]` | Static scan of a PHP codebase. Exit 1 = findings. |
| `php scanner.php <path> --json \| node triage.cjs` | AI triage: kills false positives, ranks exploitable bugs, adds exploit sketches. |
| `php scanner.php <path> --json \| node pentest.cjs <base-url> [--agents=claude,codex]` | Live pentest: agents run harmless curl proofs against the running site. |
| `./scan.sh <path> [base-url]` | Scan + triage (or pentest when URL given). |
| `php -S 127.0.0.1:8899 -t <docroot>` | Serve a site locally for pentesting. |

## Agent playbook

1. **Static scan first.** `php scanner.php <path> --json`. Never skip this — the AI stages
   consume its JSON.
2. **Triage** with `node triage.cjs` to drop false positives (the scanner's `unless` guards
   already reduce them, but confirm).
3. **Pentest only with the user's OK** and only against a local server or a target the user
   explicitly owns/authorizes. Pentest payloads must be harmless (echo/alert-style proof,
   never destructive).
4. Report CONFIRMED vulns first with file:line, evidence, and the fix.

## Rules for running the stages

- The static stage needs only `php` (8+).
- Triage and pentest need `node` plus the `claude` and/or `codex` CLI signed in.
- Pentest reports land under `php-scanner/pentest/` in the OS temp dir (`<agent>-report.md`).
- If a user gives a git URL, clone it to a temp dir and scan that.
