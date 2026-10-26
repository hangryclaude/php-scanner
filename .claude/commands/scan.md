---
description: Scan a PHP codebase for vulnerabilities (static + AI triage)
argument: path
---

Scan the PHP codebase at "$1" for vulnerabilities using this repo's pipeline.

1. Run `php scanner.php "$1" --json` and capture the findings.
2. Pipe the JSON into `node triage.cjs` for AI triage (false-positive removal + ranking).
3. Present the confirmed, ranked vulnerabilities: rule, file:line, why exploitable, exploit sketch, fix.
4. Suggest `/pentest $1 http://127.0.0.1:8899` as the next step if the user wants live proof.
