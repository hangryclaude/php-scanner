# Drop-in prompts — send php-scanner to any AI coding agent

Everything below assumes the agent has `git`, `php` (8+), `node` (18+) and a signed-in
`claude` and/or `codex` CLI. The static scan alone needs nothing but PHP.

## One-shot: the whole pipeline in a single prompt

Paste this to Claude Code, Codex, Cursor, or any agent with shell access. Fill in the
two placeholders (or drop the pentest sentence for a code-only audit):

```
Clone https://github.com/hangryclaude/php-scanner and audit the PHP site at <path-to-site> with it.

1. Run `php scanner.php <path> --json` (static scan, ~30 vulnerability rules).
2. Pipe the JSON into `node triage.cjs` for AI triage — drop false positives, rank the real exploitable bugs.
3. Serve the site with `php -S 127.0.0.1:8899 -t <path>` and run the live pentest:
   `php scanner.php <path> --json | node pentest.cjs http://127.0.0.1:8899`
   (or `--agents=claude` / `--agents=codex` for a single agent).
4. Report the confirmed vulnerabilities ranked by severity: rule, file:line, evidence, and the fix.

Rules: payloads must be harmless (echo/alert-style proofs only — no rm, no DROP, no defacement).
Only test servers I own or authorize.
```

No placeholders, straight demo on the bundled vulnerable sample site:

```
Clone https://github.com/hangryclaude/php-scanner. In the repo, run
`php -S 127.0.0.1:8899 -t testsite &` then
`php scanner.php testsite --json | node pentest.cjs http://127.0.0.1:8899`
and report every confirmed vulnerability with curl evidence and its fix.
```

## Claude Code / Claude Desktop

> /scan /path/to/php/site
> /pentest /path/to/php/site http://127.0.0.1:8899

(slash commands auto-load from `.claude/commands/` when you open this repo)

## Codex CLI

```
codex exec "Scan /path/to/php/site for vulnerabilities with php scanner.php, triage with triage.cjs, then report confirmed exploitable bugs ranked by severity."
```

```
codex exec "The site /path/to/php/site is running at http://127.0.0.1:8899 — pentest it with pentest.cjs (claude,codex agents) and report confirmed vulns with curl evidence."
```

## How the stages route AI

- **triage.cjs** uses a local AI stack (`~/Tools/lib/ai.cjs`, Ollama-first) when present,
  otherwise falls back to the `claude` CLI — works on a fresh clone with zero setup.
- **pentest.cjs** shells out to the `claude` and/or `codex` CLIs you pass via `--agents=`.
- Each agent's full pentest report is saved to `$TMPDIR/php-scanner/pentest/<agent>-report.md`.
