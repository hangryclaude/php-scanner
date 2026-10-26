# Drop-in prompts — paste into Claude or Codex when php-scanner is cloned

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

## Any agent, plain prompt

```
In the php-scanner repo: run `php scanner.php <path> --json`, pipe it to `node triage.cjs`,
then summarize the confirmed vulnerabilities ranked by exploitability with file:line and fixes.
To prove them live: serve the site and run `node pentest.cjs <base-url>`.
```
