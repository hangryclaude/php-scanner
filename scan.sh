#!/bin/zsh
# scan.sh <path> [base-url] — scan + AI triage (+ live pentest if a URL is given).
PHP=${PHP:-$(command -v php)}
DIR="${0:A:h}"
if [[ -n "$2" ]]; then
  "$PHP" "$DIR/scanner.php" "$1" --json | node "$DIR/pentest.cjs" "$2"
else
  "$PHP" "$DIR/scanner.php" "$1" --json | node "$DIR/triage.cjs"
fi
