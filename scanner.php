#!/usr/bin/env php
<?php
/**
 * php-scanner — a dependency-free static security scanner for small PHP websites.
 *
 * Usage:
 *   php scanner.php <path> [--json] [--min-severity=info|low|medium|high] [--no-color]
 *
 * Scans .php/.phtml/.inc files for the issues that actually get small
 * websites popped: SQL injection, XSS, file inclusion, command injection,
 * deserialization, hardcoded credentials, debug leftovers, and misconfig.
 *
 * Exit codes: 0 = clean, 1 = findings at/above min severity, 2 = usage error.
 */

error_reporting(E_ALL & ~E_DEPRECATED);
mb_internal_encoding('UTF-8');

const SEVERITIES = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3];

// ---------------------------------------------------------------------------
// Rules. Each rule: id, severity, message, pattern (regex), and an optional
// lookFor sub-pattern used to confirm the sink is tainted (user input nearby).
// ---------------------------------------------------------------------------

$RULES = [
    // --- SQL injection -------------------------------------------------------
    [
        'id' => 'SQLI.001', 'severity' => 'high',
        'message' => 'Possible SQL injection: variable interpolated into a query',
        'pattern' => '/\b(?:mysql_query|mysqli_query|mysqli::query|mysqli_real_query|->query|->exec|->prepare)\s*\(\s*["\'](?:[^"\']*\{?\$|[^"\']*\.)/i',
        'unless'  => '/(?:prepare|bind_param|bindValue|bindParam|execute)\s*\(/i',
        'fix' => 'Use prepared statements (PDO::prepare / mysqli_prepare) and bind parameters.',
    ],
    [
        'id' => 'SQLI.002', 'severity' => 'high',
        'message' => 'Possible SQL injection: query built by string concatenation',
        'pattern' => '/\$(?:sql|query|q)\b.*?(?:\.\s*\$_(?:GET|POST|REQUEST|COOKIE)|["\']\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE))/ix',
        'fix' => 'Bind user input instead of concatenating it into the query.',
    ],
    [
        'id' => 'SQLI.003', 'severity' => 'medium',
        'message' => 'Raw user input used inside a query string',
        'pattern' => '/["\'][^"\']*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^"\']*["\']?\s*\.\s*\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
        'fix' => 'Escape with the right *_real_escape_string() or, better, use bound parameters.',
    ],

    // --- XSS ------------------------------------------------------------------
    [
        'id' => 'XSS.001', 'severity' => 'high',
        'message' => 'Unescaped superglobal echoed to the page (XSS)',
        'pattern' => '/\b(?:echo|print)\s+\$(?:_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
        'unless'  => '/htmlspecialchars|htmlentities|strip_tags|urlencode|json_encode/i',
        'fix' => 'Wrap in htmlspecialchars($x, ENT_QUOTES, \'UTF-8\') before output.',
    ],
    [
        'id' => 'XSS.002', 'severity' => 'medium',
        'message' => 'Unescaped variable echoed (check whether it carries user input)',
        'pattern' => '/\b(?:echo|print)\s+\$[a-z_][a-z0-9_]*\s*(?:\.|;)/i',
        'unless'  => '/htmlspecialchars|htmlentities|strip_tags|json_encode|\$row\[|\$line\b|\$count\b|\$i\b|\$total\b/i',
        'fix' => 'Escape output with htmlspecialchars().',
    ],
    [
        'id' => 'XSS.003', 'severity' => 'high',
        'message' => 'User input printed without escaping inside HTML',
        'pattern' => '/<\?=\s*\$(_GET|_POST|_REQUEST|_COOKIE)\s*\[/i',
        'unless'  => '/htmlspecialchars|htmlentities/i',
        'fix' => 'Use <?= htmlspecialchars($x, ENT_QUOTES, \'UTF-8\') ?>.',
    ],

    // --- Command injection -------------------------------------------------
    [
        'id' => 'CMD.001', 'severity' => 'high',
        'message' => 'Possible command injection via user input',
        'pattern' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'unless'  => '/escapeshellarg|escapeshellcmd/i',
        'fix' => 'Use escapeshellarg() on every user-controlled argument, or avoid shell calls.',
    ],
    [
        'id' => 'CMD.002', 'severity' => 'high',
        'message' => 'Backtick shell execution with interpolation',
        'pattern' => '/`[^`]*\$/',
        'fix' => 'Backticks interpolate variables — validate input or use escapeshellarg().',
    ],
    [
        'id' => 'CMD.003', 'severity' => 'medium',
        'message' => 'eval() usage',
        'pattern' => '/\beval\s*\(/i',
        'fix' => 'Avoid eval(); it executes arbitrary code if input is tainted.',
    ],

    // --- File inclusion / path traversal ------------------------------------
    [
        'id' => 'FILE.001', 'severity' => 'high',
        'message' => 'Possible remote/local file inclusion from user input',
        'pattern' => '/\b(?:include|include_once|require|require_once)\s*\(?\s*["\'][^"\']*["\']?\s*\.\s*\$|,\s*\$_(?:GET|POST|REQUEST)/i',
        'fix' => 'Whitelist allowed pages/values; never include a path built from user input.',
    ],
    [
        'id' => 'FILE.002', 'severity' => 'high',
        'message' => 'include/require of a superglobal directly',
        'pattern' => '/\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'fix' => 'Whitelist allowed pages; basename() alone is not enough.',
    ],
    [
        'id' => 'FILE.003', 'severity' => 'medium',
        'message' => 'File operation on user-controlled path (path traversal)',
        'pattern' => '/\b(?:fopen|file_get_contents|file_put_contents|unlink|readfile|fread|file)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'fix' => 'Normalize with realpath() and verify the path stays inside the intended directory.',
    ],

    // --- Deserialization / upload ------------------------------------------
    [
        'id' => 'DESER.001', 'severity' => 'high',
        'message' => 'unserialize() on user input (object injection / RCE)',
        'pattern' => '/\bunserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'fix' => 'Use json_decode() or unserialize($x, [\'allowed_classes\' => false]).',
    ],
    [
        'id' => 'UPLOAD.001', 'severity' => 'medium',
        'message' => 'File upload processed — verify extension/type checks exist',
        'pattern' => '/\$_FILES\b/',
        'fix' => 'Restrict extensions, check MIME server-side, store uploads outside the webroot or with random names.',
    ],

    // --- Credentials & config ------------------------------------------------
    [
        'id' => 'CRED.001', 'severity' => 'high',
        'message' => 'Hardcoded database password',
        'pattern' => '/(?:mysqli?_connect|new\s+(?:PDO|mysqli)|DB_PASS(?:WORD)?\s*=)\s*\(?\s*["\'][^"\']{4,}["\']/i',
        'fix' => 'Move credentials out of source control into environment variables.',
    ],
    [
        'id' => 'CRED.002', 'severity' => 'medium',
        'message' => 'Possible hardcoded password assignment',
        'pattern' => '/\$(?:pass|password|pwd|db_pass|dbpass)\w*\s*=\s*["\'][^"\']{4,}["\']/i',
        'fix' => 'Confirm this is not a production credential; prefer env vars.',
    ],
    [
        'id' => 'CRED.003', 'severity' => 'medium',
        'message' => 'Possible API key or token literal',
        'pattern' => '/\b(?:api[_-]?key|secret|token|access[_-]?key)\b["\']?\s*(?::|=>|=)\s*["\'][A-Za-z0-9_\-\.]{16,}["\']/i',
        'fix' => 'Rotate the key if real, and load it from the environment.',
    ],

    // --- Debug leftovers & misconfig ---------------------------------------
    [
        'id' => 'DEBUG.001', 'severity' => 'medium',
        'message' => 'Leftover debug dump of user input',
        'pattern' => '/\b(?:var_dump|print_r|debug_zval_dump)\s*\(\s*\$_(?:GET|POST|REQUEST)/i',
        'fix' => 'Remove debug output before shipping.',
    ],
    [
        'id' => 'DEBUG.002', 'severity' => 'low',
        'message' => 'display_errors may be enabled (information disclosure)',
        'pattern' => '/ini_set\s*\(\s*[\'"]display_errors[\'"]\s*,\s*[\'"]1[\'"]|display_errors\s*=\s*On/i',
        'fix' => 'Disable display_errors in production; log errors instead.',
    ],
    [
        'id' => 'MISC.001', 'severity' => 'medium',
        'message' => 'extract() on user input (variable injection)',
        'pattern' => '/\bextract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'fix' => 'Use EXTR_SKIP at minimum; better, read fields explicitly.',
    ],
    [
        'id' => 'MISC.002', 'severity' => 'medium',
        'message' => 'preg_replace /e modifier (code execution)',
        'pattern' => '/preg_replace\s*\(\s*["\'][^"\']*["\']e[^"\']*["\']\s*,/i',
        'fix' => 'Use preg_replace_callback() instead of the /e modifier.',
    ],
    [
        'id' => 'MISC.003', 'severity' => 'low',
        'message' => '$_REQUEST usage (ambiguous input source)',
        'pattern' => '/\$_REQUEST\s*\[/i',
        'fix' => 'Read $_GET or $_POST explicitly; $_REQUEST merges cookies too.',
    ],
    [
        'id' => 'SSRF.001', 'severity' => 'medium',
        'message' => 'Fetches a URL built from user input (SSRF / open redirect risk)',
        'pattern' => '/\b(?:curl_init|file_get_contents|fopen|header\s*\(\s*[\'"]Location[\'"])\s*\([^)]*\$_(?:GET|POST|REQUEST)/i',
        'fix' => 'Validate the URL host against an allowlist before fetching/redirecting.',
    ],
    [
        'id' => 'XSS.004', 'severity' => 'medium',
        'message' => 'Unescaped superglobal inside HTML attribute or body',
        'pattern' => '/<[^>]+>=?\s*\$(_GET|_POST|_REQUEST|_COOKIE)\s*\[[^\]]*\]/i',
        'fix' => 'Escape with htmlspecialchars().',
    ],

    // --- Redirects, mail, crypto, uploads ------------------------------------
    [
        'id' => 'REDIR.001', 'severity' => 'medium',
        'message' => 'Open redirect: header() target from user input',
        'pattern' => '/header\s*\(\s*[\'"]Location[\'"]\s*\.\s*["\']?\s*\.\s*\$_(?:GET|POST|REQUEST)|header\s*\(\s*[\'"]Location:\s*[\'"]?\s*\.\s*\$_(?:GET|POST|REQUEST)/i',
        'fix' => 'Validate the redirect target against an allowlist of hosts/paths.',
    ],
    [
        'id' => 'MAIL.001', 'severity' => 'medium',
        'message' => 'Email header injection: user input passed to mail()',
        'pattern' => '/\bmail\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'fix' => 'Strip \\r\\n from user input before passing to mail().',
    ],
    [
        'id' => 'UPLOAD.002', 'severity' => 'medium',
        'message' => 'Uploaded file moved — check extension/MIME validation exists',
        'pattern' => '/move_uploaded_file\s*\(/i',
        'fix' => 'Allowlist extensions, verify MIME with finfo, randomize stored filename.',
    ],
    [
        'id' => 'CRYPTO.001', 'severity' => 'low',
        'message' => 'Weak hash function (md5/sha1) — weak if used for passwords',
        'pattern' => '/\b(?:md5|sha1)\s*\(/i',
        'fix' => 'Use password_hash()/password_verify() for passwords.',
    ],
    [
        'id' => 'CRYPTO.002', 'severity' => 'medium',
        'message' => 'mt_rand/rand used where security matters (tokens/captcha)',
        'pattern' => '/\b(?:mt_)?rand\s*\(/i',
        'fix' => 'Use random_bytes()/random_int() for security values.',
    ],
    [
        'id' => 'AUTH.001', 'severity' => 'medium',
        'message' => 'Loose comparison against a secret (magic-hash risk)',
        'pattern' => '/[\'"][0-9a-f]{32}[\'"]\s*==|\$[a-z_]*token\w*\s*==\s*\$|==\s*["\']0e[0-9]+["\']/i',
        'fix' => 'Use hash_equals() or === for secret comparisons.',
    ],
    [
        'id' => 'LOGIC.001', 'severity' => 'low',
        'message' => 'Assignment inside a condition (= instead of ==)',
        'pattern' => '/\bif\s*\(\s*\$[a-z_]\w*\s*=\s*(?!=)[^)]+\)/i',
        'fix' => 'Likely a typo — use == for comparison.',
    ],

    // --- Info disclosure & classic small-site hits ---------------------------
    [
        'id' => 'INFO.001', 'severity' => 'medium',
        'message' => 'phpinfo() exposed (full config/paths/env disclosure)',
        'pattern' => '/\bphpinfo\s*\(/i',
        'fix' => 'Remove or gate phpinfo() behind auth.',
    ],
    [
        'id' => 'INFO.002', 'severity' => 'medium',
        'message' => 'Possible XXE: XML parsed with user input',
        'pattern' => '/\b(?:simplexml_load_string|simplexml_load_file|DOMDocument->loadXML?|xml_parse)\s*\([^)]*\$/i',
        'unless'  => '/libxml_disable_entity_loader|LIBXML_NOENT\s*[,)]*\s*0|libxml_set_external_entity_loader/i',
        'fix' => 'Parse with LIBXML_NOENT off (default) and never trust external entities.',
    ],
    [
        'id' => 'INFO.003', 'severity' => 'medium',
        'message' => 'Possible HTTP header injection via user input',
        'pattern' => '/\bheader\s*\(\s*[\'"]?[A-Za-z-]*:?[\'"]?\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)/i',
        'unless'  => '/str_replace|preg_replace|filter_var/i',
        'fix' => 'Strip \\r\\n from user input before header().',
    ],
    [
        'id' => 'INFO.004', 'severity' => 'low',
        'message' => 'php_uname / $_SERVER[SERVER_SOFTWARE] disclosed (fingerprinting)',
        'pattern' => '/\bphp_uname\s*\(|\$_SERVER\s*\[\s*[\'"]SERVER_SOFTWARE[\'"]\s*\]/i',
        'fix' => 'Avoid advertising server software versions.',
    ],
];

// PHP2Shell (CVE-2026-109618 / CVE-2026-109619): unauthenticated RCE in PHP itself.
// Patched branches => minimum SAFE version. Anything older (or EOL 7.x/8.0/8.1
// without the source backport) is vulnerable to in-the-wild exploitation.
const PHP2SHELL_SAFE = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
const PHP2SHELL_MSG = 'PHP2Shell RCE (CVE-2026-109618/109619): PHP %s is UNPATCHED — actively exploited in the wild via session.upload_progress multipart requests';

function php2shell_check(?string $version): ?array {
    if (!$version || !preg_match('/^(\d+)\.(\d+)(?:\.(\d+))?/', trim($version), $m)) return null;
    $major = (int)$m[1]; $minorS = $m[1] . '.' . $m[2];
    $patch = (int)($m[3] ?? 0);
    if ($major < 8 || in_array($minorS, ['8.0', '8.1'], true)) {
        // EOL branches: only rare minimal source backports exist — assume vulnerable.
        return [
            'rule' => 'PHP2SHELL.001', 'severity' => 'high',
            'message' => sprintf(PHP2SHELL_MSG, $version . ' (EOL branch)'),
            'file' => '(runtime PHP version)', 'line' => 0,
            'snippet' => "PHP $version — EOL branch, no official patched release",
            'fix' => 'Move to a supported branch with the PHP2Shell fix (8.2.35+/8.3.36+/8.4.27+/8.5.12+).',
        ];
    }
    if (!isset(PHP2SHELL_SAFE[$minorS])) return null; // unknown/future branch: assume patched
    $safe = (int)substr(PHP2SHELL_SAFE[$minorS], strrpos(PHP2SHELL_SAFE[$minorS], '.') + 1);
    if ($patch >= $safe) return null;
    return [
        'rule' => 'PHP2SHELL.001', 'severity' => 'high',
        'message' => sprintf(PHP2SHELL_MSG, $version . " < " . PHP2SHELL_SAFE[$minorS]),
        'file' => '(runtime PHP version)', 'line' => 0,
        'snippet' => "PHP $version — patch to " . PHP2SHELL_SAFE[$minorS] . '+ or latest',
        'fix' => 'Update PHP to ' . PHP2SHELL_SAFE[$minorS] . ' or newer. CVE-2026-109618/109619 are exploited unauthenticated, no app-code bug required.',
    ];
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function usage_and_exit(int $code = 2): void {
    fwrite(STDERR, "Usage: php scanner.php <path> [--json] [--min-severity=info|low|medium|high] [--no-color]\n");
    exit($code);
}

$args = $_SERVER['argv'];
array_shift($args);
$target = null;
$json = false;
$minSeverity = 'info';
$phpVersion = null;
$color = function_exists('posix_isatty') ? posix_isatty(STDOUT) : true;

foreach ($args as $a) {
    if ($a === '--json') { $json = true; }
    elseif ($a === '--no-color') { $color = false; }
    elseif (preg_match('/^--php-version=(.+)$/', $a, $m)) { $phpVersion = $m[1]; }
    elseif (preg_match('/^--min-severity=(.+)$/', $a, $m)) {
        $m[1] = strtolower(trim($m[1]));
        if (!isset(SEVERITIES[$m[1]])) usage_and_exit();
        $minSeverity = $m[1];
    }
    elseif ($a === '--help' || $a === '-h') usage_and_exit(0);
    elseif ($a[0] === '-') usage_and_exit();
    else { $target = $a; }
}
if ($target === null) usage_and_exit();
if (!is_dir($target) && !is_file($target)) {
    fwrite(STDERR, "Error: no such file or directory: $target\n");
    exit(2);
}

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

function find_php_files(string $target): array {
    if (is_file($target)) return [$target];
    $files = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS)
    );
    $skipDirs = ['vendor', 'node_modules', '.git', '.svn', 'bower_components'];
    foreach ($it as $f) {
        if (!$f->isFile()) continue;
        $ext = strtolower($f->getExtension());
        if (in_array($ext, ['php', 'phtml', 'inc', 'php3', 'php4', 'php5', 'phps'], true)) {
            $rel = str_replace(DIRECTORY_SEPARATOR, '/', $f->getPathname());
            $skip = false;
            foreach ($skipDirs as $d) { if (strpos($rel, "/$d/") !== false) { $skip = true; break; } }
            if (!$skip) $files[] = $f->getPathname();
        } elseif (preg_match('/\.(?:bak|old|orig|save|copy|dist)(?:\.|$)|~$/', $f->getFilename())) {
            $files[] = $f->getPathname(); // backup of a source file = source disclosure
        }
    }
    sort($files);
    return $files;
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

$files = find_php_files($target);
$findings = [];
$filesScanned = 0;
$bytesScanned = 0;
$skipped = 0;
$startTime = microtime(true);

// --- PHP2Shell (CVE-2026-109618/109619) runtime-version check -------------
// Priority: --php-version flag > live hints found in the tree.
$declaredVersion = $phpVersion ?? null;           // from --php-version=
if ($declaredVersion === null && is_dir($target)) {
    // composer.json platform/require, Dockerfile FROM php:x.y, .php-version, .tool-versions
    foreach ([
        ['composer.json', '/"php"\s*:\s*"[\^~>=< ]*(\d+\.\d+(?:\.\d+)?)/'],
        ['Dockerfile', '/FROM\s+php:(\d+\.\d+(?:\.\d+)?)/i'],
        ['.php-version', '/^\s*(\d+\.\d+(?:\.\d+)?)\s*$/m'],
        ['.tool-versions', '/^php\s+(\d+\.\d+(?:\.\d+)?)/m'],
    ] as [$hintFile, $hintRe]) {
        $p = rtrim($target, '/') . '/' . $hintFile;
        if (is_file($p)) {
            $c = @file_get_contents($p);
            if ($c && preg_match($hintRe, $c, $hm)) { $declaredVersion = $hm[1]; break; }
        }
    }
}
if ($f = php2shell_check($declaredVersion)) $findings[] = $f;

foreach ($files as $file) {
    $size = filesize($file);
    if ($size === false) { $skipped++; continue; }
    if ($size > 2 * 1024 * 1024) { $skipped++; continue; } // skip monsters
    $code = @file_get_contents($file);
    if ($code === false) { $skipped++; continue; }
    if (substr_count($code, "\n") + 1 > 50000) { $skipped++; continue; }
    $filesScanned++;
    $bytesScanned += $size;

    // Backup/source-disclosure file itself is a finding.
    if (preg_match('/\.(?:bak|old|orig|save|copy|dist)(?:\.|$)|~$/i', $file)) {
        $findings[] = [
            'rule'     => 'INFO.005',
            'severity' => 'medium',
            'message'  => 'Backup file left in the tree — likely fetchable, leaks source',
            'file'     => $file,
            'line'     => 1,
            'snippet'  => basename($file),
            'fix'      => 'Delete editor/deploy backups; block *.bak etc. in the web server config.',
        ];
    }

    $lines = explode("\n", $code);
    foreach ($RULES as $rule) {
        // Find every match, with correct line numbers (multi-line safe).
        $offset = 0;
        while (preg_match($rule['pattern'], $code, $m, PREG_OFFSET_CAPTURE, $offset)) {
            $matchStart = $m[0][1];
            $line = substr_count($code, "\n", 0, $matchStart) + 1;
            // unless-guard: skip when the matched line (or its neighbors) already mitigates
            if (!empty($rule['unless'])) {
                $ctx = ($lines[$line - 2] ?? '') . "\n" . ($lines[$line - 1] ?? '') . "\n" . ($lines[$line] ?? '');
                if (@preg_match($rule['unless'], $ctx)) { $offset = $matchStart + max(1, strlen($m[0][0])); continue; }
            }
            $snippet = trim($lines[$line - 1] ?? '') ?: '(multi-line match)';
            if (mb_strlen($snippet) > 160) $snippet = mb_substr($snippet, 0, 157) . '...';

            $findings[] = [
                'rule'     => $rule['id'],
                'severity' => $rule['severity'],
                'message'  => $rule['message'],
                'file'     => $file,
                'line'     => $line,
                'snippet'  => $snippet,
                'fix'      => $rule['fix'],
            ];
            $offset = $matchStart + max(1, strlen($m[0][0]));
        }
    }
}

// De-dup identical (rule,file,line) hits.
$seen = [];
$findings = array_values(array_filter($findings, function ($f) use (&$seen) {
    $k = $f['rule'] . '|' . $f['file'] . '|' . $f['line'];
    if (isset($seen[$k])) return false;
    $seen[$k] = true;
    return true;
}));

// Filter by severity.
$minLevel = SEVERITIES[$minSeverity];
$findings = array_values(array_filter($findings,
    fn($f) => SEVERITIES[$f['severity']] >= $minLevel));

usort($findings, fn($a, $b) =>
    SEVERITIES[$b['severity']] <=> SEVERITIES[$a['severity']] ?: strcmp($a['file'], $b['file']));

$elapsed = microtime(true) - $startTime;
$counts = ['high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
foreach ($findings as $f) $counts[$f['severity']]++;

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

if ($json) {
    echo json_encode([
        'scanned' => ['files' => $filesScanned, 'skipped' => $skipped,
                     'bytes' => $bytesScanned, 'seconds' => round($elapsed, 2),
                     'target' => $target],
        'summary' => $counts,
        'findings' => $findings,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
    exit(empty($findings) ? 0 : 1);
}

$C = fn(string $s, string $hex) => $color ? "\x1b[{$hex}m{$s}\x1b[0m" : $s;
$sevColor = [
    'high'   => fn($s) => $C($s, '1;31'),
    'medium' => fn($s) => $C($s, '0;33'),
    'low'    => fn($s) => $C($s, '0;36'),
    'info'   => fn($s) => $C($s, '0;37'),
];

echo $C('  ██████╗ ██╗  ██╗ ██████╗ ███████╗███╗   ██╗', '1;35') . "\n";
echo $C('  ██╔══██╗██║  ██║██╔═══██╗██╔════╝████╗  ██║', '0;35') . "\n";
echo $C('  ██████╔╝███████║██║   ██║█████╗  ██╔██╗ ██║', '1;95') . "\n";
echo $C('  ██╔═══╝ ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║', '0;95') . "\n";
echo $C('  ██║     ██║  ██║╚██████╔╝███████╗██║ ╚████║', '1;35') . "\n";
echo $C('  ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝', '0;35') . "\n";
echo $C('     static security scanner for small PHP sites', '0;95') . "\n\n";
echo "Target:  $target\n";
echo "Scanned: $filesScanned file(s), " . number_format($bytesScanned) . " bytes in "
     . round($elapsed, 2) . "s"
     . ($skipped ? " (skipped $skipped oversized/unreadable)" : "") . "\n\n";

if (!$findings) {
    echo $C("✔ No findings at or above '$minSeverity' severity.\n", '1;32');
    exit(0);
}

echo "Summary: "
    . $sevColor['high']("{$counts['high']} high")
    . ", " . $sevColor['medium']("{$counts['medium']} medium")
    . ", " . $sevColor['low']("{$counts['low']} low")
    . ", " . $sevColor['info']("{$counts['info']} info") . "\n\n";

$lastFile = null;
foreach ($findings as $f) {
    if ($f['file'] !== $lastFile) {
        echo $C($f['file'], '1') . "\n";
        $lastFile = $f['file'];
    }
    echo '  ' . $sevColor[$f['severity']](sprintf('%-7s', strtoupper($f['severity'])))
        . " line {$f['line']}  [{$f['rule']}] " . $f['message'] . "\n"
        . '    ' . $C('`' . $f['snippet'] . '`', '2') . "\n"
        . '    fix: ' . $f['fix'] . "\n";
}
exit(1);
