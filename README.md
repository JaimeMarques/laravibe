# Laravibe

Offline, fail-closed security scanning built specifically for Laravel projects.

Laravibe scans Laravel configuration, PHP, Blade, and repository layout without executing application code or invoking project-owned tools. It produces console, JSON, or SARIF reports with distinct exit codes for findings and incomplete scans.

## Security and privacy

- No network requests.
- No subprocesses and no execution of target code, Composer plugins, Artisan, PHPStan, bootstrap files, or service providers.
- Reports contain fixed rule text and sanitized relative file/line locations, never source snippets or `.env` values.
- Absolute project paths and the project name are omitted.
- Files are opened with bounded reads and inode checks; symlink escapes and file-swap races fail closed.
- Unreadable, oversized, malformed, or incomplete first-party source scans return exit code `2`, never a clean result.
- Laravibe writes only to stdout. Use trusted shell redirection if a report file is needed.

## Requirements

- PHP 8.2 or newer
- A Laravel application or package with `composer.json`

Run `composer audit --locked --abandoned=fail` and PHPStan/Larastan as separate CI gates. Laravibe deliberately does not launch them because a target checkout can influence Composer/Git configuration and PHPStan can execute bootstrap or extension code.

## Install

Until Laravibe is on Packagist, install it from GitHub:

```bash
composer config repositories.laravibe vcs https://github.com/MrTheSoulz/laravibe
composer require --dev mrthesoulz/laravibe:dev-main
```

Or run a local clone:

```bash
git clone https://github.com/MrTheSoulz/laravibe.git
cd laravibe
composer install
bin/laravibe scan /path/to/laravel-project --production
```

## Usage

```bash
# Normal local scan
vendor/bin/laravibe scan .

# Deployment-oriented checks
vendor/bin/laravibe scan . --production --fail-on=high

# Machine-readable reports; set restrictive permissions first
umask 077
vendor/bin/laravibe scan . --format=json > laravibe-report.json
vendor/bin/laravibe scan . --format=sarif > laravibe-report.sarif
```

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | No finding reached the configured threshold |
| `1` | At least one finding reached the threshold |
| `2` | Invalid project, incomplete scan, unsafe path, unreadable input, or invalid arguments |

## Checks in v0.1

| Rule | Severity | Check |
|---|---|---|
| `LSEC-ENV-001` | critical | `APP_DEBUG=true` during a production scan |
| `LSEC-ENV-002` | critical | Missing or effectively empty `APP_KEY` in a present production `.env` |
| `LSEC-ENV-003` | high | Explicitly insecure session cookie transport |
| `LSEC-ENV-004` | high | Explicitly disabled HTTP-only session cookies |
| `LSEC-ENV-005` | high | Production safeguard uses unresolved environment interpolation |
| `LSEC-FS-001` | critical | Sensitive file or directory inside `public/` |
| `LSEC-CODE-001` | critical | Direct code/command execution primitives |
| `LSEC-CODE-002` | high | Native `unserialize()` |
| `LSEC-BLADE-001` | high | Unescaped Blade output |
| `LSEC-MASS-001` | high | `$request->all()` passed to `create()` or `update()` |
| `LSEC-SQL-001` | critical | Request input passed to a raw SQL API |

PHP rules use PHP's tokenizer so comments and strings are ignored and multiline calls are handled. Blade `<?php ... ?>` and `@php ... @endphp` blocks are scanned. First-party locations include root `artisan`, `app/`, `bootstrap/`, `routes/`, `config/`, `resources/views/`, `database/`, `src/`, `Modules/`, `modules/`, `public/`, `lang/`, and `resources/lang/`.

Native rules are deliberately narrow heuristics. A finding requires review; a clean result is not proof that an application is secure.

## GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
  - run: composer install --no-interaction --prefer-dist
  - name: Laravibe
    run: vendor/bin/laravibe scan . --production --format=sarif --fail-on=high > laravibe-report.sarif
  - name: Upload SARIF
    if: always() && hashFiles('laravibe-report.sarif') != ''
    uses: github/codeql-action/upload-sarif@faaca9a8f6edddba5725ffe5adefdab6669a2eca # v3
    with:
      sarif_file: laravibe-report.sarif
```

Run the project's normal `composer audit` and PHPStan/Larastan commands as separate steps.

## Development

```bash
composer install
composer check
```

The test suite uses synthetic secrets and fixtures only.

## Vulnerabilities

Use GitHub private vulnerability reporting. Do not publish credentials, customer data, or proprietary source in an issue.

## License

MIT
