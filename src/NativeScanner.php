<?php

declare(strict_types=1);

namespace Laravibe;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use SplFileInfo;

final class NativeScanner
{
    public function __construct(private readonly SafeFileReader $reader = new SafeFileReader())
    {
    }

    /** @return list<Finding> */
    public function scan(string $directory, bool $production = false): array
    {
        $resolvedRoot = realpath($directory);

        if ($resolvedRoot === false || !is_dir($resolvedRoot)) {
            throw new RuntimeException('Scan target is not a readable directory.');
        }

        $root = rtrim($resolvedRoot, DIRECTORY_SEPARATOR);
        $findings = $production ? $this->scanEnvironment($root) : [];

        foreach (['.env', '.git', 'composer.json', 'composer.lock', 'auth.json'] as $sensitiveName) {
            $publicPath = $root . '/public/' . $sensitiveName;

            if (!file_exists($publicPath) && !is_link($publicPath)) {
                continue;
            }

            $findings[] = new Finding(
                ruleId: 'LSEC-FS-001',
                severity: 'critical',
                message: 'A sensitive file or directory is inside the public web root.',
                path: 'public/' . $sensitiveName,
                line: 0,
                remediation: 'Remove it from public/ and rotate any exposed credentials.',
            );
        }

        foreach ($this->sourceFiles($root) as $file) {
            $contents = $this->reader->read($root, $file, 2_000_000);
            $path = $this->relativePath($root, $file);
            $info = new SplFileInfo($file);
            array_push(
                $findings,
                ...($this->isBladeFile($info)
                    ? $this->scanBladeFile($contents, $path)
                    : $this->scanPhpFile($contents, $path)),
            );
        }

        $artisan = $root . '/artisan';

        if (is_link($artisan)) {
            throw new RuntimeException('The Artisan entry point is a symbolic link.');
        }

        if (is_file($artisan)) {
            array_push(
                $findings,
                ...$this->scanPhpFile($this->reader->read($root, $artisan, 2_000_000), 'artisan'),
            );
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function scanPhpFile(string $contents, string $path): array
    {
        $code = $this->codeWithoutCommentsAndStrings($contents);
        $findings = [];

        foreach ($this->matchOffsets(
            '/(?<!->)(?<!::)\b(?:eval|shell_exec|system|passthru|exec|popen|proc_open)\s*\(/i',
            $code,
        ) as $offset) {
            if (!$this->isGlobalCall($code, $offset)) {
                continue;
            }

            $findings[] = new Finding(
                ruleId: 'LSEC-CODE-001',
                severity: 'critical',
                message: 'Direct code or command execution primitive detected.',
                path: $path,
                line: $this->lineAtOffset($contents, $offset),
                remediation: 'Remove the primitive or isolate it behind strict validation and an allowlist.',
            );
        }

        foreach ($this->matchOffsets('/(?<!->)(?<!::)\bunserialize\s*\(/i', $code) as $offset) {
            if (!$this->isGlobalCall($code, $offset)) {
                continue;
            }

            $findings[] = new Finding(
                ruleId: 'LSEC-CODE-002',
                severity: 'high',
                message: 'Native unserialize() can enable object injection with untrusted data.',
                path: $path,
                line: $this->lineAtOffset($contents, $offset),
                remediation: 'Use JSON or a typed serializer; never unserialize untrusted input.',
            );
        }

        foreach ($this->matchOffsets(
            '/(?:create|update)\s*\(\s*\$request\s*->\s*all\s*\(\s*\)\s*\)/is',
            $code,
        ) as $offset) {
            $findings[] = new Finding(
                ruleId: 'LSEC-MASS-001',
                severity: 'high',
                message: 'Unvalidated request data is used for mass assignment.',
                path: $path,
                line: $this->lineAtOffset($contents, $offset),
                remediation: 'Pass validated or explicitly selected fields to create/update.',
            );
        }

        foreach ($this->matchOffsets(
            '/(?:DB\s*::\s*(?:raw|select|statement|unprepared)|->\s*(?:whereRaw|havingRaw|orderByRaw))\s*\([^;]*?(?:\$request\b|request\s*\()/is',
            $code,
        ) as $offset) {
            $findings[] = new Finding(
                ruleId: 'LSEC-SQL-001',
                severity: 'critical',
                message: 'Request input reaches a raw SQL API.',
                path: $path,
                line: $this->lineAtOffset($contents, $offset),
                remediation: 'Use query bindings or the query builder instead of interpolating request data.',
            );
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function scanBladeFile(string $contents, string $path): array
    {
        $withoutBladeComments = preg_replace_callback(
            '/{{--.*?--}}/s',
            fn (array $match): string => $this->blankPreservingLines((string) $match[0]),
            $contents,
        );

        if (!is_string($withoutBladeComments)) {
            throw new RuntimeException('Blade template parsing failed.');
        }

        $findings = [];

        foreach ($this->matchOffsets('/{!!.*?!!}/s', $withoutBladeComments) as $offset) {
            $findings[] = new Finding(
                ruleId: 'LSEC-BLADE-001',
                severity: 'high',
                message: 'Unescaped Blade output can introduce cross-site scripting.',
                path: $path,
                line: $this->lineAtOffset($contents, $offset),
                remediation: 'Use {{ ... }} escaping or sanitize trusted HTML before rendering.',
            );
        }

        array_push($findings, ...$this->scanPhpFile($withoutBladeComments, $path));

        $matched = preg_match_all('/@php\b(.*?)@endphp/s', $withoutBladeComments, $blocks, PREG_OFFSET_CAPTURE);

        if ($matched === false) {
            throw new RuntimeException('Blade PHP block parsing failed.');
        }

        foreach ($blocks[1] as $block) {
            $body = (string) $block[0];
            $bodyOffset = (int) $block[1];
            $baseLine = $this->lineAtOffset($contents, $bodyOffset);

            foreach ($this->scanPhpFile("<?php\n" . $body, $path) as $finding) {
                $findings[] = new Finding(
                    ruleId: $finding->ruleId,
                    severity: $finding->severity,
                    message: $finding->message,
                    path: $finding->path,
                    line: $baseLine + max(0, $finding->line - 2),
                    remediation: $finding->remediation,
                    tool: $finding->tool,
                );
            }
        }

        return $findings;
    }

    /** @return list<Finding> */
    private function scanEnvironment(string $root): array
    {
        $path = $root . '/.env';

        if (is_link($path)) {
            throw new RuntimeException('The environment file is a symbolic link.');
        }

        if (!is_file($path)) {
            return [];
        }

        $environment = $this->environment($this->reader->read($root, $path, 1_000_000));
        $findings = [];
        $debug = $environment['APP_DEBUG'] ?? null;
        $key = $environment['APP_KEY'] ?? null;
        $secureCookie = $environment['SESSION_SECURE_COOKIE'] ?? null;
        $httpOnly = $environment['SESSION_HTTP_ONLY'] ?? null;

        if ($debug !== null && !$debug['interpolated'] && $debug['value'] === 'true') {
            $findings[] = $this->environmentFinding(
                'LSEC-ENV-001',
                'critical',
                'APP_DEBUG is enabled for a production scan.',
                'Set APP_DEBUG=false in the production environment.',
                $debug['line'],
            );
        }

        if ($key === null || (!$key['interpolated'] && ($key['value'] === '' || $key['value'] === null))) {
            $findings[] = $this->environmentFinding(
                'LSEC-ENV-002',
                'critical',
                'APP_KEY is missing in the production environment file.',
                'Generate and inject a unique APP_KEY without committing it.',
                $key['line'] ?? 0,
            );
        }

        if ($secureCookie !== null && !$secureCookie['interpolated'] && $secureCookie['value'] === 'false') {
            $findings[] = $this->environmentFinding(
                'LSEC-ENV-003',
                'high',
                'Secure session cookies are disabled for a production scan.',
                'Set SESSION_SECURE_COOKIE=true when the application is served over HTTPS.',
                $secureCookie['line'],
            );
        }

        if ($httpOnly !== null && !$httpOnly['interpolated'] && $httpOnly['value'] === 'false') {
            $findings[] = $this->environmentFinding(
                'LSEC-ENV-004',
                'high',
                'HTTP-only session cookies are disabled for a production scan.',
                'Set SESSION_HTTP_ONLY=true.',
                $httpOnly['line'],
            );
        }

        foreach ([$debug, $key, $secureCookie, $httpOnly] as $setting) {
            if ($setting === null || !$setting['interpolated']) {
                continue;
            }

            $findings[] = $this->environmentFinding(
                'LSEC-ENV-005',
                'high',
                'A production security setting uses unresolved environment interpolation.',
                'Verify the resolved deployment value explicitly in the deployment environment.',
                $setting['line'],
            );
        }

        return $findings;
    }

    private function environmentFinding(
        string $ruleId,
        string $severity,
        string $message,
        string $remediation,
        int $line,
    ): Finding {
        return new Finding($ruleId, $severity, $message, '.env', $line, $remediation);
    }

    /** @return iterable<string> */
    private function sourceFiles(string $root): iterable
    {
        $roots = [
            'app',
            'bootstrap',
            'routes',
            'config',
            'resources/views',
            'database',
            'src',
            'Modules',
            'modules',
            'public',
            'lang',
            'resources/lang',
        ];

        foreach ($roots as $relativeRoot) {
            $path = $root . '/' . $relativeRoot;

            if (is_link($path)) {
                throw new RuntimeException('A source root is a symbolic link.');
            }

            if (!file_exists($path)) {
                continue;
            }

            $resolvedPath = realpath($path);

            if ($resolvedPath === false || !is_dir($resolvedPath) || !$this->isWithinRoot($root, $resolvedPath)) {
                throw new RuntimeException('A source root escapes the project directory.');
            }

            $files = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($resolvedPath, FilesystemIterator::SKIP_DOTS),
            );

            foreach ($files as $file) {
                if (!$file instanceof SplFileInfo) {
                    throw new RuntimeException('Unable to inspect a source entry.');
                }

                if (!$file->isFile()) {
                    continue;
                }

                $extension = strtolower($file->getExtension());

                if ($extension !== 'php' && !$this->isBladeFile($file)) {
                    continue;
                }

                if ($file->isLink()) {
                    throw new RuntimeException('A source file is a symbolic link.');
                }

                $resolvedFile = $file->getRealPath();

                if ($resolvedFile === false || !$this->isWithinRoot($root, $resolvedFile)) {
                    throw new RuntimeException('A source file escapes the project directory.');
                }

                yield $resolvedFile;
            }
        }
    }

    /** @return array<string, array{value: ?string, interpolated: bool, line: int}> */
    private function environment(string $contents): array
    {
        $values = [];

        foreach (preg_split('/\R/', $contents) ?: [] as $index => $line) {
            $trimmed = trim($line);

            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }

            if (str_starts_with($trimmed, 'export ')) {
                $trimmed = ltrim(substr($trimmed, 7));
            }

            if (preg_match('/\A([A-Za-z_][A-Za-z0-9_]*)\s*=/', $trimmed, $matches) !== 1) {
                continue;
            }

            $separator = strpos($trimmed, '=');

            if ($separator === false) {
                continue;
            }

            $values[$matches[1]] = $this->environmentValue(substr($trimmed, $separator + 1), $index + 1);
        }

        return $values;
    }

    /** @return array{value: ?string, interpolated: bool, line: int} */
    private function environmentValue(string $raw, int $line): array
    {
        $raw = ltrim($raw);
        $quoted = false;
        $doubleQuoted = false;

        if ($raw !== '' && ($raw[0] === '"' || $raw[0] === "'")) {
            $quoted = true;
            $quote = $raw[0];
            $doubleQuoted = $quote === '"';
            $closing = $this->closingQuote($raw, $quote);

            if ($closing === null) {
                throw new RuntimeException('Malformed quoted environment value.');
            }

            $value = substr($raw, 1, $closing - 1);
            $remainder = trim(substr($raw, $closing + 1));

            if ($remainder !== '' && !str_starts_with($remainder, '#')) {
                throw new RuntimeException('Malformed quoted environment value.');
            }
        } else {
            $withoutComment = preg_replace('/\s+#.*$/', '', $raw);

            if (!is_string($withoutComment)) {
                throw new RuntimeException('Environment value parsing failed.');
            }

            $value = trim($withoutComment);
        }

        $lower = strtolower($value);
        $normalized = match ($lower) {
            'true', '(true)' => 'true',
            'false', '(false)' => 'false',
            'empty', '(empty)' => '',
            'null', '(null)' => null,
            default => $lower,
        };

        return [
            'value' => $normalized,
            'interpolated' => (!$quoted || $doubleQuoted) && str_contains($value, '$'),
            'line' => $line,
        ];
    }

    private function closingQuote(string $value, string $quote): ?int
    {
        $escaped = false;

        for ($index = 1, $length = strlen($value); $index < $length; $index++) {
            $character = $value[$index];

            if ($character === $quote && !$escaped) {
                return $index;
            }

            if ($character === '\\' && !$escaped) {
                $escaped = true;
                continue;
            }

            $escaped = false;
        }

        return null;
    }

    private function codeWithoutCommentsAndStrings(string $contents): string
    {
        $sanitized = '';

        foreach (token_get_all($contents) as $token) {
            if (!is_array($token)) {
                $sanitized .= $token;
                continue;
            }

            [$id, $text] = $token;

            if (in_array($id, [
                T_COMMENT,
                T_DOC_COMMENT,
                T_CONSTANT_ENCAPSED_STRING,
                T_ENCAPSED_AND_WHITESPACE,
                T_INLINE_HTML,
                T_START_HEREDOC,
                T_END_HEREDOC,
            ], true)) {
                $sanitized .= $this->blankPreservingLines($text);
                continue;
            }

            $sanitized .= $text;
        }

        return $sanitized;
    }

    private function blankPreservingLines(string $text): string
    {
        $blank = preg_replace('/[^\r\n]/', ' ', $text);

        if (!is_string($blank)) {
            throw new RuntimeException('Source sanitization failed.');
        }

        return $blank;
    }

    /** @return list<int> */
    private function matchOffsets(string $pattern, string $subject): array
    {
        $matched = preg_match_all($pattern, $subject, $matches, PREG_OFFSET_CAPTURE);

        if ($matched === false) {
            throw new RuntimeException('A scanner rule could not be evaluated.');
        }

        $offsets = [];

        foreach ($matches[0] ?? [] as $match) {
            $offsets[] = $match[1];
        }

        return $offsets;
    }

    private function isGlobalCall(string $code, int $offset): bool
    {
        $prefix = rtrim(substr($code, 0, $offset));

        return !str_ends_with($prefix, '->')
            && !str_ends_with($prefix, '?->')
            && !str_ends_with($prefix, '::')
            && preg_match('/\bfunction\s*$/i', $prefix) !== 1;
    }

    private function lineAtOffset(string $contents, int $offset): int
    {
        return substr_count(substr($contents, 0, $offset), "\n") + 1;
    }

    private function isBladeFile(SplFileInfo $file): bool
    {
        return str_ends_with($file->getFilename(), '.blade.php');
    }

    private function relativePath(string $root, string $path): string
    {
        return ltrim(str_replace('\\', '/', substr($path, strlen($root))), '/');
    }

    private function isWithinRoot(string $root, string $path): bool
    {
        $normalizedRoot = rtrim(str_replace('\\', '/', $root), '/');
        $normalizedPath = str_replace('\\', '/', $path);

        return $normalizedPath === $normalizedRoot
            || str_starts_with($normalizedPath, $normalizedRoot . '/');
    }
}
