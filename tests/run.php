<?php

declare(strict_types=1);

use Laravibe\Finding;
use Laravibe\NativeScanner;
use Laravibe\ProjectInspector;
use Laravibe\ReportRenderer;
use Laravibe\SafeFileReader;
use Laravibe\ScanReport;
use Laravibe\SecurityScanner;

spl_autoload_register(static function (string $class): void {
    $prefix = 'Laravibe\\';

    if (!str_starts_with($class, $prefix)) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $path = dirname(__DIR__) . '/src/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require $path;
    }
});

/** @var array<string, Closure(): void> $tests */
$tests = [];

$tests['detects Laravel projects without loading project code'] = static function (): void {
    $directory = laravelProject();

    assertTrue(ProjectInspector::isLaravelProject($directory));
    removeDirectory($directory);
};

$tests['rejects a composer manifest symlink'] = static function (): void {
    $directory = temporaryDirectory();
    $outside = temporaryDirectory();
    file_put_contents($outside . '/composer.json', '{"require":{"laravel/framework":"^12.0"}}');
    symlink($outside . '/composer.json', $directory . '/composer.json');

    assertFalse(ProjectInspector::isLaravelProject($directory));

    unlink($directory . '/composer.json');
    removeDirectory($directory);
    removeDirectory($outside);
};

$tests['safe file reads reject symlinks and enforce bounds'] = static function (): void {
    $directory = temporaryDirectory();
    $outside = temporaryDirectory();
    file_put_contents($outside . '/fixture', 'TEST_ONLY_EXTERNAL_CONTENT');
    symlink($outside . '/fixture', $directory . '/linked');
    file_put_contents($directory . '/large', str_repeat('x', 32));
    $reader = new SafeFileReader();

    assertThrows(static fn (): string => $reader->read($directory, $directory . '/linked', 64), RuntimeException::class);
    assertThrows(static fn (): string => $reader->read($directory, $directory . '/large', 16), RuntimeException::class);

    unlink($directory . '/linked');
    removeDirectory($directory);
    removeDirectory($outside);
};

$tests['production environment findings never include values'] = static function (): void {
    $directory = temporaryDirectory();
    file_put_contents(
        $directory . '/.env',
        "APP_DEBUG=true\nAPP_KEY=base64:TEST_ONLY_NON_SECRET_VALUE\nSESSION_SECURE_COOKIE=false\nSESSION_HTTP_ONLY=false\n",
    );

    $findings = (new NativeScanner())->scan($directory, production: true);
    $encoded = json_encode($findings, JSON_THROW_ON_ERROR);
    $ruleIds = ruleIds($findings);

    assertSame(['LSEC-ENV-001', 'LSEC-ENV-003', 'LSEC-ENV-004'], $ruleIds);
    assertFalse(str_contains($encoded, 'TEST_ONLY_NON_SECRET_VALUE'));
    removeDirectory($directory);
};

$tests['missing and null application keys are findings'] = static function (): void {
    $missing = temporaryDirectory();
    file_put_contents($missing . '/.env', "APP_DEBUG=false\n");
    $null = temporaryDirectory();
    file_put_contents($null . '/.env', "APP_DEBUG=false\nAPP_KEY=(null)\n");

    assertSame(['LSEC-ENV-002'], ruleIds((new NativeScanner())->scan($missing, production: true)));
    assertSame(['LSEC-ENV-002'], ruleIds((new NativeScanner())->scan($null, production: true)));
    removeDirectory($missing);
    removeDirectory($null);
};

$tests['dotenv export reserved values and quoted comments are parsed'] = static function (): void {
    $directory = temporaryDirectory();
    file_put_contents(
        $directory . '/.env',
        "export APP_DEBUG=\"true\" # \"comment quote\"\nAPP_KEY=(empty) # missing\nSESSION_SECURE_COOKIE=(false)\nSESSION_HTTP_ONLY=(false)\n",
    );

    assertSame(
        ['LSEC-ENV-001', 'LSEC-ENV-002', 'LSEC-ENV-003', 'LSEC-ENV-004'],
        ruleIds((new NativeScanner())->scan($directory, production: true)),
    );
    removeDirectory($directory);
};

$tests['dotenv interpolation ignores single-quoted dollar signs'] = static function (): void {
    $directory = temporaryDirectory();
    file_put_contents(
        $directory . '/.env',
        "APP_DEBUG=\${DEBUG_VALUE}\nAPP_KEY=\"\${APPLICATION_KEY}\"\nSESSION_SECURE_COOKIE='\${LITERAL_DOLLAR}'\nSESSION_HTTP_ONLY=true\n",
    );

    $findings = (new NativeScanner())->scan($directory, production: true);
    $encoded = json_encode($findings, JSON_THROW_ON_ERROR);

    assertSame(['LSEC-ENV-005', 'LSEC-ENV-005'], ruleIds($findings));
    assertFalse(str_contains($encoded, 'APPLICATION_KEY'));
    assertFalse(str_contains($encoded, 'LITERAL_DOLLAR'));
    removeDirectory($directory);
};

$tests['public sensitive files are flagged without being read'] = static function (): void {
    $directory = temporaryDirectory();
    mkdir($directory . '/public', 0700, true);
    file_put_contents($directory . '/public/.env', 'APP_KEY=TEST_ONLY_PUBLIC_SENTINEL');

    $findings = (new NativeScanner())->scan($directory);

    assertSame(['LSEC-FS-001'], ruleIds($findings));
    assertFalse(str_contains(json_encode($findings, JSON_THROW_ON_ERROR), 'TEST_ONLY_PUBLIC_SENTINEL'));
    removeDirectory($directory);
};

$tests['source roots reject live and dangling symlinks'] = static function (): void {
    $directory = temporaryDirectory();
    $outside = temporaryDirectory();
    mkdir($outside . '/app', 0700, true);
    symlink($outside . '/app', $directory . '/app');

    assertThrows(static fn (): array => (new NativeScanner())->scan($directory), RuntimeException::class);
    unlink($directory . '/app');
    symlink($outside . '/missing', $directory . '/app');
    assertThrows(static fn (): array => (new NativeScanner())->scan($directory), RuntimeException::class);

    unlink($directory . '/app');
    removeDirectory($directory);
    removeDirectory($outside);
};

$tests['PHP rules handle multiline code and ignore comments strings tests and vendor'] = static function (): void {
    $directory = temporaryDirectory();
    mkdir($directory . '/app', 0700, true);
    mkdir($directory . '/tests', 0700, true);
    mkdir($directory . '/vendor/package', 0700, true);
    file_put_contents($directory . '/app/Safe.php', "<?php /* eval(\$x); */ \$text = 'shell_exec(1)';\n");
    file_put_contents($directory . '/app/Danger.php', "<?php\nreturn shell_exec\n(\n    \$command\n);\n");
    file_put_contents($directory . '/tests/Fixture.php', "<?php eval(\$x);\n");
    file_put_contents($directory . '/vendor/package/File.php', "<?php eval(\$x);\n");

    $findings = (new NativeScanner())->scan($directory);

    assertSame(['LSEC-CODE-001'], ruleIds($findings));
    assertSame('app/Danger.php', $findings[0]->path);
    assertSame(2, $findings[0]->line);
    removeDirectory($directory);
};

$tests['all conventional first-party Laravel roots are scanned'] = static function (): void {
    $directory = temporaryDirectory();

    foreach (['app', 'bootstrap', 'routes', 'config', 'database', 'src', 'Modules', 'modules', 'public', 'lang', 'resources/lang'] as $root) {
        mkdir($directory . '/' . $root, 0700, true);
        file_put_contents($directory . '/' . $root . '/Danger.php', "<?php eval(\$payload);\n");
    }

    file_put_contents($directory . '/artisan', "#!/usr/bin/env php\n<?php eval(\$payload);\n");
    $findings = (new NativeScanner())->scan($directory);

    assertSame(12, count($findings));
    assertTrue(in_array('artisan', array_map(static fn (Finding $finding): string => $finding->path, $findings), true));
    removeDirectory($directory);
};

$tests['large unrelated public assets are ignored but large PHP fails closed'] = static function (): void {
    $directory = temporaryDirectory();
    mkdir($directory . '/public', 0700, true);
    file_put_contents($directory . '/public/bundle.js', str_repeat('x', 2_000_001));

    assertSame([], (new NativeScanner())->scan($directory));

    file_put_contents($directory . '/public/Large.php', str_repeat(' ', 2_000_001));
    assertThrows(static fn (): array => (new NativeScanner())->scan($directory), RuntimeException::class);
    removeDirectory($directory);
};

$tests['unserialize mass assignment and raw SQL are detected'] = static function (): void {
    $directory = temporaryDirectory();
    mkdir($directory . '/app', 0700, true);
    file_put_contents(
        $directory . '/app/Risky.php',
        "<?php\nunserialize(\$request->input('x'));\nUser::create(\n    \$request->all()\n);\nDB::select(\n    'select * from users where id = ' . \$request->input('id')\n);\n",
    );

    assertSame(
        ['LSEC-CODE-002', 'LSEC-MASS-001', 'LSEC-SQL-001'],
        ruleIds((new NativeScanner())->scan($directory)),
    );
    removeDirectory($directory);
};

$tests['Blade raw output embedded PHP and at-php blocks are detected'] = static function (): void {
    $directory = temporaryDirectory();
    mkdir($directory . '/resources/views', 0700, true);
    file_put_contents(
        $directory . '/resources/views/risky.blade.php',
        "{{-- {!! \$comment !!} --}}\n{!! \$user->bio !!}\n<?php unserialize(\$payload); ?>\n@php\neval(\$payload);\n@endphp\n",
    );

    assertSame(
        ['LSEC-BLADE-001', 'LSEC-CODE-002', 'LSEC-CODE-001'],
        ruleIds((new NativeScanner())->scan($directory)),
    );
    removeDirectory($directory);
};

$tests['security scanner never executes target binaries'] = static function (): void {
    $directory = laravelProject();
    mkdir($directory . '/vendor/bin', 0700, true);
    $marker = $directory . '/executed';

    foreach ([$directory . '/composer', $directory . '/vendor/bin/phpstan'] as $binary) {
        file_put_contents($binary, "#!/bin/sh\nprintf executed > " . escapeshellarg($marker) . "\n");
        chmod($binary, 0700);
    }

    $originalPath = getenv('PATH');
    putenv('PATH=' . $directory . PATH_SEPARATOR . (is_string($originalPath) ? $originalPath : ''));

    try {
        $report = (new SecurityScanner())->scan($directory);
    } finally {
        is_string($originalPath) ? putenv('PATH=' . $originalPath) : putenv('PATH');
    }

    assertFalse(file_exists($marker));
    assertFalse($report->hasOperationalErrors());
    removeDirectory($directory);
};

$tests['incomplete native scans return operational failure'] = static function (): void {
    $directory = laravelProject();
    $outside = temporaryDirectory();
    removeDirectory($directory . '/app');
    mkdir($outside . '/app', 0700, true);
    symlink($outside . '/app', $directory . '/app');

    $report = (new SecurityScanner())->scan($directory);

    assertSame(['native: scan incomplete.'], $report->errors);
    assertSame(2, $report->exitCode('high'));
    unlink($directory . '/app');
    removeDirectory($directory);
    removeDirectory($outside);
};

$tests['severity thresholds fail closed on invalid values'] = static function (): void {
    $finding = new Finding('TEST-001', 'high', 'Test finding.', 'app/Test.php', 1, 'Fix it.');
    $report = new ScanReport('/app', [$finding]);

    assertSame(1, $report->exitCode('high'));
    assertSame(0, $report->exitCode('critical'));
    assertThrows(static fn (): int => $report->exitCode('unknown'), InvalidArgumentException::class);
    assertThrows(
        static fn (): Finding => new Finding('TEST-002', 'unknown', 'Bad.', 'app/Test.php', 1, 'Fix.'),
        InvalidArgumentException::class,
    );
};

$tests['JSON and console reports sanitize target paths and control bytes'] = static function (): void {
    $finding = new Finding(
        'TEST-001',
        'high',
        "Finding\nwith-control\033[31m",
        "app/My File#%\033.php",
        4,
        "Fix\rnow.",
    );
    $report = new ScanReport("/private/customer\033-project", [$finding]);
    $renderer = new ReportRenderer();
    $json = $renderer->render($report, 'json');
    $console = $renderer->render($report, 'console');
    $decoded = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

    assertSame('project', $decoded['target']);
    assertFalse(str_contains($json, '/private/'));
    assertFalse(str_contains($json, '\\u001b'));
    assertFalse(str_contains($console, "\033"));
    assertFalse(str_contains($console, "\r"));
};

$tests['SARIF encodes artifact URIs and omits file-level regions'] = static function (): void {
    $fileFinding = new Finding('TEST-001', 'high', 'Test.', 'app/My File#%.php', 9, 'Fix.');
    $rootFinding = new Finding('TEST-002', 'critical', 'Test.', 'composer.lock', 0, 'Fix.');
    $sarif = (new ReportRenderer())->render(new ScanReport('/private/app', [$fileFinding, $rootFinding]), 'sarif');
    $decoded = json_decode($sarif, true, 512, JSON_THROW_ON_ERROR);
    $encoded = json_encode($decoded, JSON_THROW_ON_ERROR);
    $first = $decoded['runs'][0]['results'][0]['locations'][0]['physicalLocation'];
    $second = $decoded['runs'][0]['results'][1]['locations'][0]['physicalLocation'];

    assertFalse(str_contains($encoded, '/private/app'));
    assertSame('app/My%20File%23%25.php', $first['artifactLocation']['uri']);
    assertSame(9, $first['region']['startLine']);
    assertFalse(array_key_exists('region', $second));
};

$tests['CLI emits JSON and the finding exit code'] = static function (): void {
    $directory = laravelProject();
    file_put_contents($directory . '/app/Danger.php', "<?php eval(\$payload);\n");

    $result = runCommand([
        PHP_BINARY,
        dirname(__DIR__) . '/bin/laravibe',
        'scan',
        $directory,
        '--format=json',
        '--fail-on=high',
    ], dirname(__DIR__));
    $decoded = json_decode($result['stdout'], true, 512, JSON_THROW_ON_ERROR);

    assertSame(1, $result['exit_code']);
    assertSame('laravibe', $decoded['tool']);
    assertSame('LSEC-CODE-001', $decoded['findings'][0]['rule_id']);
    assertFalse(str_contains($result['stdout'], $directory));
    removeDirectory($directory);
};

$tests['CLI requires a target and rejects removed file-output options'] = static function (): void {
    $missing = runCommand([PHP_BINARY, dirname(__DIR__) . '/bin/laravibe', 'scan'], dirname(__DIR__));
    $output = runCommand([
        PHP_BINARY,
        dirname(__DIR__) . '/bin/laravibe',
        'scan',
        '.',
        '--output=report.json',
    ], dirname(__DIR__));

    assertSame(2, $missing['exit_code']);
    assertSame(2, $output['exit_code']);
    assertSame("Laravibe error: scan could not be completed.\n", $missing['stderr']);
};

$tests['CLI errors never echo attacker-controlled arguments'] = static function (): void {
    $result = runCommand([
        PHP_BINARY,
        dirname(__DIR__) . '/bin/laravibe',
        'scan',
        "--unknown=ATTACKER_CONTROLLED_TEXT\033[31m",
    ], dirname(__DIR__));

    assertSame(2, $result['exit_code']);
    assertSame("Laravibe error: scan could not be completed.\n", $result['stderr']);
    assertFalse(str_contains($result['stderr'], 'ATTACKER_CONTROLLED_TEXT'));
    assertFalse(str_contains($result['stderr'], "\033"));
};

$failures = 0;

foreach ($tests as $name => $test) {
    try {
        $test();
        fwrite(STDOUT, "PASS {$name}\n");
    } catch (Throwable $error) {
        $failures++;
        fwrite(STDERR, "FAIL {$name}: {$error->getMessage()}\n");
    }
}

fwrite(STDOUT, sprintf("%d tests, %d failures\n", count($tests), $failures));
exit($failures === 0 ? 0 : 1);

/** @param list<Finding> $findings @return list<string> */
function ruleIds(array $findings): array
{
    return array_map(static fn (Finding $finding): string => $finding->ruleId, $findings);
}

function assertTrue(bool $condition, string $message = 'Expected true'): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function assertFalse(bool $condition, string $message = 'Expected false'): void
{
    if ($condition) {
        throw new RuntimeException($message);
    }
}

function assertSame(mixed $expected, mixed $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException($message !== '' ? $message : sprintf(
            'Expected %s, got %s',
            var_export($expected, true),
            var_export($actual, true),
        ));
    }
}

/** @param class-string<Throwable> $expected */
function assertThrows(Closure $callback, string $expected): void
{
    try {
        $callback();
    } catch (Throwable $error) {
        if ($error instanceof $expected) {
            return;
        }

        throw new RuntimeException(sprintf('Expected %s, got %s', $expected, $error::class));
    }

    throw new RuntimeException("Expected {$expected} to be thrown");
}

function temporaryDirectory(): string
{
    $directory = sys_get_temp_dir() . '/laravibe-' . bin2hex(random_bytes(8));

    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create test directory');
    }

    return $directory;
}

function laravelProject(): string
{
    $directory = temporaryDirectory();
    mkdir($directory . '/app', 0700, true);
    file_put_contents($directory . '/composer.json', '{"require":{"laravel/framework":"^12.0"}}');
    file_put_contents($directory . '/composer.lock', '{}');

    return $directory;
}

function removeDirectory(string $directory): void
{
    if (is_link($directory)) {
        unlink($directory);
        return;
    }

    if (!is_dir($directory)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($items as $item) {
        if ($item->isLink() || $item->isFile()) {
            unlink($item->getPathname());
        } else {
            rmdir($item->getPathname());
        }
    }

    rmdir($directory);
}

/**
 * @param non-empty-list<string> $command
 * @return array{exit_code: int, stdout: string, stderr: string}
 */
function runCommand(array $command, string $directory): array
{
    $pipes = [];
    $process = proc_open(
        $command,
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
        $pipes,
        $directory,
        null,
        ['bypass_shell' => true],
    );

    if (!is_resource($process)) {
        throw new RuntimeException('Unable to run test command');
    }

    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);

    return [
        'exit_code' => proc_close($process),
        'stdout' => is_string($stdout) ? $stdout : '',
        'stderr' => is_string($stderr) ? $stderr : '',
    ];
}
