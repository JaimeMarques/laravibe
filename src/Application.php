<?php

declare(strict_types=1);

namespace Laravibe;

use Throwable;

final class Application
{
    /** @param list<string> $arguments */
    public function run(array $arguments): int
    {
        array_shift($arguments);

        if ($arguments === []) {
            return $this->writeStdout($this->help()) ? 0 : 2;
        }

        if ($arguments[0] === '--version') {
            return $this->writeStdout("Laravibe 0.1.0\n") ? 0 : 2;
        }

        if (in_array($arguments[0], ['--help', '-h'], true)) {
            return $this->writeStdout($this->help()) ? 0 : 2;
        }

        if ($arguments[0] === 'scan') {
            array_shift($arguments);

            if ($arguments === []) {
                return $this->fail();
            }

            if (in_array($arguments[0], ['--help', '-h'], true)) {
                return $this->writeStdout($this->help()) ? 0 : 2;
            }
        }

        try {
            $options = $this->parseArguments($arguments);
            $report = (new SecurityScanner())->scan(
                directory: $options['directory'],
                production: $options['production'],
            );
            $output = (new ReportRenderer())->render($report, $options['format']);

            if (!$this->writeStdout($output)) {
                return 2;
            }

            return $report->exitCode($options['fail_on']);
        } catch (Throwable) {
            return $this->fail();
        }
    }

    /**
     * @param list<string> $arguments
     * @return array{directory: string, production: bool, format: string, fail_on: string}
     */
    private function parseArguments(array $arguments): array
    {
        $options = [
            'directory' => '',
            'production' => false,
            'format' => 'console',
            'fail_on' => 'high',
        ];

        foreach ($arguments as $argument) {
            if ($argument === '--production') {
                $options['production'] = true;
                continue;
            }

            if (str_starts_with($argument, '--format=')) {
                $options['format'] = strtolower(substr($argument, 9));
                continue;
            }

            if (str_starts_with($argument, '--fail-on=')) {
                $options['fail_on'] = strtolower(substr($argument, 10));
                continue;
            }

            if (str_starts_with($argument, '-')) {
                throw new \InvalidArgumentException('Unknown option.');
            }

            if ($options['directory'] !== '') {
                throw new \InvalidArgumentException('Only one target directory is allowed.');
            }

            $options['directory'] = $argument;
        }

        if ($options['directory'] === '' || !is_dir($options['directory'])) {
            throw new \InvalidArgumentException('A valid target directory is required.');
        }

        if (!in_array($options['format'], ['console', 'json', 'sarif'], true)) {
            throw new \InvalidArgumentException('Invalid report format.');
        }

        if (!in_array($options['fail_on'], ['info', 'low', 'medium', 'high', 'critical'], true)) {
            throw new \InvalidArgumentException('Invalid failure threshold.');
        }

        return $options;
    }

    private function writeStdout(string $contents): bool
    {
        $written = fwrite(STDOUT, $contents);

        return $written !== false && $written === strlen($contents);
    }

    private function fail(): int
    {
        fwrite(STDERR, "Laravibe error: scan could not be completed.\n");

        return 2;
    }

    private function help(): string
    {
        return <<<'TEXT'
Laravibe — offline, fail-closed security scanner for Laravel

Usage:
  laravibe scan <path> [options]

Options:
  --production          Check production environment safeguards
  --format=<format>     console, json, or sarif
  --fail-on=<severity>  info, low, medium, high, or critical (default: high)
  --version             Show the version
  -h, --help            Show this help

Write reports with shell redirection, for example:
  laravibe scan . --format=sarif > laravibe-report.sarif

Exit codes: 0 clean, 1 findings at threshold, 2 scanner/configuration failure.
No source snippets or environment values are included in reports.
Target project code is never executed and Laravibe performs no network requests.
TEXT
        . "\n";
    }
}
