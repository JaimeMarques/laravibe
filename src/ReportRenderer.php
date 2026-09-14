<?php

declare(strict_types=1);

namespace Laravibe;

use InvalidArgumentException;
use JsonException;

final class ReportRenderer
{
    /** @throws JsonException */
    public function render(ScanReport $report, string $format): string
    {
        if ($format === 'console') {
            return $this->consoleReport($report);
        }

        $data = match ($format) {
            'json' => $this->reportData($report),
            'sarif' => $this->sarifData($report),
            default => throw new InvalidArgumentException('Unsupported report format.'),
        };

        return json_encode(
            $data,
            JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE,
        ) . "\n";
    }

    private function consoleReport(ScanReport $report): string
    {
        $lines = ['Laravibe — project', str_repeat('=', 60)];

        foreach ($report->findings as $finding) {
            $location = $this->safePath($finding->path) . ($finding->line > 0 ? ':' . $finding->line : '');
            $lines[] = sprintf('[%s] %s  %s', strtoupper($finding->severity), $finding->ruleId, $location);
            $lines[] = '  ' . $this->safeText($finding->message);
            $lines[] = '  Fix: ' . $this->safeText($finding->remediation);
        }

        foreach ($report->errors as $error) {
            $lines[] = '[ERROR] ' . $this->safeText($error);
        }

        $lines[] = str_repeat('-', 60);
        $lines[] = sprintf('%d finding(s), %d scanner error(s)', count($report->findings), count($report->errors));

        return implode("\n", $lines) . "\n";
    }

    /** @return array<string, mixed> */
    private function sarifData(ScanReport $report): array
    {
        $rules = [];
        $results = [];

        foreach ($report->findings as $finding) {
            $level = match ($finding->severity) {
                'critical', 'high' => 'error',
                'medium' => 'warning',
                'low', 'info' => 'note',
                default => throw new InvalidArgumentException('Invalid finding severity.'),
            };
            $message = $this->safeText($finding->message);
            $remediation = $this->safeText($finding->remediation);

            if (!isset($rules[$finding->ruleId])) {
                $rules[$finding->ruleId] = [
                    'id' => $finding->ruleId,
                    'shortDescription' => ['text' => $finding->ruleId],
                    'help' => ['text' => $remediation],
                    'defaultConfiguration' => ['level' => $level],
                ];
            }

            $physicalLocation = [
                'artifactLocation' => ['uri' => $this->sarifUri($finding->path)],
            ];

            if ($finding->line > 0) {
                $physicalLocation['region'] = ['startLine' => $finding->line];
            }

            $results[] = [
                'ruleId' => $finding->ruleId,
                'level' => $level,
                'message' => ['text' => $message . ' ' . $remediation],
                'locations' => [['physicalLocation' => $physicalLocation]],
            ];
        }

        $notifications = array_map(
            fn (string $error): array => [
                'level' => 'error',
                'message' => ['text' => $this->safeText($error)],
            ],
            $report->errors,
        );

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'Laravibe',
                        'version' => '0.1.0',
                        'informationUri' => 'https://github.com/MrTheSoulz/laravibe',
                        'rules' => array_values($rules),
                    ],
                ],
                'invocations' => [[
                    'executionSuccessful' => !$report->hasOperationalErrors(),
                    'toolExecutionNotifications' => $notifications,
                ]],
                'results' => $results,
            ]],
        ];
    }

    /** @return array<string, mixed> */
    private function reportData(ScanReport $report): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];

        foreach ($report->findings as $finding) {
            $counts[$finding->severity]++;
        }

        return [
            'schema_version' => 1,
            'tool' => 'laravibe',
            'target' => 'project',
            'status' => $report->hasOperationalErrors()
                ? 'error'
                : ($report->findings === [] ? 'clean' : 'findings'),
            'summary' => ['total' => count($report->findings)] + $counts,
            'findings' => array_map(fn (Finding $finding): array => $this->findingData($finding), $report->findings),
            'errors' => array_map(fn (string $error): string => $this->safeText($error), $report->errors),
        ];
    }

    /** @return array{rule_id: string, severity: string, message: string, path: string, line: int, remediation: string, tool: string} */
    private function findingData(Finding $finding): array
    {
        return [
            'rule_id' => $finding->ruleId,
            'severity' => $finding->severity,
            'message' => $this->safeText($finding->message),
            'path' => $this->safePath($finding->path),
            'line' => $finding->line,
            'remediation' => $this->safeText($finding->remediation),
            'tool' => $this->safeText($finding->tool),
        ];
    }

    private function safeText(string $text): string
    {
        $sanitized = preg_replace('/[\x00-\x1F\x7F-\x9F]+/', ' ', $text);

        return trim(substr(is_string($sanitized) ? $sanitized : '', 0, 2_000));
    }

    private function safePath(string $path): string
    {
        $normalized = str_replace('\\', '/', $path);
        $sanitized = preg_replace('/[\x00-\x1F\x7F-\x9F]/', '_', $normalized);

        return substr(is_string($sanitized) ? $sanitized : 'redacted', 0, 1_000);
    }

    private function sarifUri(string $path): string
    {
        return implode('/', array_map('rawurlencode', explode('/', $this->safePath($path))));
    }
}
