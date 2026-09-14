<?php

declare(strict_types=1);

namespace Laravibe;

use JsonSerializable;

final readonly class Finding implements JsonSerializable
{
    public function __construct(
        public string $ruleId,
        public string $severity,
        public string $message,
        public string $path,
        public int $line,
        public string $remediation,
        public string $tool = 'native',
    ) {
        if (preg_match('/\A[A-Z0-9][A-Z0-9._-]{0,127}\z/', $ruleId) !== 1) {
            throw new \InvalidArgumentException('Invalid finding rule identifier.');
        }

        if (!in_array($severity, ['info', 'low', 'medium', 'high', 'critical'], true)) {
            throw new \InvalidArgumentException('Invalid finding severity.');
        }

        $normalizedPath = str_replace('\\', '/', $path);

        if ($path === ''
            || str_starts_with($normalizedPath, '/')
            || preg_match('/\A[A-Za-z]:\//', $normalizedPath) === 1
            || in_array('..', explode('/', $normalizedPath), true)
            || $line < 0) {
            throw new \InvalidArgumentException('Invalid finding location.');
        }

        if ($message === '' || $remediation === '' || $tool === '') {
            throw new \InvalidArgumentException('Invalid finding metadata.');
        }
    }

    /** @return array{rule_id: string, severity: string, message: string, path: string, line: int, remediation: string, tool: string} */
    public function jsonSerialize(): array
    {
        return [
            'rule_id' => $this->ruleId,
            'severity' => $this->severity,
            'message' => $this->message,
            'path' => $this->path,
            'line' => $this->line,
            'remediation' => $this->remediation,
            'tool' => $this->tool,
        ];
    }
}
