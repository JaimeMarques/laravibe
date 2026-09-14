<?php

declare(strict_types=1);

namespace Laravibe;

final readonly class ScanReport
{
    /**
     * @param list<Finding> $findings
     * @param list<string> $errors
     */
    public function __construct(
        public string $target,
        public array $findings = [],
        public array $errors = [],
    ) {
    }

    public function hasOperationalErrors(): bool
    {
        return $this->errors !== [];
    }

    public function exitCode(string $failOn): int
    {
        if ($this->hasOperationalErrors()) {
            return 2;
        }

        $threshold = $this->severityRank($failOn);

        foreach ($this->findings as $finding) {
            if ($this->severityRank($finding->severity) >= $threshold) {
                return 1;
            }
        }

        return 0;
    }

    private function severityRank(string $severity): int
    {
        return match (strtolower($severity)) {
            'info' => 0,
            'low' => 1,
            'medium' => 2,
            'high' => 3,
            'critical' => 4,
            default => throw new \InvalidArgumentException('Invalid severity threshold.'),
        };
    }
}
