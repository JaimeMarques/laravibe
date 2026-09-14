<?php

declare(strict_types=1);

namespace Laravibe;

use Throwable;

final class SecurityScanner
{
    public function scan(
        string $directory,
        bool $production = false,
    ): ScanReport {
        $target = realpath($directory) ?: $directory;

        if (!ProjectInspector::isLaravelProject($target)) {
            return new ScanReport(
                target: $target,
                errors: ['Target is not a Laravel project.'],
            );
        }

        $findings = [];
        $errors = [];

        try {
            array_push($findings, ...(new NativeScanner())->scan($target, $production));
        } catch (Throwable) {
            $errors[] = 'native: scan incomplete.';
        }

        return new ScanReport(
            target: $target,
            findings: $findings,
            errors: $errors,
        );
    }
}
