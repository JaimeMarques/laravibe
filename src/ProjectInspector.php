<?php

declare(strict_types=1);

namespace Laravibe;

use JsonException;
use RuntimeException;

final class ProjectInspector
{
    public static function isLaravelProject(string $directory): bool
    {
        $root = realpath($directory);

        if ($root === false || !is_dir($root)) {
            return false;
        }

        try {
            $contents = (new SafeFileReader())->read(
                $root,
                rtrim($root, DIRECTORY_SEPARATOR) . '/composer.json',
                1_000_000,
            );
        } catch (RuntimeException) {
            return false;
        }

        try {
            $composer = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return false;
        }

        if (!is_array($composer)) {
            return false;
        }

        $packages = array_merge(
            is_array($composer['require'] ?? null) ? $composer['require'] : [],
            is_array($composer['require-dev'] ?? null) ? $composer['require-dev'] : [],
        );

        return isset($packages['laravel/framework']) || isset($packages['illuminate/foundation']);
    }
}
