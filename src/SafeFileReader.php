<?php

declare(strict_types=1);

namespace Laravibe;

use RuntimeException;

final class SafeFileReader
{
    public function read(string $root, string $path, int $maxBytes): string
    {
        if ($maxBytes < 1) {
            throw new RuntimeException('Invalid file size limit.');
        }

        $canonicalRoot = realpath($root);
        $before = @lstat($path);
        $canonicalPath = realpath($path);

        if ($canonicalRoot === false
            || $before === false
            || $canonicalPath === false
            || !$this->isRegularFile($before)
            || !$this->isWithinRoot($canonicalRoot, $canonicalPath)) {
            throw new RuntimeException('Unsafe or unreadable file.');
        }

        if ($before['size'] > $maxBytes) {
            throw new RuntimeException('File exceeds the scan size limit.');
        }

        $stream = @fopen($path, 'rb');

        if (!is_resource($stream)) {
            throw new RuntimeException('File could not be opened safely.');
        }

        try {
            $opened = fstat($stream);

            if ($opened === false || !$this->sameFile($before, $opened) || !$this->isRegularFile($opened)) {
                throw new RuntimeException('File changed during validation.');
            }

            $contents = stream_get_contents($stream, $maxBytes + 1);
            $after = fstat($stream);

            if (!is_string($contents)
                || strlen($contents) > $maxBytes
                || $after === false
                || !$this->sameFile($opened, $after)) {
                throw new RuntimeException('File changed or exceeded limits while being read.');
            }

            return $contents;
        } finally {
            fclose($stream);
        }
    }

    /** @param array<int|string, int|string> $stat */
    private function isRegularFile(array $stat): bool
    {
        $mode = $stat['mode'] ?? null;

        return is_int($mode) && ($mode & 0170000) === 0100000;
    }

    /**
     * @param array<int|string, int|string> $left
     * @param array<int|string, int|string> $right
     */
    private function sameFile(array $left, array $right): bool
    {
        return isset($left['dev'], $left['ino'], $right['dev'], $right['ino'])
            && $left['dev'] === $right['dev']
            && $left['ino'] === $right['ino'];
    }

    private function isWithinRoot(string $root, string $path): bool
    {
        $normalizedRoot = rtrim(str_replace('\\', '/', $root), '/');
        $normalizedPath = str_replace('\\', '/', $path);

        return $normalizedPath === $normalizedRoot
            || str_starts_with($normalizedPath, $normalizedRoot . '/');
    }
}
