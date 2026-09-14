# Contributing

1. Fork the repository and create a focused branch.
2. Add a failing test before changing scanner behavior.
3. Run `composer check`.
4. Open a pull request explaining the rule's signal, false-positive risks, and remediation.

Rules must never print source snippets, environment values, credentials, absolute project paths, or control characters. Unsafe, unreadable, oversized, or incomplete first-party scans must fail closed rather than produce a clean result.
