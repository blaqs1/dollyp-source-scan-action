# DollyP Source Scan Action

Reusable static source-code scanner for DollyP WebChecker.

This action:

- scans a local workspace or a validated ZIP extraction
- never installs dependencies from the scanned project
- never runs project code, tests, builds, hooks, Docker, or package scripts
- submits only redacted structured findings to DollyP

Inputs are intentionally narrow and must be issued by DollyP backend task tickets.
