# Changelog

All notable changes to APKRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses calendar versioning (`YYYY.MM.N`).

## [Unreleased]

### Added
- `apkradar --version` prints `APKRadar <version>` and exits with code 0.

### Fixed
- `batch-excel` without `--output` now writes the report next to the input as
  `<name>_report.xlsx`. Previously the file name was malformed
  (`registro.xlsx` → `registro_report_report.xlsxx`), a `.xls`/`.xlsx`
  sequence in a folder name was rewritten too, and an input with an uppercase
  extension (`REGISTRO.XLSX`) was overwritten by the report.

## [2026.09.29] - 2026-09-17

### Fixed
- **Tracker false negatives eliminated.** SDKs that declare no manifest
  component (Firebase Analytics, AppsFlyer, Facebook App Events) were never
  detected, because the scanner only inspected manifest components. The
  scanner now also searches the APK's DEX files for class descriptors
  (e.g. `Lcom/appsflyer/`), only for signatures the manifest did not already
  match. DEX files are streamed in 4 MB blocks with overlap, so a large DEX is
  never loaded into memory in full, and an unreadable DEX never fails the scan.
- Firebase Analytics is now also detected through
  `com.google.android.gms.measurement`.
- **Extra-EU transfers for SDKs found only in the code.** Extra-EU vendors were
  matched against manifest components only, so an SDK detected in the DEX files
  (e.g. AppsFlyer, Firebase Analytics) did not report its vendor. The vendor of
  every detected SDK is now reported as an extra-EU transfer.
- **One entry per SDK.** When several signatures identify the same SDK (Firebase
  Analytics via `com.google.firebase.analytics` and
  `com.google.android.gms.measurement`), it is listed once and counted once in
  the score, instead of once per matching signature.
- `batch-excel`: rows with a package name but no APK path are no longer counted
  as failed audits. They are marked `SKIPPED` with an empty score, reported in a
  summary line, and no longer cause exit code 1.

### Changed
- `render_letter()` no longer accepts the unused `ssl_expiry` parameter. The
  expiry date is still shown in the CLI output.

## [2026.09.28] - 2026-09-16

### Security
- Rich markup injection: all external data printed by the CLI (app names, file
  paths, domains, Play Store fields, CookieRadar errors, search queries, Excel
  rows) is now escaped, so crafted values can no longer inject console markup.
- Excel formula injection (CSV/formula injection, OWASP): string values written
  to Excel reports are always stored as text, and values starting with `=`,
  `+`, `-`, `@`, tab or carriage return also get Excel's quote prefix, so they
  stay text even after editing or CSV export.

### Changed
- CodSpeed benchmarks: action upgraded from v3 to v5, mode switched from
  `walltime` to `simulation`.

## [2026.09.27] - 2026-09-16

### Security
- SMTP delivery of DPO letters now verifies the server certificate and hostname
  (both SMTPS on port 465 and STARTTLS) before sending credentials.

### Fixed
- **Tracker false positives eliminated.** Components were truncated to 3-4
  package segments and matched with a bidirectional substring test, so a
  generic prefix such as `com.google.android` matched
  `com.google.android.gms.analytics` and reported trackers the app does not
  contain. Matching is now segment-aware: a component matches a signature only
  if it is that package or lives under it. The same fix applies to extra-EU
  transfer detection.
- A failed scan now scores 0 instead of being scored as a clean app. `audit`
  exits with code 1 on a failed scan; `batch` and `batch-excel` report how many
  scans failed and exit with code 1.
- `send` refuses to generate or send a DPO letter when the scan failed.
- SSL status is classified from the OpenSSL verification code: `expired`,
  `hostname_mismatch`, `self_signed`, `unknown_ca`, `invalid`, `timeout`,
  `error`. Previously any verification failure was reported as "expired", and
  `send` reported any other error as "valid".
- DPO letter, technical measures section: the MailRadar score is described as
  inadequate only when it is below 60; SSL is stated as an issue only for
  expired, self-signed or unknown-CA certificates (a hostname mismatch is
  excluded, since the publisher domain is inferred from the package name).

## [2026.09.26] - 2026-09-15

No functional changes (test coverage raised to 89%).

## [2026.09.25] - 2026-09-15

### Fixed
- Added the missing `openpyxl` runtime dependency required by the Excel
  features.

## [2026.09.24] - 2026-09-15

No functional changes (Excel module tests).

## [2026.09.23] - 2026-09-15

### Added
- Excel input/output and the `batch-excel` command.

## [2026.09.22] - 2026-09-15

### Fixed
- Added the missing `google-play-scraper` runtime dependency required by the
  `search` command.

## [2026.09.21] - 2026-09-15

No functional changes (search command tests).

## [2026.09.20] - 2026-09-15

### Changed
- Removed the old `search.py` module, replaced by `search_cmd.py`.

## [2026.09.19] - 2026-09-15

### Added
- `search` command.
- `--verbose` flag for full stack analysis.

### Changed
- CI: `SonarSource/sonarqube-scan-action` bumped from v5 to v6.

## [2026.09.18] - 2026-09-14

### Added
- Domain extraction from bundled SDKs and multi-domain full stack analysis.

### Fixed
- Removed `asyncio_mode` from the pytest configuration.

## [2026.09.17] - 2026-09-12

No functional changes.

## [2026.09.16] - 2026-09-12

No functional changes.

## [2026.09.15] - 2026-09-12

### Fixed
- Benchmarks rewritten as stable, instrumentation-friendly tests.

## [2026.09.14] - 2026-09-12

### Changed
- CI: `pytest-timeout` added to all workflows.

## [2026.09.13] - 2026-09-12

### Changed
- Default pytest timeout of 30 seconds.

## [2026.09.12] - 2026-09-12

### Security
- SSL certificate check enforces TLS 1.2 as the minimum protocol version
  (CodeQL `py/insecure-protocol`).

## [2026.09.11] - 2026-09-12

### Added
- `send`: NOYB support.

### Changed
- `send`: universal DPO letter template.

## [2026.09.10] - 2026-09-12

### Added
- `send`: SSL certificate check and MailRadar integration.

## [2026.09.9] - 2026-09-12

### Added
- `send` command to generate and deliver GDPR letters to the DPO.

## [2026.09.8] - 2026-09-12

### Fixed
- Release pipeline waits 60 seconds for PyPI propagation before the Docker
  build.

## [2026.09.7] - 2026-09-12

No functional changes (extractor and utils edge case tests).

## [2026.09.6] - 2026-09-12

### Changed
- `package_to_domain` detects generic package segments and extracts deep
  links.

## [2026.09.5] - 2026-09-12

### Added
- APK format shown in the audit output.

### Fixed
- Full stack analysis uses `total_score` and `grade` from MailRadar's
  `DomainReport`.

## [2026.09.4] - 2026-09-12

### Added
- XAPK (APKPure) and APKM (APKMirror) bundle support via the extractor module.

## [2026.09.3] - 2026-09-12

### Fixed
- Full stack analysis uses `analyze_domain` from MailRadar and `asyncio.run`
  for CookieRadar.

## [2026.09.2] - 2026-09-12

### Added
- `--full` flag: full stack analysis with MailRadar and CookieRadar.

### Fixed
- Benchmarks excluded from the default pytest run.

## [2026.09.1] - 2026-09-12

### Added
- Initial APKRadar CLI.
- Scanner with tracker detection, sensitive permissions analysis and extra-EU
  transfer detection.
- Dockerfile and `SECURITY.md`.
- CI/CD pipeline: tests, PyPI publish, Docker image, security scans,
  SonarCloud, Codecov and CodSpeed benchmarks.

### Changed
- GitHub Actions bumped: `actions/checkout` 4→7, `actions/setup-python` 5→7,
  `docker/login-action` 3→4, `docker/build-push-action` 6→7,
  `softprops/action-gh-release` 2→3.

### Fixed
- Docker image no longer depends on `openjdk`, which is not available on
  Debian Trixie.
- `.github` and `Dockerfile` excluded from SonarCloud analysis.

[Unreleased]: https://github.com/maksimtech/apkradar/compare/v2026.09.29...HEAD
[2026.09.29]: https://github.com/maksimtech/apkradar/compare/v2026.09.28...v2026.09.29
[2026.09.28]: https://github.com/maksimtech/apkradar/compare/v2026.09.27...v2026.09.28
[2026.09.27]: https://github.com/maksimtech/apkradar/compare/v2026.09.26...v2026.09.27
[2026.09.26]: https://github.com/maksimtech/apkradar/compare/v2026.09.25...v2026.09.26
[2026.09.25]: https://github.com/maksimtech/apkradar/compare/v2026.09.24...v2026.09.25
[2026.09.24]: https://github.com/maksimtech/apkradar/compare/v2026.09.23...v2026.09.24
[2026.09.23]: https://github.com/maksimtech/apkradar/compare/v2026.09.22...v2026.09.23
[2026.09.22]: https://github.com/maksimtech/apkradar/compare/v2026.09.21...v2026.09.22
[2026.09.21]: https://github.com/maksimtech/apkradar/compare/v2026.09.20...v2026.09.21
[2026.09.20]: https://github.com/maksimtech/apkradar/compare/v2026.09.19...v2026.09.20
[2026.09.19]: https://github.com/maksimtech/apkradar/compare/v2026.09.18...v2026.09.19
[2026.09.18]: https://github.com/maksimtech/apkradar/compare/v2026.09.17...v2026.09.18
[2026.09.17]: https://github.com/maksimtech/apkradar/compare/v2026.09.16...v2026.09.17
[2026.09.16]: https://github.com/maksimtech/apkradar/compare/v2026.09.15...v2026.09.16
[2026.09.15]: https://github.com/maksimtech/apkradar/compare/v2026.09.14...v2026.09.15
[2026.09.14]: https://github.com/maksimtech/apkradar/compare/v2026.09.13...v2026.09.14
[2026.09.13]: https://github.com/maksimtech/apkradar/compare/v2026.09.12...v2026.09.13
[2026.09.12]: https://github.com/maksimtech/apkradar/compare/v2026.09.11...v2026.09.12
[2026.09.11]: https://github.com/maksimtech/apkradar/compare/v2026.09.10...v2026.09.11
[2026.09.10]: https://github.com/maksimtech/apkradar/compare/v2026.09.9...v2026.09.10
[2026.09.9]: https://github.com/maksimtech/apkradar/compare/v2026.09.8...v2026.09.9
[2026.09.8]: https://github.com/maksimtech/apkradar/compare/v2026.09.7...v2026.09.8
[2026.09.7]: https://github.com/maksimtech/apkradar/compare/v2026.09.6...v2026.09.7
[2026.09.6]: https://github.com/maksimtech/apkradar/compare/v2026.09.5...v2026.09.6
[2026.09.5]: https://github.com/maksimtech/apkradar/compare/v2026.09.4...v2026.09.5
[2026.09.4]: https://github.com/maksimtech/apkradar/compare/v2026.09.3...v2026.09.4
[2026.09.3]: https://github.com/maksimtech/apkradar/compare/v2026.09.2...v2026.09.3
[2026.09.2]: https://github.com/maksimtech/apkradar/compare/v2026.09.1...v2026.09.2
[2026.09.1]: https://github.com/maksimtech/apkradar/releases/tag/v2026.09.1
