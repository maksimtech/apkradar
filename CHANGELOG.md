# Changelog

All notable changes to APKRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses calendar versioning (`YYYY.MM.N`).

## [Unreleased]

## [2026.40] - 2026-09-26
### Changed

- **Baseline: the five Radar restart from a common number.** They had drifted to
  .32, .12, .11, .6 and .3 of the same generation, which left the shared part of
  the version meaning nothing at all. The highest count in the suite was taken,
  rounded up for headroom, and every Radar starts again from 2026.40 — a jump
  for most of them, and a number that means the same thing in all five.

  From here the count belongs to each Radar again, and something urgent gets a
  third segment on top: 2026.40.1 before 2026.41, the way a suite has always
  done it. 2026 is a settling year; from 2027 the count moves when the code
  moves.


### Added

- **The app itself is now a third witness on who publishes it.** Two sources
  named the publisher's domain and neither could check the other: the reverse-DNS
  of the package name and Play's `developerWebsite` are both written by whoever
  built the app, so when they agreed the report called the domain established on
  the strength of one party saying the same thing twice. The package is the one
  source that is not a declaration. `apkradar/content.py` asks it a single
  question about a single host — does this package name it, and does the mention
  look deliberate — and deliberately cannot answer with a domain of its own, so
  it can corroborate a candidate and never introduce one.

  Deliberate means the app points at a page of the host that describes the
  relationship (`/privacy`, `/informativa`, `/terms`, `/legal`) or names it at
  least three times. One bare occurrence stays a coincidence.

  Measured on three real apps: 112 Where ARE U names `where.areu.lombardia.it`
  nine times including the URL of its privacy notice, and `beta80group.it` — the
  software house that built it — not once, so the art. 32 letter now goes to the
  agency rather than to its supplier. On abc 123 Tracing neither candidate
  appears at all, which is the honest outcome for an app that says nothing about
  itself: nothing established, no letter.

  The corroboration never applies to the package-name guess. Corroborating that
  with the contents of the APK is the developer agreeing with themselves.

- `provenance` gains `corroborated`, printed as "from Google Play listing, and
  the app points at it". Nothing that was established before stops being
  established.

### Fixed

- **Seven audit defects, each reproduced on a real APK before being fixed.** Two
  of the three artifacts are byte-identical to the ones in the report and the
  Play listings were read live. Which domain belongs to the publisher: reversing
  the package name gives whoever *built* the app — `it.Beta80Group.whereareu`
  gives a software house for an app published by a regional health agency — and
  `developerWebsite` is not authoritative either, since for one app it is a
  Zendesk helpdesk tenant whose mail posture is Zendesk's. Both are consulted
  now, platform tenants are dropped, the listing wins over the guess, and at most
  one domain is ever analysed as the publisher's. A guess is never presented as a
  fact, and a domain that was set aside is not printed at all: it belongs to a
  third party.

- **A domain that is for sale is never audited.** `gameitech.com`, the
  reverse-DNS of a children's app, redirects to a for-sale lander; a score of
  0/100 there is the posture of a parking page, and anyone may buy the name after
  a report quoting it is written.

- **The README example renders the way a real terminal shows it.** The tables had
  square corners because the block was generated on a console reporting
  `legacy_windows=True`, which substitutes the box characters `box.ROUNDED` asks
  for. It is now rendered through a console the test declares — 80 columns, no
  colour, `legacy_windows=False` — so the same bytes come out on any machine.

## [2026.09.32] - 2026-09-24

### Fixed
- **`apkradar batch` reads its list of APKs as UTF-8.** It used a bare
  `open(file)`, so the locale chose the encoding: a UTF-8 list of paths was read
  correctly on Linux and wrongly on a Windows console — and the path that came
  back would not open, while the run reported it as though it had. Three more
  defects in the same four lines: a byte order mark, which Notepad writes by
  default, became part of the first path and that path then "did not exist"; an
  `OSError` that is not `FileNotFoundError` — a directory, a permission —
  escaped as a traceback instead of a message; and `#` was tested against the
  unstripped line, so an **indented comment was treated as an APK path**.
- **A peer that presents no TLS certificate is reported as such.**
  `getpeercert()` answers `None` in that case, and indexing it raised
  `TypeError`, which the bare `except` turned into `"error"`: the right outcome
  reached by the wrong road. The `verify_code` attribute is also validated
  before it is used as a dictionary key.
- **An unverifiable law now says what it costs.** The report warned that an act
  could not be fetched, and separately printed `SHA256: non disponibile` against
  each citation, with nothing joining the two — so a missing hash read as a
  defect in the hashing. It is not: with no verified text there is nothing to
  hash, and printing one anyway would assert a verification that never happened.
- **`APKRADAR_HOME` is no longer taken literally.** `~/cache` made a directory
  named `~`, a relative value followed the working directory so the cache
  stopped being one cache, and `"   "` became a directory name.
- The Excel export no longer builds a list of transfer entity names on every row
  of every sheet and discards it.

### Changed
- ruff, mypy, hypothesis and mutmut are development dependencies, with a
  `Quality` workflow running ruff and mypy on every push and pull request, and a
  weekly, non-blocking mutation run.
- The suite gains eleven properties checked against generated input, and a
  contract test that refuses any code letting the locale choose a text
  encoding.
- **Every string the tool writes itself is now in English**, which the
  CHANGELOG already was. The report's section is `Provisions applied` rather
  than `Norme applicate`, and finding titles, scope notes, evidence lines and
  the release script's messages follow. Two things stay Italian on purpose: a
  provision's quoted text, which is fetched from the official Italian version of
  each act and hashed — translating it would change every SHA-256 in every cache
  — and `templates/dpo_letter_it.txt`, a formal letter addressed to an Italian
  data protection officer.

## [2026.09.31] - 2026-09-19

### Added
- `audit` ends with a "Provisions applied" section: each finding cites the legal
  provisions it concerns, with the SHA-256 of the exact text applied and the
  date of that wording. The text is downloaded on every audit and cached in
  `~/.apkradar/law_cache.json` (`APKRADAR_HOME` moves the folder); a changed
  text is reported with its previous hash. Offline the cached copy is cited,
  or "SHA256: non disponibile". A failed law check never fails the audit.
  - GDPR (EUR-Lex): trackers → art. 5(1)(a) and 6; extra-EU transfers →
    art. 46; trackers persisting after rejection (`--full`) → art. 7;
    sensitive permissions → art. 9.
  - Directive (EU) 2019/770 on digital content (EUR-Lex): trackers →
    art. 8(1)(b), to be checked against the app's privacy policy.
  - Italian Consumer Code, D.Lgs. 206/2005 (Normattiva, text in force):
    sensitive permissions → art. 49, information for distance contracts, to be
    checked against the information the app gives before download.

## [2026.09.30] - 2026-09-18

### Added
- `apkradar --version` prints `APKRadar <version>` and exits with code 0.

### Fixed
- Firebase Crashlytics is now detected. Only the legacy Fabric package
  (`com.crashlytics`) was recognised, so apps using the current SDK
  (`com.google.firebase.crashlytics`) reported no Crashlytics tracker. Apps
  containing both are listed once.
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

[Unreleased]: https://github.com/maksimtech/apkradar/compare/v2026.09.30...HEAD
[2026.09.30]: https://github.com/maksimtech/apkradar/compare/v2026.09.29...v2026.09.30
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
