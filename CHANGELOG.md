# Changelog

All notable changes to APKRadar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses **CalVer, Apple style**: `YYYY.count[.fix]`, not SemVer.
`YYYY` is the generation, shared by the five Radar; the count belongs to each of
them and moves when its code moves; the third segment is for something urgent on
what has already shipped. The line above said `YYYY.MM.N` until 2026-09-29, which
no version in this file has ever matched — 40 is not a month, and
`tests/test_version_contract.py` has been enforcing the real form all along.

## [Unreleased]

### Fixed

- **A manifest component whose class is not in the DEX is no longer a tracker, nor a
  transfer.** Fennec 157.0.0 as F-Droid builds it (`org.mozilla.fennec_fdroid` 1570020,
  SHA-256 `04a5f4d3…47a9`) declares `com.adjust.sdk.AdjustPreinstallReferrerReceiver`
  and holds no class under `com.adjust` in any of its three DEX files: the build is made
  without the Adjust SDK and the manifest keeps the receiver. The audit reported "Adjust"
  and a transfer to "Adjust GmbH (Germany) → USA", and the DPO letter would have put both
  in front of Mozilla — an allegation about code that is not in the file. Declared
  components are now confirmed against the DEX (`Lcom/adjust/sdk/Adjust…Receiver;`,
  the whole descriptor) before they count; an APK with no readable code is still read on
  the manifest's word, since "nothing to check against" is not "confirmed absent".
  `tests/test_declared_without_code.py` holds the manifest excerpt as a real APK.
- **`--full` no longer audits every deep-link host of an app that opens other sites'
  links.** OsmAnd~ 5.4.9 (`net.osmand.plus` 540903) declares 427 deep-link hosts —
  maps.google.com and some 200 Google country domains, map.baidu.com, maps.yandex.ru,
  here.com, maps.apple.com — because it opens links to other maps; NewPipe 0.29.1 declares
  56 for YouTube, SoundCloud, Bandcamp and PeerTube instances. Each was taken as "SDK or
  deep-link domain found in the APK" and queued for MailRadar, a TLS handshake and a
  headless browser: on OsmAnd about three and a half hours, at the ~30 s per domain
  measured on Mastodon the same day, of traffic to Google, Baidu and Yandex about an app
  that talks to none of them. Above `MAX_DEEP_LINK_DOMAINS` (10; the most a publisher was
  seen declaring for itself is F-Droid's four) no deep-link host is audited, the report
  says how many were set aside and why, and the hosts stay in `ScanResult.manifest_domains`
  as data. `tests/test_deep_links_cap.py` holds 24 of OsmAnd's hosts as a real APK.

## [2026.44.1] - 2026-10-09

### Changed

- **The suite also runs on Python 3.15-dev, as a row that may fail.** 3.15 goes final
  on 2026-10-09 (PEP 790). The classifiers and the stable matrix stay at 3.11-3.14 and
  `tests/test_ci_dependencies.py` now checks that they are the same list, with the
  experimental row being the version after the last one. A dependency without a wheel
  for 3.15 shows up as a yellow row before the release rather than as a red matrix
  after the classifier is added; mailradar and patchradar have had the row since
  3.14-dev.

### Security

- **The image no longer installs `gnupg` and `default-jre-headless`, which nothing in it
  ran.** Both stood in the Dockerfile from the first commit (2026-09-12; the JRE as
  `openjdk-17-jre-headless` until trixie stopped shipping it). No code in apkradar
  executes a system binary: the APK is read by androguard, which is pure Python; the DPO
  letter goes out over SMTP from this package's own sender; `mailradar.checker`, the one
  mailradar entry point apkradar calls, looks GPG keys up over HTTP through
  `mailradar.gpg`, and `cookieradar.scanner` runs no Java. The `gpg` binary is run by
  `mailradar.sender`, which apkradar never imports.

  What `gnupg` did bring in was dirmngr → libldap2 → libsasl2-2, and Docker Scout
  reported CVE-2026-107161 (high) in cyrus-sasl2 against it — "not fixed" in trixie, open
  in every Debian suite according to `patchradar debian`, so no rebuild would ever have
  closed it. `libsasl2-2` is not in `python:3.12-slim-trixie` itself, measured with
  `apt-get install -s gnupg` in the base image: it arrives only with `gnupg`, and leaves
  with it. The apt step is now `update && upgrade`, as in exeradar and patchradar.

  Measured on the two images: 913 MB → 612 MB (`docker images`, 301 MB less), 117 → 87
  Debian packages, and `docker scout cves --only-package cyrus-sasl2` goes from one high
  to no package at all. `tests/test_docker_contract.py` now parses the apt step and
  fails on any package it names, and `tests/docker/inspect.sh`, run against the built
  image in CI, fails if `libsasl2-2`, `gnupg` or `default-jre-headless` is installed or
  `gpg` or `java` is on PATH — the one judgement in a script that otherwise only reports.
  The smoke test, `--help`, `--version` and an `audit` of a real APK were run inside the
  new image before this was written down.

## [2026.44] - 2026-10-08

### Added

- **The files the build is told to include are checked to be there.** apkradar lost its
  `LICENSE` out of the working tree on 2026-10-04 and the loss reached `main`: pyproject
  names the file, so `python -m build` failed with `License file does not exist: LICENSE`,
  and the PyPI publish and the image went down with it. cookieradar lost its own a few
  hours later, during a run of the suite. Neither suite noticed, because neither looked.

  What removes them is still not known, and these cases do not explain it. They stop it
  reaching a commit, which is the part that can be fixed without knowing.

  The expectation is read out of the declarations rather than written down as `LICENSE`,
  because the five Radar do not declare it the same way: patchradar states its licence as
  text and only its Dockerfile names the file, the other four name it in pyproject, and of
  those apkradar and mailradar do not copy it into the image. So two cases — every file
  pyproject names, and every path the Dockerfile copies — and between them each repository
  is covered, three of them twice.

  Checked by moving the file aside in all five: it fails where it should and passes where
  the declaration genuinely does not name it, and pointing pyproject at a file that is not
  there fails too.

### Fixed

- **The OCI licence label is the key the standard names.** It read
  `org.opencontainers.image.license`, singular, which nothing reads — so a tool asking the
  image what it is licensed under got no answer, while the label looked right in the file.
  cookieradar's suite has rejected that spelling for a while; this one had not been asked.

- **Two defences in `release.sh` that the tests did not actually measure.** Found by
  mutating the script rather than by reading it.

  Replacing the existing-tag check's `fail` with an `echo` of the same words left every
  case green: the script carried on, bumped, **committed**, and only then did `git tag`
  refuse the tag that already existed. The release was still refused — one commit too
  late, which is the opposite of what the script promises, that a refusal leaves the
  version file modified and nothing else. The cases now check that it did not commit on
  its way to refusing.

  And `git push --atomic` was not measured at all; two separate pushes passed. With two
  pushes `main` arrives and the tag does not, so the repository carries a version bump
  that no release and no published artifact corresponds to — and the tag that would
  produce them cannot be pushed afterwards either, because the version it would be
  given is by then "already the current version". A `pre-receive` hook on the test
  remote now refuses tags, which is the way to make the second half fail on demand.

  Both mutations fail now, along with the three that already did.

- **The PyPI wait allows a margin once the index answers.** apkradar's Docker build
  failed on 2026-10-03 with `No matching distribution found` **fifteen seconds after**
  the wait had reported the version available — 16:31:21 against 16:31:36. The poll is
  not wrong and not enough: it establishes that the file is reachable from the runner,
  while the build container, multi-platform through buildx, resolves the index again
  and can reach an edge still serving the old one.

  This is not the `sleep 60` that stood in that step before polling and lost the race
  twice. That was a guess about how long publishing takes, made before knowing
  anything; this waits for the fact first and then allows a bounded margin for it to
  propagate, and says so in the log when it uses one.

  It narrows the window; it does not close it. What closes it is not asking the index
  during the build at all — which is what exeradar's Dockerfile already does, with
  `pip install /app/src`, and why exeradar has no wait script and did not hit this.
  cookieradar and patchradar are one word from that (`_SOURCE=local`); apkradar and
  mailradar would need the build argument added. That follow-up is the first entry
  under Changed, below.

  Three cases hold the margin, and they were needed twice over. The two cases that
  already drove this script pass the retry interval as zero so they stay fast, and the
  new default made every success wait 45 seconds past their timeout — so the suite was
  red in all four repositories until those two were told to ask for no grace. Telling
  them that alone would have left the margin itself unmeasured, which is the shape of
  defect this script was written to fix in the first place. So: one case times a
  two-second grace and checks the log says why it waited, one checks that no grace
  waits for nothing and claims nothing, and one measures the *default* without the
  suite paying 45 seconds for it — started with no grace argument, the script must
  still be running three seconds after the index answered. All four ways of undoing
  the margin were checked against them: the default set to zero, the wait removed
  while the log still claims it, the log removed while the wait still happens, and the
  guard removed so zero waits anyway.

- **Deep links from the manifest are read on real APKs.** androguard 4 returns the
  manifest as bytes, the search for `android:host` was a str pattern, and the TypeError
  went into an `except Exception: pass` — so `manifest_domains` was empty on every APK,
  and a host like `where.areu.lombardia.it` never reached `audit --full` or
  `batch --full`. The suite did not notice because its mocks returned a str, which is
  what they return no longer.

- **A deep-link host has to be a hostname, and so does what is sent to a proxy.** Only
  `localhost`, `127.0.0.1` and `192.*` were refused: `10.0.2.2` (the emulator's host),
  other private addresses, values with spaces and values with a CR/LF went on to
  MailRadar, the certificate check and the `CONNECT` line, which wrote the domain in
  unchecked — a header of the APK's choosing, sent to the proxy. Latent while the deep
  links were never read, which is why the two were fixed together. The DEX scan's
  hostname rules now apply to the manifest too, and `_open_tunnel` refuses anything
  outside `[A-Za-z0-9.-]` before connecting.

- **`batch-excel --augment` writes each result on the row it came from.** Blank rows
  were skipped when reading and not when writing, so one blank line moved every later
  score, grade and tracker list onto the app above — in the file being overwritten.
  Both sides now use the first sheet, as the README says, rather than whichever sheet
  the file was last saved on.

- **`batch-excel` no longer calls a failed scan GOOD.** Its own chain of ifs fell
  through to "🟢 GOOD — N/A — 0 trackers" for a file that was never opened; it prints
  `batch`'s line now, sensitive permissions included.

- **`batch --output` reports start empty.** A failed scan saves no report, but stopping
  the recording did not clear Rich's buffer, and its output opened the next APK's file.

- **Corroboration by the APK checks the whole host.** `example.com.br` counted as a
  mention of `example.com`, and `https://example.com.attacker.net/privacy` or
  `https://example.com@attacker.net/privacy` as its policy page — enough to make the
  domain verified and the letter state an art. 32 finding against it. And the commonest
  case could never corroborate: Play's `https://www.example.com` is normalised to
  `example.com`, and the same `www.` host in the APK was refused for the dot before it.
  `www.` is the one prefix taken as the same host.

- **The letter is in one language.** Only the Italian template exists, and with
  `--lang en` the art. 9 reasons and the TLP block were still written in English inside
  it. The language is now the template's. `--lang` is also matched against the
  templates that exist before it reaches a path: on Windows `/../..` used to load any
  `.txt` as a Jinja template.

- **Smaller ones.** `BODY_SENSORS_BACKGROUND` is a sensitive permission, so its art. 9
  reason, which law_checker always had, can be reached. A DEX with exactly 500 hosts
  is no longer reported as stopped at 500. `NO_PROXY=*` means no proxy, as it does to
  curl, requests and httpx. `tlp.subject` does not take `TLP:AMBER+STRICT` for
  `TLP:AMBER`. Report names in `batch` are compared casefolded, so `App.apk` and
  `app.apk` no longer overwrite each other on Windows and macOS. A failed extraction
  from an XAPK or APKM removes its temporary directory. `com.my_company.app` maps to
  `my-company.com`, not to a name with an underscore, and `domain_to_url` no longer
  takes `httpbin.org` for a URL. `python -m apkradar.cli batch-excel` exists: the
  `__main__` block ran before that command was defined.

- **docker.yml no longer pastes the dispatch input into a script.** The version typed
  into the form was substituted into bash, and from there into Python, in the job that
  holds the Docker Hub token. It arrives through `env:` now and has to look like a
  release tag; the unused `NORMALIZED` output went with it. A case reads every workflow
  for the pattern.

- **Shell scripts are LF on every clone.** With Git for Windows' `core.autocrlf=true`,
  `release.sh` came out as `set -euo pipefail\r` and bash refused it, which a bash on
  Linux reading that checkout reports as 23 failing release cases. `.gitattributes`
  now says `*.sh text eol=lf`, and a case asks git that it does.

### Changed

- **mailradar 2026.43 and cookieradar 2026.43 are now the floor.** The audit leans on their checks — SPF, DMARC and DKIM on the publisher's domain, the cookie sessions on its site — and both shipped the fixes from the same review today: a bare `all` read as `+all`, `redirect=` followed, the ten-lookup limit, TLS verified before the password is sent; `batch` surviving a 403, the accept selector no longer clicking "disagree". `pip install -U apkradar` brings them along.
- **The race with PyPI is closed rather than narrowed, and two stale defaults went with
  it.** This is the repository where the race was measured: on 2026-10-03 the Docker build
  failed with `No matching distribution found` at 16:31:36, **fifteen seconds after** the
  wait had reported the version available at 16:31:21. The poll runs on the runner; the
  multi-platform build resolves the index again, per platform, from whichever edge answers.
  Before the poll a fixed `sleep 60` lost the same race twice, on 2026-09-24 and
  2026-09-30. Nothing that waits can close it. Not asking does, so the image is built from
  the source the tag points at.

  The Dockerfile could not do that — it only knew how to install from the index — so it
  gained the `local`/`pypi` switch the other Radar have, with `local` as the default,
  `--only-binary :all:` on both branches, and the source copied in. Nothing is compiled
  while building this image: it is built for amd64 and arm64, and a dependency without an
  aarch64 wheel would be compiled under QEMU, which in a release means tens of minutes or
  an out-of-memory.

  Two defaults had rotted, and both published August's code without anything looking
  wrong: `ARG APKRADAR_VERSION=2026.9.1` in the Dockerfile, while this project was at
  2026.43, so `docker build .` built August; and `default: 'v2026.09.8'` on the rebuild
  dispatch, so the form arrived pre-filled with something that looked deliberate.

  The checkout now stands on the tag being built. That matters more here than in exeradar
  or cookieradar, where a smoke test compares the version in the image against the tag
  before anything is pushed: this workflow logs in, builds and pushes, so a checkout left
  on the default branch would have published `main`'s code under an old release's tag
  rather than failing.

  And the image is built on every push and pull request, not only when asked.
  `docker-build-check.yml` could not run on its own before — the Dockerfile needed a
  published version handed to it — so the only thing that built this image automatically
  was the workflow that publishes it, and the first attempt at a build was the one that
  released. Given a version it still reproduces that one from the index, which keeps
  `latest_pypi_version.py` in use rather than orphaned.

  That the file on PyPI can be installed, which the old arrangement proved by accident, is
  now checked on purpose in `publish.yml` after the upload — where a slow index delays a
  check instead of failing a build, and with no margin, because there is a single resolver
  there.

  Ten mutations hold all of this, and all ten fail: the image back on the index, the
  checkout off the tag, either stale default restored, the published file unchecked, a
  margin where there is one resolver, the build check no longer running on pull requests,
  the Dockerfile defaulting to `pypi`, the local branch compiling dependencies, and the
  licence label back to singular.

- **`release.sh` runs the suite after the bump, and refuses before committing.**
  The version is written as the script's first act, so a suite run *before* a
  release cannot see what the bump breaks. Twice — apkradar 2026.42 on 2026-10-03
  and 2026.43 on 2026-10-04 — `test_the_readme_states_the_version_it_was_captured_with`
  failed in CI, on `main`, with the tag already pushed, and was fixed by hand after
  the fact.

  The gate sits between writing the version and committing it, not after: a refusal
  then leaves the version file modified and nothing else touched, which is what
  somebody needs to see, and `git checkout` undoes it. A gate after the commit would
  have to undo a commit, and undoing is worse than not doing. A repository with no
  `tests/` is not held up by a suite it does not have.

  Three cases hold it, and the first was checked against the script without the gate:
  a failing suite stops the release with nothing committed, tagged or pushed; a
  passing one lets it through; and no `tests/` is not a failure.


## [2026.43] - 2026-10-04

### Changed

- **`release.sh` is cookieradar's, which is the one with tests.** This script had
  none, and that is why `git tag ${TAG}` with no message survived in it until it
  stopped the 2026.42 release on 2026-10-03: where `tag.gpgsign` is true a bare
  `git tag` is a signed tag, and a signed tag needs a message. cookieradar's suite
  would have caught it — it asserts `git cat-file -t <tag>` is `tag`, and a bare tag
  is lightweight, which resolves to `commit`.

  Porting those tests failed fourteen times and was right to. This script was 49
  lines against cookieradar's 88, and what it did not do is the point: **no CalVer
  validation at all** — its own usage line suggested `2026.09.4`, the month scheme
  abandoned on 2026-09-29, which under PEP 440 sorts *below* `2026.10`, and the
  script would have released it. No check of tags already on the remote, none of the
  branch, none that local main matches `origin/main`, and no refusal when the version
  asked for is the one already current.

  Two tests are new. The tag's message is asserted, not only that it is annotated.
  And a tag that cannot be made must leave the remote untouched — signing on with a
  signing program that does not exist, so `git tag -a` fails exactly where it failed
  in the incident. That one is the half that did the damage: main was pushed *before*
  the tag, so the bump reached the remote and the tag never did, leaving a version
  nothing pointed at and no workflow reacting, since they trigger on the tag. The tag
  is now made before anything is pushed and the push is atomic.

  Checked against the old order rather than assumed: three of the twenty-one fail.

## [2026.42] - 2026-10-03

### Removed

- **`CVE-2026-84782` out of `SECURITY-EXCEPTIONS.toml`; `CVE-2026-82560` kept on
  purpose.** The openssl entry was never an acceptance — it said so — but a
  rebuild: `patchradar debian CVE-2026-84782` reports it resolved in trixie at
  `3.5.7-1~deb13u3`, and the Dockerfile's `apt-get upgrade` picks that up at the
  next build. GitHub closed the alert at **2026-09-30T17:22:37Z**, this
  repository's republish, so the rebuild happened and the entry goes. Its return
  would mean the upgrade stopped taking, which is worth a build failing over.

  `CVE-2026-82560` is the counter-case and stays, which is not about how long it
  has been quiet — it has been quiet longer. Docker Scout stopped reporting it at
  2026-09-29T15:27:49Z, earlier and on its own, with nothing done to the image in
  between, while `patchradar debian CVE-2026-82560` on 2026-10-02 still reports
  perl no-dsa in trixie at `5.40.1-6+deb13u1`, no fix in any suite, Debian bug
  1148455. perl-base is still installed and still unfixed; only the reporting
  changed, and Scout has already changed its mind about this exact id once —
  which is why the gate reads closed alerts at all. The entry now says that.

  Checked by running `tools/security_exceptions.py` against this repository's live
  open and closed alerts rather than by inference: exit 0, with `CVE-2026-82560`
  the one settled entry it names. The same decision was taken in exeradar the same
  day, which is where the rule came from.

### Added

- **The hosts an APK carries in its code.** The domain list came from the package
  name, the Google Play listing and the manifest's deep links — none of which is
  where an application keeps the servers it talks to. Those are string literals in
  the DEX, and R8 leaves them alone: it renames classes and methods, so a release
  build says nothing about its dependencies, but the URLs survive verbatim.

  Auditing Breezy Weather 6.2.2 on 2026-10-02 is what prompted it. The manifest
  declared one deep link and the package name guessed one domain, while the DEX
  held 161 hosts — AccuWeather, NOAA, JMA, Baidu and Xiaomi among them. The report
  said "no extra-EU transfers", and it was right to: that check reads SDK
  packages, and a weather service reached over plain HTTP ships no SDK. The two
  builds of that release differ by this finding and by nothing else the tool
  measures — `standard` carries five hosts belonging to vendors APKRadar reports
  on, `freenet` carries none, and both score 80/100.

  `apkradar.hosts` reads the same DEX files the tracker search reads, in chunks so
  a large one never lands in memory whole, and `ScanResult` gains `dex_hosts` plus
  `dex_endpoints`, `dex_references` and `dex_vendor_hosts`.

  Three decisions hold the finding to what it can support:

  - **It changes no score.** A host in a literal is a host the code *can* reach,
    which is not traffic: an app offering fifty providers carries fifty endpoints
    and contacts the one configured, so a point per host would penalise choice.
    The report says "carried in the DEX — reachable by the code, not observed in
    traffic", and a test asserts the score is untouched by three endpoints
    including Xiaomi's.
  - **The hosts are not added to `get_all_domains`.** `--full` would otherwise run
    MailRadar, an SSL check and CookieRadar on 153 domains the app may never
    contact. A test pins that too, so it stays a decision rather than becoming a
    drift.
  - **Specification URIs are labelled, not dropped.** `www.w3.org` and
    `www.opengis.net` arrive as XML namespaces, which nothing dereferences. The
    reference set is a short one of standards bodies, licences and schemas;
    anything arguable stays an endpoint, because silently reclassifying an
    endpoint as documentation hides what the feature exists to show.

  Two ways of inventing a hostname are closed off, and they are the same mistake
  twice. A URL cut by a chunk boundary would yield its own prefix — `api.exam` out
  of `api.example.com`, which passes every DNS rule there is — so a match touching
  the end of a buffer is deferred to the next one, the last chunk's tail being read
  as final so nothing at the end of a DEX is lost. The host pattern also stops at
  the 253-character DNS limit, so a longer string left the regex holding a
  truncation of it, and a truncation that ends at a dot is a well-formed hostname
  that never existed: a match whose next byte could still belong to the host is
  refused. The second case was found by the test written for the first.

  Format strings (`https://%s/`), templates, single labels, IPv4 literals and
  malformed labels are refused; hosts are lowercased, deduplicated and sorted; the
  list stops at 500 and reports that it did.

- **The gate reads FIRST's forecast on the CVEs it already holds.** EPSS is indexed
  by CVE, and `SECURITY-EXCEPTIONS.toml` is the one surface in this repository that
  holds CVE ids: Docker Scout names its alerts by CVE, so every accepted finding
  already has an id, a written reason and a review date. The forecast is what those
  records lacked — "no fix in any suite" accepted until December is comfortable at
  an EPSS of 0.1% and is something else at 40%.

  The forecast changes no verdict. The gate fails on a blocking alert with no entry
  and on an entry past its date, and on nothing else: `exit_code` takes the
  forecasts and ignores them, so the signature says they were available and did not
  decide anything. Only ids that *are* CVE ids are looked up —
  `SNYK-DEBIAN13-GCC14-20386241` is CVE-2026-95619 and says so in its description,
  and reading prose is guessing. A CVE FIRST does not score prints "not scored by
  FIRST" rather than 0.0%, which is a real reading at the floor of the scale; FIRST
  unreachable prints nothing and the report is the one this script produced before.

  The accepted findings are listed on a **passing** run, worst first, because that
  is where somebody decides whether to renew a review date and nothing else prompts
  it.

  Ported from patchradar with its nineteen tests; `tools/security_exceptions.py` is
  shared by copy across the five, and all four copies were byte-identical before
  this.

- **The letter can carry its distribution terms: `apkradar send --tlp amber`.**
  The document goes to a company and describes an unpublished audit of its
  application; whether the recipient may forward it is the sender's decision, and
  until now there was no way to express one. TLP 2.0 is FIRST's standard for
  exactly that — the same body behind EPSS and the team directory — so
  `apkradar/tlp.py` is part of treating FIRST as a source these tools cite rather
  than consume.

  The label goes in two places, as FIRST's guidance for email asks: in front of
  the subject line, so it is read before the message is opened, and in a block at
  the top of the body saying what the recipient may do. The label is never
  translated — the letter is Italian and `TLP:AMBER+STRICT` stays as the standard
  writes it, because a recipient's mail rules match on the token — while the
  permission underneath it is in the language of the document.

  Four rules, and only the first is about spelling:

  - **`TLP:WHITE` is refused, not quietly mapped.** TLP 2.0 renamed WHITE to
    CLEAR in 2022; accepting it would put a label on a document that the current
    standard does not define. The refusal names the replacement, and it happens
    before the APK is opened — a typo is answerable without doing the work.
  - **AMBER and AMBER+STRICT say different things.** AMBER permits sharing with
    the recipient's clients, AMBER+STRICT stops at the organisation. They are the
    pair people conflate, and that difference is why +STRICT exists.
  - **An unmarked letter is unmarked, not CLEAR.** No `--tlp` means the sender
    said nothing about redistribution, and reading silence as unlimited permission
    would be the same mistake as reading an empty result list as "nothing is
    there". Verified by mutation: making `parse_optional(None)` return CLEAR fails
    three tests, two of them about the letter rather than the parser.
  - **The standard is cited with its version.** A label without one is a word:
    WHITE meant something in TLP 1.0 and AMBER+STRICT did not exist. The block
    names TLP 2.0 and links first.org, so the letter still reads correctly in five
    years.

  Forty-three tests, written before the code.

### Fixed

- **Mutation testing runs again: `also_copy` in `[tool.mutmut]`.** The Saturday
  run died in all five Radar on 2026-10-03, before a single mutant was tried, and
  the cause was the same one each time with a different victim — here, `tests/test_exceptions_epss.py` could not import `security_exceptions` from `tools/`.

  mutmut copies `source_paths` into `mutants/` and runs the suite from there,
  adding only `tests/`, `test/`, `setup.cfg`, `pyproject.toml` and `uv.lock` of its
  own accord. So every test that imports from `tools/` or `scripts/`, or reads a
  file at the repository root, found nothing — and since the stats phase runs the
  suite rather than merely collecting it, one such test killed the whole run.

  The list was verified rather than guessed. mutmut 3.8 refuses to run on Windows,
  so the `mutants/` tree was rebuilt by hand from mutmut's own copy rules —
  `configuration.py:184` and `utils/file_utils.py:66` — and the suite run inside it
  until it passed: **908 passed, 2 skipped, 52 subtests**.

  This is *not* the previous day's move to `ubuntu-26.04`: the failures are
  Python-level, inside a copied tree, and patchradar's instance dates from
  2026-09-26. The weekly cron is only what surfaced them all at once — the first
  firing since the tests that trip it were written.

- **The image Snyk scans has a fixed tag, so code scanning keeps one
  configuration for it.** It was built as `snyk-scan:${GITHUB_SHA}`, and Snyk
  Container writes its own automation id into the SARIF from the image reference it
  scanned — overriding the `category:` given to `upload-sarif`. So every commit
  minted a new code-scanning configuration that nothing could ever find again, and a
  pull request was told *"configurations present on refs/heads/main were not
  found"* and could no longer be shown which alerts it had introduced.

  Measured on 2026-10-02: apkradar had reached **32** such configurations and pull
  request #16 could not be diffed. The other four showed one each — the tag is
  identical in all five, and the difference is only that apkradar's image carries
  an extra target (`/usr/share/ca-certificates-java/1`) that Snyk reports under the
  image reference. The fix therefore goes in all five: the defect is there whether
  or not it has surfaced.

  The 32 already recorded stay listed until the stale configurations are deleted,
  which is a deletion of code-scanning data and not done here.

- **The gcc advisories are recorded, under each scanner's id.** CVE-2026-102010
  and CVE-2026-95619 reached this image on 2026-10-02. Snyk and Docker Scout give
  one flaw two ids and the gate matches by id, so one flaw needs two entries —
  zlib has been in that position since September. Both positions were read with
  `patchradar debian`: open in trixie for gcc-12 and gcc-14, no fix in any suite,
  no Debian bug.

  They were not written earlier in the day, when the same survey showed this
  repository with nothing missing: an entry that matches no alert fails the gate
  too, deliberately, so the record follows the scanners instead of anticipating
  them.

  `tests/docker/inspect.sh` now prints the gcc, g++, cpp, libgcc and libstdc++
  packages. The entries say libstdc++6 is what is installed and not the compiler,
  and that sentence had been asserted and never measured; a flaw in cc1 needs
  something to compile, and nothing in this image compiles anything.

- **A test was pinning Rich's output stream for every test that ran after it.**
  `test_the_console_is_flushed_even_when_the_body_raises` saved `cli.console.file`
  and assigned it back, which looks like a restore and is not: Rich's `file` is a
  property that falls back to `sys.stdout` when nothing was set, so writing the
  current value into it fixes that stream for good. Measured here on 2026-09-30:
  with the two files named explicitly in that order,
  `tests/test_hash_is_verifiable.py` asserted against an empty `result.output` —
  the whole report had gone to the terminal instead of the CliRunner's buffer. The
  suite was green only because of the order the files are collected in. The test
  builds a console of its own now and monkeypatches it in.

- **"App not found on Google Play" was three different answers.** `lookup()`
  wrapped the whole query in one `except Exception` and returned
  `available=False` for all of them: the store having no such listing, the store
  not answering at all — a timeout, a 429, a page that changed shape — and
  google-play-scraper not being installed. It then searched the web for
  "&lt;package&gt; removed banned Google Play Store" and printed the abstract as
  `removal_reason`, so a working app behind a slow connection could be reported
  as taken down, with a reason.

  `status` now says which of the three happened — `listed`, `not_listed`,
  `unknown` — the web abstract is fetched only when the store did answer "no",
  and it is printed as what it is: an unverified hint, from a search that will
  answer with a namesake or with Play policy in general if it has nothing better.
  `available` stays, as a property meaning `status == listed`.

  The store that answered is part of the answer, too.
  `google_play_scraper.app` defaults to `country="us", lang="en"`, which nothing
  said out loud, so an app published for Europe only answered "not found" from a
  shop it had never been in. The defaults are unchanged and now recorded in every
  result and printed with it, and `apkradar search --country it --lang it` asks
  another store.

  Measured rather than asserted: of the 147 rows in the app repository of
  2026-09-29, 21 were recorded as absent from Play, and all 21 are absent from the
  Italian store as well as the American one — every one of them the store
  answering `App not found(404).` rather than failing. So on that corpus the
  hidden locale changed nothing and the collapse hid nothing. The distinction is
  made because the code could not have told the difference if it were there, which
  is a different claim from having caught it doing so.

- **Reading the advertising ID is no longer reported as serving advertising.**
  `com.google.android.gms.ads.identifier.AdvertisingIdClient` is the call that
  reads the advertising ID. It ships in play-services-ads-identifier, which
  arrives with measurement, analytics, basement and a long list of libraries that
  have nothing to do with advertising — so the DEX search for
  `Lcom/google/android/gms/ads/` found it in applications that had never
  displayed an advertisement.

  The signature table had one entry for that whole prefix, named "Google Ads",
  and `SDK_DOMAINS` hung `googleadservices.com` and `doubleclick.net` on it. Those
  domains are audited and then named in the letter sent to the publisher, so the
  outcome was a written allegation that the app talks to DoubleClick, drawn from
  evidence that it can read an identifier. Understating a report is one kind of
  mistake; putting a false statement about somebody's traffic in a signed letter
  is another.

  `scanner.SIGNATURE_EXCEPTIONS` now narrows a signature against sub-packages
  that mean something else, in the manifest and in the DEX alike, and the
  identifier is reported under its own name — "Google advertising ID
  (AdvertisingIdClient)". The finding itself was never in doubt and keeps its
  place: the `AD_ID` permission is in `SENSITIVE_PERMISSIONS`, and an online
  identifier is what art. 4(1) and recital 30 are about. AdMob is still detected,
  from any of its hundreds of classes that are not under `ads/identifier/`.

  `extract_sdk_domains` also matched with `prefix in package`, a substring test
  on a package name, which is how `com.appsflyerish.sdk` would have collected
  AppsFlyer's domain. It is segment-aware now, the same rule the scanner uses.
  Eleven tests, including one that walks a class descriptor across the read
  boundary at forty-eight offsets: the word that says "identifier" is exactly the
  part that a short overlap would have cut off.

- **GDPR art. 9 is no longer cited for permissions that are not special
  categories.** Every one of the twenty-eight entries in
  `SENSITIVE_PERMISSIONS` was mapped to art. 9 — storage read, calendar, device
  accounts, the advertising identifier — and that citation went into the letter
  addressed to a data protection officer, in the heading of section 2:
  "PERMESSI SENSIBILI — art. 5(1)(c), 9 GDPR".

  Art. 9(1) is an exhaustive list: racial or ethnic origin, political opinions,
  religious or philosophical beliefs, trade union membership, genetic data,
  biometric data processed *for the purpose of uniquely identifying* a natural
  person, health, sex life and sexual orientation. A letter that cites it for a
  storage permission gives its reader something to dismiss in one line, ahead of
  the findings that hold — the trackers, the extra-EU transfers, the
  undisclosed permissions.

  Two of them were worth naming in the code, because they look like art. 9 and
  are not. **Location** can *reveal* a special category by inference, which is a
  property of a purpose and a pattern rather than of the permission, and this
  audit reads a manifest. **An on-device biometric unlock** — `USE_BIOMETRIC`,
  `USE_FINGERPRINT` — asks Android to authenticate: the matching happens in the
  operating system, the template never leaves the secure hardware, and the app
  receives a boolean, so there is no biometric data being processed to identify
  anybody.

  What is left is health data: `BODY_SENSORS`, `ACTIVITY_RECOGNITION`, and Health
  Connect records matched by their `android.permission.health.` prefix so that
  adding one later cannot quietly inherit the old behaviour. Sensitive
  permissions now cite art. 5(1)(c) and art. 6, which apply to all of them, and
  art. 9 appears as a separate finding — phrased as a question about the purpose,
  with the condition named, because the purpose is exactly what a manifest does
  not state.

  `BODY_SENSORS` was also described as "biometric sensors", which is what it
  reads like and not what it gives; it now says "vital signs (heart rate)". Ten
  tests were added, including one that reads the whole permission table and
  asserts which entries may cite art. 9.

- **The Docker build no longer races its own publish.** `docker.yml` and
  `publish.yml` both fire on the tag push, in parallel, and the Dockerfile
  installs `apkradar==<new version>` from PyPI. A fixed `sleep 60` stood in for
  the wait and lost that race twice: 2026.9.32 on 2026-09-24, two failures, and
  v2026.41 on 2026-09-30, one at `Dockerfile:24`.

  Both were reported as `No matching distribution found for apkradar==<version>`,
  listing versions up to the *previous* release — which reads as a failed
  publish, while PyPI already held the files and only the index had not caught
  up. Re-running the job alone was enough both times, and establishing that cost
  a detour on each occasion.

  `.github/scripts/wait_for_pypi.sh` now polls with pip itself, which is what the
  Dockerfile uses and what the index answers for, for up to ten minutes. It runs
  *after* the version is extracted rather than before, because the tag is
  `v2026.41` while the distribution is `2026.41` and `==v2026.41` is not a
  version pip can ever find — where the `sleep` sat, there was nothing to wait
  for by name. Ported from cookieradar, which has polled since 2026-09-24, with
  its tests: `tests/test_ci_scripts.py` drives the script with a fake pip and
  pins where the step sits, what version it is given, and that nothing in the
  workflow waits by sleeping again.

### Changed

- **The CI runners are pinned to `ubuntu-26.04`, and the benchmarks job is pinned
  to `ubuntu-24.04` because CodSpeed cannot run on 26.04.** `ubuntu-latest` was
  Ubuntu 24.04 — read off a live run on 2026-10-02, image `ubuntu24/20260927.320` —
  and GitHub moves that label on its own schedule, so the choice was between finding
  out what breaks on a branch or finding out later on `main` at a moment nobody
  picked.

  Something did break, which is the whole value of having asked: `CodSpeedHQ/action`
  v5 fails on 26.04 with `##[error]Unsupported system`. `mode: simulation` was
  already set and the action was pinned, so it is the image and nothing else. Every
  one of the five Radar runs CodSpeed, so every one of them would have broken the
  same way the day the label moved by itself.

  That job is pinned to **24.04 rather than left on `ubuntu-latest`**: left there it
  keeps working right up to the day the label moves and then fails on `main`. 24.04
  is supported until April 2029, and a comment beside it says to try 26.04 again now
  and then, because nothing here will notice when CodSpeed adds support.

  The risk surface was measured before anything changed — no `apt-get` and no `sudo`
  in any workflow, Python from `actions/setup-python` at explicit versions, no
  `container:` or `services:` jobs — and the Docker path was checked on its own by
  dispatching `docker-build-check.yml` against the branch, which succeeded on image
  `ubuntu26/20260927.149`.

  What pinning costs: nothing bumps it for you. Dependabot updates action versions,
  not `runs-on`.

- **ruff now lints `tools/` as well, because it never did.** Every one of the five
  Radar lints its package and its tests and stops there, which left
  `tools/security_exceptions.py` outside the check — the script that refuses a build
  over an unexplained alert had never been seen by the linter that gates the build.
  Found on 2026-10-02 by running ruff over the whole tree by hand while working on
  something else, which is not a way of finding things that scales.

- **The Italian comments are in English**, in `tests/test_shutdown_flush.py` — the
  subprocess script included — and `tests/test_hash_is_verifiable.py`.

## [2026.41] - 2026-09-29

### Fixed

- **The report no longer ends with a traceback.** Rich wraps `sys.stdout` in a
  `FileProxy` while a spinner runs and restores the stream without flushing it, so
  a partial line sat in that buffer until the proxy was garbage-collected — often
  during interpreter shutdown, where the message is
  `ImportError: sys.meta_path is None`. It appeared after a completed analysis, on
  a terminal only, and looked like the software failing at the worst possible
  moment. Every spinner now flushes both streams before it stops.

- **The SHA256 is shown whole, or it cannot be verified.** The digest was
  truncated in both the terminal report and the Excel export, including under
  `--full`. A hash that cannot be compared against another copy of the file is
  decoration: whoever reads an APK's digest is reading it in order to check it.
  The Excel column widens to 70 when a value reaches 64 characters.

- **Each domain is analysed once.** Two loops over the full-stack domains meant a
  domain could be reported twice in the same audit, which reads as two findings
  where there is one.

- **The publisher's domain is probed over https first.** `looks_parked` requested
  `http://domain` in cleartext, and the body of that response decides whether a
  report says a publisher's domain is for sale — on that path anyone can insert a
  for-sale marker. https first, http only after it fails: a real site is never
  asked over cleartext, and a parked domain with no certificate for its own name
  is still found, which is what the fallback is for. Measured against nine real
  domains on 2026-09-29: no verdict changed, and python.org, example.com and
  maksimtech.com moved to https with the same answer.

### Added

- **A CI gate that refuses.** Every other security workflow reports: `snyk.yml`
  carries `continue-on-error`, CodeQL and Docker Scout upload SARIF, and
  SonarCloud decides its quality gate after the job has already succeeded. On
  2026-09-29 all of them were green while twelve high-severity alerts were open.
  `security-posture.yml` reads what they published and fails when a blocking
  finding has nobody's name against it; `SECURITY-EXCEPTIONS.toml` records the
  accepted ones, each with a reason and a review date. `sonarcloud.yml` now waits
  for its own quality gate, without which a red gate is a green job.

### Changed

- The prose is in English throughout. The DPO letter and the quoted law stay in
  Italian, because that is the language they are read in.

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

[Unreleased]: https://github.com/maksimtech/apkradar/compare/v2026.44.1...HEAD
[2026.44.1]: https://github.com/maksimtech/apkradar/compare/v2026.44...v2026.44.1
[2026.44]: https://github.com/maksimtech/apkradar/compare/v2026.43...v2026.44
[2026.43]: https://github.com/maksimtech/apkradar/compare/v2026.42...v2026.43
[2026.42]: https://github.com/maksimtech/apkradar/compare/v2026.41...v2026.42
[2026.41]: https://github.com/maksimtech/apkradar/compare/v2026.40...v2026.41
[2026.40]: https://github.com/maksimtech/apkradar/compare/v2026.09.32...v2026.40
[2026.09.32]: https://github.com/maksimtech/apkradar/compare/v2026.09.31...v2026.09.32
[2026.09.31]: https://github.com/maksimtech/apkradar/compare/v2026.09.30...v2026.09.31
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
