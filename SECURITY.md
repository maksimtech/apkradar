# Security Policy

## Reporting a vulnerability

Write to <security@maksimtech.com>; the GPG key for that address is on
keys.openpgp.org. Please do not open a public issue for a vulnerability.

APKRadar has a single maintainer, Massimo Moretti, who reads that address.

## Supported versions

Only the latest release receives fixes. Versions follow CalVer (`YYYY.count[.fix]`):
a fix ships as the next release, never as a patch to an older one.

## How vulnerabilities are found

- **CodeQL, Bandit and Trivy** (repository files) run on every pull request, on
  every push to `main` and weekly.
- **Snyk** checks the code, the dependencies and an image built from the
  Dockerfile on every pull request and push to `main`, when the Snyk token is
  available to the run. Of its findings, only a high or critical dependency issue
  that the pull request adds, and `main` does not have, fails the job; the code and
  image findings are published to GitHub code scanning.
- **Docker Scout** checks the published `latest` image on every push to `main`,
  weekly and on demand. The image is built on `python:3.12-slim-trixie` (Debian
  Trixie) when a release is cut, with `apt-get upgrade` run at build time; it is
  not rebuilt on a schedule, so Debian's security patches reach it with the next
  release.
- **Dependabot** alerts and security updates are enabled for this repository, and
  `.github/dependabot.yml` asks for version updates of the Python dependencies and
  of the GitHub Actions weekly.
- **Security Posture** reads the alerts CodeQL, Bandit, Trivy, Snyk and Docker Scout
  publish to GitHub code scanning and fails when a high or critical finding has no
  reasoned exception in `SECURITY-EXCEPTIONS.toml`. It also runs weekly, because an
  exception expires by date and not by commit.
- Reports sent to the address above.

## Response times

- A fix ships with the next release. Releases can be up to a month apart.
- For a vulnerability with a CVSS score of 9.0 or more, customers who have given a
  security contact are told within 48 hours of the report being taken in charge,
  even if the fix is not ready yet.
- A vulnerability that is accepted rather than fixed is recorded in
  `SECURITY-EXCEPTIONS.toml` with the reason and a review date; Security Posture
  fails once the review date has passed.

## Customer notification

Every fix is described in the release notes on GitHub, which are the CHANGELOG
section of that version. For a vulnerability with a CVSS score of 9.0 or more,
customers who have given a security contact also get a direct email.

## Rollback

Every version stays installable and pinnable:

- PyPI: `pip install apkradar==<version>`;
- Docker Hub: `maksimtech/apkradar:v<version>`, and the SHA256 digest of that image.
  The tag is pushed when the release is cut. A manual rebuild of a release
  (`docker.yml`, started by hand) pushes the same tag again over a new image, so
  pin the digest when the exact image matters: a digest cannot change.

Rolling back means pinning the previous version or digest. Releases are cut with
`release.sh`.

## What the tool sends, and to whom

APKRadar contacts third parties: Google Play and, when Play has no listing,
DuckDuckGo, with the package name; the EU and Italian law sources it cites; and,
with `--full`, the domains of the publisher and of the SDKs it finds. `send` mails
a letter about the app through the SMTP server you name. Every host, what each one
receives and which command reaches it are listed in
[docs/nis2-compliance.md](docs/nis2-compliance.md), section 3.

## Evidence attached to every release

Each GitHub release carries CycloneDX SBOMs of the image and of the Python
environment, and dated Trivy reports of the image and of the repository at the
tag. The Trivy reports are an automated scan for known vulnerabilities, not a
penetration test; no penetration test has been carried out. What these files are,
and the answers to the questions a customer subject to NIS2 may ask, are in
[docs/nis2-compliance.md](docs/nis2-compliance.md).

Last reviewed: 2026-10-11
