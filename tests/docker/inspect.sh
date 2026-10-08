#!/bin/sh
# What the image actually contains, printed rather than taken from a scanner.
#
# This exists because Docker Desktop cannot be installed on the machine this is
# developed on — Windows 10 IoT Enterprise LTSC 2021 is build 19044 and Docker
# requires 19045, a build that edition never receives. The image can therefore
# only be examined from inside a CI job, which is a better place for it anyway: a
# Linux runner is what the image actually runs on.
#
# Two questions, both of which SECURITY-EXCEPTIONS.toml currently answers on
# evidence borrowed from patchradar rather than measured here.
#
# 1. Which perl is installed? The record says only `perl-base` — Essential, which
#    dpkg itself depends on — and cites a measurement taken inside patchradar's
#    image. Docker Scout names the *source* package for CVE-2026-82560, and
#    Debian's `perl` source produces both `perl-base` and the removable `perl`.
#    Which one is here decides whether that finding is ours to close or only ours
#    to record.
#
# 2. Is the build tooling still here? Unlike patchradar, exeradar and mailradar,
#    this Dockerfile does not remove pip, setuptools and wheel — so the copies
#    vendored inside them are in the published image, at a path no pin can reach.
#    Docker Scout does not report them against this repository today, which makes
#    it a latent exposure and not a finding. The version printed below is what a
#    decision about it should rest on, and removing them needs the smoke test to
#    still pass, which is why this runs beside it and not instead of it.
#
# Run by .github/workflows/docker-build-check.yml, which builds and publishes
# nothing:
#     docker run --rm -i --entrypoint sh apkradar:build-check - < inspect.sh
#
# It reports and does not judge — a red step here would be a broken diagnostic, and
# what matters is whether the numbers and the record agree — with one exception, at
# the end: the Dockerfile installs no system package, and that is checked in the
# image rather than only in the file, because the one time it did install something
# the cost was a Security Posture nobody could close.
set -eu

echo "── perl packages installed ──"
# Only the versioned lines are real installs. `perl`, `perl-modules` and the
# `perlapi-*` entries come back with no version when they are virtual packages
# that perl-base provides.
dpkg-query -W -f '  ${Package} ${Version} essential=${Essential} priority=${Priority}\n' \
    'perl*' 'libperl*' 2>/dev/null || echo "  none"

echo
echo "── the other packages the record names ──"
# Patterns, not exact names: Debian trixie's 64-bit time_t transition renamed a
# number of libraries with a `t64` suffix, and an exact name that no longer exists
# comes back looking like "not installed" rather than "I asked the wrong question".
# That happened once, on cookieradar's libcups2, on 2026-09-30.
for pattern in 'zlib1g*' 'libattr1*' 'libacl1*'; do
    found=$(dpkg-query -W -f '  ${Package} ${Version} priority=${Priority}\n' "$pattern" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "$found"
    else
        echo "  $pattern matched nothing installed"
    fi
done

echo
echo "── build tooling: present here, unlike three of the five Radar ──"
for pkg in pip setuptools wheel; do
    if version=$(python -c "import importlib.metadata as m, sys; sys.stdout.write(m.version('$pkg'))" 2>/dev/null); then
        echo "  $pkg $version is in the published image"
    else
        echo "  $pkg absent"
    fi
done

echo
echo "── anything left under pip/_vendor ──"
find / -path '*/pip/_vendor*' -name 'bom.cdx.json' 2>/dev/null | sed 's/^/  /' || true
echo "  (nothing above means the path Scout reports on other Radar is not here)"

echo
echo "── the C++ toolchain, or only its runtime ──"
# Snyk reports CVE-2026-102010 and CVE-2026-95619 against the *source* package
# gcc-14, and Debian's gcc source produces both the compiler and libstdc++6. Those
# are not the same exposure: a flaw in cc1 needs something to compile, and nothing
# in this image compiles anything. SECURITY-EXCEPTIONS.toml says libstdc++6 is what
# is installed; this is the measurement behind that sentence.
dpkg-query -W -f '  ${Package} ${Version} priority=${Priority}\n' \
    'libstdc++*' 'gcc*' 'g++*' 'cpp*' 'libgcc*' 2>/dev/null \
    || echo "  no gcc or libstdc++ package installed"

echo
echo "── size of the installed set ──"
printf '  %s packages\n' "$(dpkg-query -f '.\n' -W | wc -l)"

echo
echo "── nothing installed beyond the base image ──"
# tests/test_docker_contract.py reads the Dockerfile; this reads the image, which is
# what Docker Scout reads. `gnupg` and `default-jre-headless` were installed here from
# the first commit and nothing in apkradar ran either: androguard is pure Python, the
# DPO letter goes out over SMTP, `mailradar.checker` looks GPG keys up over HTTP and
# `cookieradar.scanner` runs no Java. The `gpg` binary is run by `mailradar.sender`,
# which apkradar never imports. What `gnupg` did bring was dirmngr → libldap2 →
# libsasl2-2, and CVE-2026-107161 in cyrus-sasl2 has no fix in trixie — an alert that
# could only be closed by not installing what carried it. libsasl2-2 is listed first
# because it is the package Scout named, and the two after it are the ones that were
# asked for.
#
# `dpkg -s` has to fail, and the two binaries have to be absent from PATH: the
# question is not "is the package record gone" but "can anything here run it".
failed=0
for pkg in libsasl2-2 gnupg default-jre-headless; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "  FAIL: $pkg is installed ($(dpkg-query -W -f '${Version}' "$pkg"))"
        failed=1
    else
        echo "  ok: $pkg is not installed"
    fi
done
for bin in gpg java; do
    if found=$(command -v "$bin" 2>/dev/null); then
        echo "  FAIL: $bin is on PATH at $found"
        failed=1
    else
        echo "  ok: no $bin on PATH"
    fi
done
if [ "$failed" -ne 0 ]; then
    echo "  the image installs something the Dockerfile says it does not" >&2
    exit 1
fi
