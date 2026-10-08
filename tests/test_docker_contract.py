"""What the image is allowed to install, and from where.

docker.yml pushes maksimtech/apkradar:latest to Docker Hub, and unlike exeradar and
cookieradar there is no smoke test between the build and the push — this job logs in,
builds and pushes. A bad `:latest` is what everyone pulling the image gets, so the parts
that are easy to get quietly wrong are pinned here rather than discovered by whoever
pulls it.

Static checks on the Dockerfile's text: they need no Docker daemon, which is the point,
because the machine this was written on does not have one. What they cannot tell you is
whether the image builds — docker-build-check.yml does that, on every push and pull
request as of the change these cases came with.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"


def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_the_source_can_be_either_the_checkout_or_the_index():
    """Two branches, because the release wants this tag's code and somebody
    reproducing an old image wants what was published then."""
    text = dockerfile()

    assert "APKRADAR_SOURCE" in text
    assert "local)" in text and "pypi)" in text


def test_a_plain_build_uses_the_working_tree():
    """`docker build .` has to say something about the code in front of whoever ran
    it. With a PyPI default it said 2026.9.1 for ever, and it did: that was the default
    here while the project was at 2026.43."""
    assert re.search(r"ARG\s+APKRADAR_SOURCE=local", dockerfile())


def test_a_pypi_build_has_to_say_which_version():
    """The stale default is the trap, not the missing one. `ARG APKRADAR_VERSION=2026.9.1`
    meant a build with no arguments published August's code under today's tag, silently,
    because nothing about it looks wrong."""
    assert not re.search(r"ARG\s+APKRADAR_VERSION=\S", dockerfile()), (
        "a default version here rebuilds an old release by accident"
    )


def test_nothing_is_ever_built_from_source_while_building_this_image():
    """The image is built for linux/amd64 and linux/arm64. A dependency with no
    aarch64 wheel would be compiled under QEMU emulation, which in a release means
    tens of minutes or an out-of-memory, arriving as a surprise the first time some
    dependency stops shipping one.

    The local branch has to build this package's own wheel — it is a source tree —
    and then installs it under the same restriction, which is what leaves the
    dependencies subject to it.
    """
    text = dockerfile()
    installs = [line for line in text.splitlines() if "pip install" in line]
    assert installs, "nothing installs anything"

    for line in installs:
        if "/app/" in line or "apkradar==" in line:
            assert "--only-binary :all:" in line, line

    assert "pip wheel --no-deps" in text, (
        "the local branch has a source tree to build before it can install a wheel"
    )


def test_the_licence_label_is_the_one_the_standard_names():
    """`org.opencontainers.image.licenses` is the key, plural. The singular is read by
    nothing, so a tool asking an image what it is licensed under gets no answer — and
    the label looks right in the file either way, which is why it survived."""
    text = dockerfile()

    assert 'org.opencontainers.image.licenses="MIT"' in text
    assert "org.opencontainers.image.license=" not in text


def _run_instructions() -> list[str]:
    """Every RUN of the Dockerfile as one string, continuation lines joined."""
    joined: list[str] = []
    current: list[str] | None = None
    for raw in dockerfile().splitlines():
        line = raw.rstrip()
        if current is None:
            if not line.startswith("RUN "):
                continue
            current = [line[len("RUN "):].rstrip("\\").strip()]
        else:
            current.append(line.rstrip("\\").strip())
        if not line.endswith("\\"):
            joined.append(" ".join(current))
            current = None
    return joined


def _apt_packages_installed() -> list[str]:
    """What `apt-get install` is asked for, across every RUN: the words after it that
    are not flags, up to the next `&&`, `;` or `|`. Flags with a value in the next word
    (`-o Dpkg::...`, `-t suite`) are not used here, so a word is either a flag or a
    package."""
    packages: list[str] = []
    for instruction in _run_instructions():
        for match in re.finditer(r"apt-get\s+install\b(.*?)(?=&&|;|\||$)", instruction):
            packages.extend(word for word in match.group(1).split() if not word.startswith("-"))
    return packages


def test_the_image_installs_no_system_package():
    """The base image is enough. Nothing in apkradar runs a system binary: the APK is
    read by androguard, which is pure Python; the DPO letter is sent over SMTP by this
    package's own sender; and of the two other Radar it imports, `mailradar.checker`
    looks GPG keys up over HTTP through `mailradar.gpg` — the `gpg` binary is run by
    `mailradar.sender`, which apkradar never imports — and `cookieradar.scanner` runs
    no Java.

    `gnupg` and `default-jre-headless` sat here from the first commit, unused, and the
    first one cost a Security Posture: `gnupg` pulls in dirmngr → libldap2 → libsasl2-2,
    and CVE-2026-107161 in cyrus-sasl2 has no fix in trixie, so the alert could only be
    closed by not installing what carried it. A package that nothing runs is an
    exposure with no return, which is why this says "none" rather than "not these two".
    """
    assert _apt_packages_installed() == [], (
        "the Dockerfile installs system packages; nothing in the image executes one, "
        "so each is attack surface with no use — see the docstring"
    )


def test_the_base_image_packages_are_still_upgraded_at_build_time():
    """Installing nothing is not the same as leaving Debian's packages where the base
    image put them: SECURITY-EXCEPTIONS.toml rests on `apt-get upgrade` running at
    build time, so a fix Debian ships arrives at the next release without being
    chased."""
    apt_runs = [run for run in _run_instructions() if "apt-get" in run]
    assert len(apt_runs) == 1, apt_runs
    (run,) = apt_runs
    assert re.search(r"apt-get\s+update\s*&&\s*apt-get\s+upgrade\s+-y", run), run
    assert "rm -rf /var/lib/apt/lists/*" in run, "the package lists stay in the image otherwise"
