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
