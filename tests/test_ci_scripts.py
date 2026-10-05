"""The wait that keeps the Docker build from racing its own publish.

`docker.yml` and `publish.yml` both fire on the tag push, in parallel, and the
Dockerfile installs `apkradar==<new version>` from PyPI. A fixed `sleep 60` stood
in for the wait and lost that race twice:

  2026-09-24  apkradar 2026.9.32 — two Docker failures
  2026-09-30  apkradar v2026.41  — one, at Dockerfile:24

Both were reported as `No matching distribution found for apkradar==<version>`,
listing versions up to the *previous* release. That reads like a failed publish,
and both times PyPI already held the files: what had not happened was the index
catching up. The detour to establish that cost more than the fix, which is why
the fix is here.

Two things had to be right, and the second is not obvious: the wait has to ask
pip, because pip is what the Dockerfile uses and what the index answers for; and
it has to run *after* the version is extracted, because the tag is `v2026.41` and
`apkradar==v2026.41` is not a version pip can ever find. The `sleep` sat before
that step, where it had nothing to wait for by name.

Ported from cookieradar, which has polled since 2026-09-24.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WAIT_FOR_PYPI = ROOT / ".github" / "scripts" / "wait_for_pypi.sh"
WORKFLOWS = ROOT / ".github" / "workflows"

PACKAGE = "apkradar"
# The step output that holds the pip version — 2026.41, not v2026.41.
PIP_VERSION_OUTPUT = "NORMALIZED"


@pytest.fixture
def fake_pip(tmp_path):
    """A `pip` on PATH that fails until the call count reaches SUCCEED_AT.

    The script is run for real, by bash, with the retry interval set to zero.
    What is faked is only the answer from the index.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    pip = bin_dir / "pip"
    pip.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{log}"\n'
        f'n=$(wc -l < "{log}")\n'
        '[ "$n" -ge "$SUCCEED_AT" ]\n',
        encoding="utf-8",
    )
    pip.chmod(0o755)

    def run(succeed_at, *args):
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "SUCCEED_AT": str(succeed_at)}
        proc = subprocess.run(
            ["bash", str(WAIT_FOR_PYPI), *args],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return proc, calls

    def start(succeed_at, *args):
        """The same script, left running, for the one case that is about *not* finishing."""
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               "SUCCEED_AT": str(succeed_at)}
        return subprocess.Popen(
            ["bash", str(WAIT_FOR_PYPI), *args],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    run.start = start
    return run


def test_it_asks_pip_for_the_exact_version_and_stops_on_the_first_answer(fake_pip):
    proc, calls = fake_pip(1, PACKAGE, "2026.41", "5", "0", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 1
    assert "download" in calls[0]
    assert "--no-deps" in calls[0]          # the package, not its dependency tree
    assert f"{PACKAGE}==2026.41" in calls[0]


def test_it_keeps_asking_until_the_index_has_caught_up(fake_pip):
    proc, calls = fake_pip(3, PACKAGE, "2026.41", "5", "0", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 3


def test_it_gives_up_and_says_so_rather_than_letting_the_build_start(fake_pip):
    """A version that never appears is a failure, not something to build around.

    The failure has to name the version: "still not available" with no subject is
    the kind of message that sent the last two investigations the wrong way.
    """
    proc, calls = fake_pip(99, PACKAGE, "2026.41", "4", "0")

    assert proc.returncode != 0
    assert len(calls) == 4
    assert f"{PACKAGE}==2026.41" in proc.stderr


def test_it_refuses_to_run_without_a_package_and_a_version(fake_pip):
    """Called wrong, it must not wait for nothing and then report success."""
    proc, calls = fake_pip(1)

    assert proc.returncode != 0
    assert calls == []
    assert "Usage" in proc.stderr


def test_it_allows_the_index_a_grace_once_the_version_is_there(fake_pip):
    """The margin is a wait that happens, not a line in the log.

    apkradar 2026.42 built fifteen seconds after this script reported the version
    available — 16:31:21 against 16:31:36 — because the runner and the buildx
    container resolve different edges of the index. A grace that is printed and not
    taken would leave that exactly as it was while looking fixed.
    """
    start = time.monotonic()
    proc, calls = fake_pip(1, PACKAGE, "2026.41", "5", "0", "2")
    elapsed = time.monotonic() - start

    assert proc.returncode == 0, proc.stderr
    assert elapsed >= 2, f"it reported a grace it did not take ({elapsed:.1f}s)"
    assert "agree with itself" in proc.stdout, "it waited without saying why"


def test_no_grace_waits_for_nothing_and_claims_nothing(fake_pip):
    """Zero has to mean zero, including in the log: a release that did not need the
    margin should not read as though it used one.

    Timed as a difference rather than against the clock. An absolute upper bound here
    read `< 2` and saw 21.4 seconds the first time five suites ran on one machine at
    once — measuring what the machine was doing rather than what the script was doing.
    The gap between a run that is given a grace and one that is not is the grace,
    whatever else is happening.
    """
    start = time.monotonic()
    proc, _ = fake_pip(1, PACKAGE, "2026.41", "5", "0", "0")
    without = time.monotonic() - start

    start = time.monotonic()
    waited, _ = fake_pip(1, PACKAGE, "2026.41", "5", "0", "3")
    with_grace = time.monotonic() - start

    assert proc.returncode == 0, proc.stderr
    assert waited.returncode == 0, waited.stderr
    assert "agree with itself" not in proc.stdout
    assert with_grace - without >= 2, (
        f"no grace took {without:.1f}s and a three second grace took "
        f"{with_grace:.1f}s, so the grace was not waited for"
    )


def test_the_default_grace_is_a_wait_and_not_zero(fake_pip):
    """Measured, without the suite paying the whole default for it.

    Started with no grace argument against an index that answers on the first ask,
    the script must still be running a few seconds later. Remove the default, or set
    it to zero, and it exits immediately and this fails — which is the point: every
    other case here passes a grace explicitly, so without this one the default could
    be deleted and nothing would notice.
    """
    proc = fake_pip.start(1, PACKAGE, "2026.41", "5", "0")
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=3)
    finally:
        proc.kill()
        proc.wait(timeout=10)


# ─── the workflow: where the wait sits, and what it is given ────────────────

yaml = pytest.importorskip("yaml")


def _workflow(name):
    wf = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    wf["on"] = wf.pop(True, wf.get("on"))     # PyYAML reads the `on` key as True
    return wf


def _docker_steps():
    return _workflow("docker.yml")["jobs"]["docker"]["steps"]


def _publish_steps():
    return _workflow("publish.yml")["jobs"]["build-and-publish"]["steps"]


def test_the_release_image_is_built_from_the_tag_and_not_from_the_index():
    """What closes the race instead of narrowing it.

    This job installed `apkradar==<the new version>` from PyPI while publish.yml was
    still uploading it, and polled the index first to make that work. The poll runs
    on the runner; the multi-platform build resolves the index again, per platform,
    from whichever edge answers. This repository is where that was measured: on
    2026-10-03 the build failed with "No matching distribution found" at 16:31:36,
    fifteen seconds after the poll reported the version available at 16:31:21.
    Nothing that waits can close it. Not asking does.
    """
    steps = _docker_steps()
    build = next(s for s in steps if "build-push-action" in s.get("uses", ""))
    args = build["with"]["build-args"]

    assert "APKRADAR_SOURCE=local" in args
    assert "APKRADAR_VERSION=" not in args, (
        "built from the checkout, there is no version to hand the image"
    )
    assert not [s for s in steps if "wait_for_pypi.sh" in s.get("run", "")], (
        "nothing here needs the index now, so nothing here should wait for it"
    )


def test_a_rebuild_checks_out_the_version_it_was_asked_for():
    """The trap that building from the checkout sets, and that the index did not.

    This workflow can be dispatched with the tag of an already published release.
    While the image installed that version from PyPI, where the job stood in the tree
    did not matter; built from the checkout it decides what ships. And unlike exeradar
    and cookieradar there is no smoke test between the build and the push here — this
    job logs in, builds and pushes — so a checkout left on the default branch would
    publish `main`'s code under an old release's tag rather than failing.
    """
    checkout = next(s for s in _docker_steps() if "actions/checkout" in s.get("uses", ""))

    assert "inputs.version" in checkout.get("with", {}).get("ref", "")


def test_the_dispatch_offers_no_stale_version_as_its_default():
    """`default: 'v2026.09.8'` sat in this workflow while the project was at 2026.43.

    A default that is a version is a version that rots, and the rot is invisible: the
    dispatch form arrives pre-filled with something that looks deliberate. Whoever
    rebuilds without reading it republishes August.
    """
    dispatch = _workflow("docker.yml")["on"]["workflow_dispatch"]
    version = dispatch["inputs"]["version"]

    assert "default" not in version, f"a default version rots: {version.get('default')!r}"


def test_the_image_is_built_before_a_release_and_not_only_during_one():
    """Otherwise the first attempt at building the image is the one that publishes it.

    docker.yml pushes to Docker Hub, `:latest` included, so running it *is* a release.
    docker-build-check.yml exists for that and was reachable by hand only — and it had
    to be, because it could not build anything without being handed a published
    version to install. Building from the checkout removes that, so it can run on
    every change like the suite does.
    """
    triggers = _workflow("docker-build-check.yml")["on"]

    assert "pull_request" in triggers, "a change that breaks the image should say so in its PR"
    assert "push" in triggers, "and on main, because that is what the next release builds"


def test_the_published_file_is_still_checked_where_it_was_published():
    """The old arrangement proved one thing by accident: that what lands on PyPI can
    be installed. Taking the image off the index would lose it, so the job that
    uploads says it on purpose — after the upload, where a slow index delays a check
    instead of failing a build."""
    steps = _publish_steps()
    names = [s.get("name", s.get("uses", "")) for s in steps]

    upload = next(i for i, s in enumerate(steps) if "gh-action-pypi-publish" in s.get("uses", ""))
    wait = next(i for i, s in enumerate(steps) if "wait_for_pypi.sh" in s.get("run", ""))
    verify = next(i for i, s in enumerate(steps) if "--version" in s.get("run", ""))

    assert upload < wait < verify, names
    assert "apkradar==" in steps[verify]["run"], "it has to be the version just uploaded"


def test_the_check_asks_for_no_margin_because_there_is_one_resolver():
    """The grace exists because the runner and the buildx container ask different
    edges of the index — measured here, on 2026-10-03. In publish.yml there is only
    the runner, which has just had `pip download` answer, so a margin would buy
    nothing, and a wait that buys nothing is what that script was rewritten to stop
    doing."""
    wait = next(s for s in _publish_steps() if "wait_for_pypi.sh" in s.get("run", ""))
    arguments = wait["run"].split("wait_for_pypi.sh", 1)[1].split()

    assert arguments[-1] == "0", wait["run"]


def test_nothing_in_the_docker_workflow_waits_by_sleeping():
    """The regression this file exists for.

    A fixed sleep is a guess about someone else's queue, and on a re-run it
    restarts from this job's own start rather than from the publish finishing.
    """
    for step in _docker_steps():
        assert "sleep" not in step.get("run", ""), step.get("name")
