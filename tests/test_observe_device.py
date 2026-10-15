"""Observing an app on a phone over adb: the run `observe` then reads.

`observe` reads a capture someone already took. `observe-device` takes it: it pulls the
app's APKs from the phone, has PCAPdroid capture the app's traffic, launches the app,
lets it run, takes a screenshot, stops the capture and brings the files back. Nothing
on the phone is tapped by APKRadar: PCAPdroid asks the operator to allow another app
to drive a capture, and the operator answers.

adb is a real program here too. tests/adb_fake.py answers each call with the output a
Motorola moto g17 (Android 15, PCAPdroid 1.9.1) gave on 2026-10-15 for that same call —
fixtures/adb_moto_g17_recorded.json, unedited — and logs it, so the tests read back
which commands ran and in which order. A call nobody recorded fails the test.

Two things the recording showed that the order tests below hold:
- a capture already running when the start request arrives keeps running, and the
  request is dropped: the file this run named never appears;
- three seconds after the stop request PCAPdroid was still capturing, and the file
  grew from 836,839 to 837,511 bytes once it had stopped.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from apkradar import device
from apkradar.cli import app
from tests import adb_fake
from tests.android_files import dex_blob, manifest, write_apk

FIXTURES = Path(__file__).parent / "fixtures"
RECORDED = json.loads((FIXTURES / "adb_moto_g17_recorded.json").read_text(encoding="utf-8"))["results"]
CAPTURE = FIXTURES / "pcapdroid_kids_app_first_launch_recorded.pcap"
PACKAGE = "com.gameitech.preschool.abc123.tracing.learning"
SERVICES = ["shell", "dumpsys", "activity", "services", "com.emanuelef.remote_capture"]

runner = CliRunner()


def answer(name: str, *, args: list[str] | None = None, file: Path | None = None) -> dict:
    """A recorded result, answering the call it was recorded for unless `args` says otherwise."""
    entry = {k: RECORDED[name][k] for k in ("args", "returncode", "stdout", "stderr")}
    if args is not None:
        entry["args"] = args
    if file is not None:
        entry["file"] = str(file)
    return entry


def instead(of: str, name: str) -> dict[str, list[dict]]:
    """The call recorded as `of`, answered as `name` was: a phone where that went otherwise."""
    return {of: [answer(name, args=RECORDED[of]["args"])]}


def services(*names: str) -> list[dict]:
    """PCAPdroid's services dump, call after call."""
    return [answer(n) for n in names]


def phone(tmp_path: Path, *, dumps=None, capture: Path = CAPTURE, replace: dict | None = None) -> list[dict]:
    """The scenario of a whole run on the recorded phone."""
    apk = write_apk(tmp_path / "base-built.apk", manifest(PACKAGE),
                    dex=dex_blob(urls=("https://googleads.g.doubleclick.net/mads/gma",)))
    split = tmp_path / "split-built.apk"
    split.write_bytes(b"PK\x05\x06" + b"\x00" * 18)          # an empty zip: a split holds no manifest of its own
    shot = tmp_path / "shot-built.png"
    shot.write_bytes(b"\x89PNG\r\n\x1a\n")
    entries = {
        "package_paths": [answer("package_paths")],
        "pcapdroid_listed": [answer("pcapdroid_listed")],
        "services": services(*(dumps or ("no_capture", "capture_waiting_confirmation", "capture_running",
                                         "capture_stopping", "no_capture"))),
        "apk_pulled": [answer("apk_pulled", file=Path(apk))],
        "split_pulled": [answer("split_pulled", file=split)],
        "files_removed": [answer("files_removed")],
        "wake": [answer("wake")],
        "app_stopped": [answer("app_stopped")],
        "app_data_cleared": [answer("app_data_cleared")],
        "capture_start_sent": [answer("capture_start_sent")],
        "app_launched": [answer("app_launched")],
        "screenshot_taken": [answer("screenshot_taken")],
        "capture_stop_sent": [answer("capture_stop_sent")],
        "capture_pulled": [answer("capture_pulled", file=capture)],
        "screenshot_pulled": [answer("screenshot_pulled", file=shot)],
        "pcapdroid_stopped": [answer("pcapdroid_stopped")],
    }
    entries.update(replace or {})
    return [e for group in entries.values() for e in group]


def adb(tmp_path: Path, entries: list[dict], serial: str | None = None) -> tuple[device.Device, Path]:
    scenario, log = adb_fake.write_scenario(tmp_path, entries)
    return device.Device(adb_fake.command(scenario, log), serial=serial), log


def run(tmp_path: Path, entries: list[dict], said: list[str] | None = None, **options) -> tuple[device.Run, Path]:
    phone_, log = adb(tmp_path, entries)
    options.setdefault("seconds", 0)
    options.setdefault("poll", 0.01)
    found = device.observe_app(phone_, PACKAGE, tmp_path / "out",
                               say=(said if said is not None else []).append, **options)
    return found, log


def shell(calls: list[list[str]]) -> list[str]:
    """Each call as one line, the serial and the local half of a pull left out."""
    lines = []
    for c in calls:
        c = c[2:] if c[:1] == ["-s"] else c
        lines.append(" ".join(c[:2] if c[:1] == ["pull"] else c))
    return lines


def index(lines: list[str], start: str) -> int:
    return next(i for i, line in enumerate(lines) if line.startswith(start))


# --- a run --------------------------------------------------------------------------


def test_a_run_brings_back_the_apks_the_capture_and_the_screenshot(tmp_path):
    found, _ = run(tmp_path, phone(tmp_path))
    assert [p.name for p in found.apks] == ["base.apk", "split_config.arm64_v8a.apk"]
    assert found.apks[0].read_bytes() == (tmp_path / "base-built.apk").read_bytes()
    assert found.capture.read_bytes() == CAPTURE.read_bytes()
    assert found.screenshot.read_bytes().startswith(b"\x89PNG")
    assert {p.parent for p in (*found.apks, found.capture, found.screenshot)} == {tmp_path / "out"}


def test_the_capture_runs_before_the_app_starts_and_ends_after_it_stops(tmp_path):
    _, log = run(tmp_path, phone(tmp_path))
    lines = shell(adb_fake.calls(log))
    start, launch = index(lines, "shell am start -e action start"), index(lines, "shell monkey")
    stop = index(lines, "shell am start -e action stop")
    assert start < launch < stop < lines.index(f"shell am force-stop {PACKAGE}", launch)
    # what PCAPdroid captures is this app: the request names it, and this run's file
    assert f"-e pcap_name apkradar-observe.pcap -e app_filter {PACKAGE}" in lines[start]


def test_the_capture_is_pulled_only_once_pcapdroid_has_stopped(tmp_path):
    """Three seconds after the stop request the phone still listed CaptureService, and
    the file went on growing until it stopped: a pull then would take a cut capture."""
    _, log = run(tmp_path, phone(tmp_path))
    lines = shell(adb_fake.calls(log))
    stop, pull = index(lines, "shell am start -e action stop"), index(lines, "pull /sdcard/Download/PCAPdroid/")
    dumps_after_stop = [i for i, line in enumerate(lines) if line == " ".join(SERVICES) and stop < i < pull]
    assert len(dumps_after_stop) == 2          # still stopping, then gone


def test_the_files_left_on_the_phone_are_removed_before_and_after(tmp_path):
    """Removed first so a file from an earlier run cannot be taken for this one."""
    _, log = run(tmp_path, phone(tmp_path))
    lines = shell(adb_fake.calls(log))
    removals = [i for i, line in enumerate(lines) if line.startswith("shell rm -f ")]
    assert len(removals) == 2
    assert removals[0] < index(lines, "shell am start -e action start")
    assert removals[1] > index(lines, "pull /sdcard/Download/apkradar-observe.png")


def test_the_app_data_is_left_alone_unless_asked(tmp_path):
    _, log = run(tmp_path, phone(tmp_path))
    assert not any(line.startswith("shell pm clear") for line in shell(adb_fake.calls(log)))


def test_clear_data_makes_the_run_a_first_launch(tmp_path):
    _, log = run(tmp_path, phone(tmp_path), clear_data=True)
    lines = shell(adb_fake.calls(log))
    assert index(lines, f"shell pm clear {PACKAGE}") < index(lines, "shell am start -e action start")


def test_the_serial_goes_with_every_call(tmp_path):
    scenario, log = adb_fake.write_scenario(tmp_path, phone(tmp_path))
    device.observe_app(device.Device(adb_fake.command(scenario, log), serial="ZY32MMVBZB"), PACKAGE,
                       tmp_path / "out", seconds=0, poll=0.01, say=[].append)
    calls = adb_fake.calls(log)
    assert calls and all(c[:2] == ["-s", "ZY32MMVBZB"] for c in calls)


# --- the operator's confirmation ------------------------------------------------------


def test_the_operator_is_asked_to_allow_the_capture_on_the_phone(tmp_path):
    said: list[str] = []
    run(tmp_path, phone(tmp_path), said=said)
    asked = [line for line in said if "Allow" in line]
    assert len(asked) == 1
    assert "60 s" in asked[0]


def test_nobody_is_asked_when_the_capture_starts_at_once(tmp_path):
    said: list[str] = []
    run(tmp_path, phone(tmp_path, dumps=("no_capture", "capture_running", "capture_stopping", "no_capture")),
        said=said)
    assert not [line for line in said if "Allow" in line]


def test_a_capture_never_allowed_closes_pcapdroid_and_launches_nothing(tmp_path):
    """The request left on screen could be allowed later and start a capture nobody
    collects, under this run's name: closing PCAPdroid withdraws it."""
    entries = phone(tmp_path, dumps=("no_capture", "capture_waiting_confirmation"))
    with pytest.raises(device.DeviceError, match="did not start within 0.2 s"):
        run(tmp_path, entries, confirm_timeout=0.2)
    lines = shell(adb_fake.calls(tmp_path / "adb-calls.jsonl"))
    assert "shell am force-stop com.emanuelef.remote_capture" in lines
    assert not any(line.startswith("shell monkey") for line in lines)


def test_a_capture_already_running_is_refused(tmp_path):
    """Its start request would be dropped and this run's file never written."""
    entries = phone(tmp_path, dumps=("capture_running",))
    with pytest.raises(device.DeviceError, match="already capturing"):
        run(tmp_path, entries)
    lines = shell(adb_fake.calls(tmp_path / "adb-calls.jsonl"))
    assert not any(line.startswith("shell am start") for line in lines)


def test_a_capture_that_does_not_stop_is_reported(tmp_path):
    entries = phone(tmp_path, dumps=("no_capture", "capture_running"))
    with pytest.raises(device.DeviceError, match="did not stop within 0.2 s"):
        run(tmp_path, entries, stop_timeout=0.2)


def test_an_empty_capture_says_so(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(device.DeviceError, match="empty capture"):
        run(tmp_path, phone(tmp_path, capture=empty))


# --- what is not there ----------------------------------------------------------------


def test_a_package_not_on_the_phone_stops_the_run_at_once(tmp_path):
    entries = phone(tmp_path, replace=instead("package_paths", "package_not_installed"))
    with pytest.raises(device.DeviceError, match=f"{PACKAGE} is not installed on the device"):
        run(tmp_path, entries)
    assert shell(adb_fake.calls(tmp_path / "adb-calls.jsonl")) == [f"shell pm path {PACKAGE}"]


def test_pcapdroid_missing_says_where_to_get_it(tmp_path):
    entries = phone(tmp_path, replace=instead("pcapdroid_listed", "nothing_listed"))
    with pytest.raises(device.DeviceError, match="PCAPdroid .* is not installed.*F-Droid"):
        run(tmp_path, entries)


def test_adb_s_own_error_is_passed_on(tmp_path):
    """A wrong serial: adb says so on stderr, and that is the message."""
    entries = phone(tmp_path, replace=instead("package_paths", "unknown_serial"))
    with pytest.raises(device.DeviceError, match="device 'ZZ00NOTADEVICE' not found"):
        run(tmp_path, entries)


def test_an_app_without_a_launcher_activity_still_has_its_capture_stopped(tmp_path):
    entries = phone(tmp_path, replace=instead("app_launched", "launch_without_activity"))
    with pytest.raises(device.DeviceError, match="no launcher activity"):
        run(tmp_path, entries)
    lines = shell(adb_fake.calls(tmp_path / "adb-calls.jsonl"))
    assert index(lines, "shell am start -e action stop") > index(lines, "shell monkey")


@pytest.mark.parametrize("name", ["com.example;reboot", "com.example app", "$(id)", "example", "com..example", ""])
def test_a_name_that_is_not_a_package_never_reaches_the_phone_s_shell(tmp_path, name):
    """adb shell hands its words to the phone's shell: the name is checked first."""
    phone_, log = adb(tmp_path, [])
    with pytest.raises(device.DeviceError, match="not an Android package name"):
        device.observe_app(phone_, name, tmp_path / "out", seconds=0, say=[].append)
    assert adb_fake.calls(log) == []


# --- the command ----------------------------------------------------------------------


def test_observe_device_reports_what_the_app_contacted(tmp_path):
    scenario, log = adb_fake.write_scenario(tmp_path, phone(tmp_path))
    outcome = runner.invoke(app, ["observe-device", PACKAGE, "--out", str(tmp_path / "out"), "--seconds", "0",
                                  "--adb", adb_fake.program(scenario, log)], terminal_width=200)
    assert outcome.exit_code == 0, outcome.output
    text = " ".join(outcome.output.split())
    assert "Hosts contacted at runtime (7" in text
    assert "googleads.g.doubleclick.net" in text
    assert "Brought back:" in text and (tmp_path / "out" / "capture.pcap").read_bytes() == CAPTURE.read_bytes()


def test_observe_device_failing_on_the_phone_exits_1_with_the_reason(tmp_path):
    entries = phone(tmp_path, replace=instead("package_paths", "package_not_installed"))
    scenario, log = adb_fake.write_scenario(tmp_path, entries)
    outcome = runner.invoke(app, ["observe-device", PACKAGE, "--out", str(tmp_path / "out"),
                                  "--adb", adb_fake.program(scenario, log)], terminal_width=200)
    assert outcome.exit_code == 1
    assert "is not installed on the device" in outcome.output


def test_the_report_can_go_into_the_directory_the_run_creates(tmp_path):
    """Refused on the first real run, 2026-10-15: the report target was checked before
    --out existed, so a report beside the capture had "no directory to write into"."""
    scenario, log = adb_fake.write_scenario(tmp_path, phone(tmp_path))
    out = tmp_path / "run1"
    outcome = runner.invoke(app, ["observe-device", PACKAGE, "--out", str(out), "--seconds", "0",
                                  "--output", str(out / "report.txt"), "--adb", adb_fake.program(scenario, log)])
    assert outcome.exit_code == 0, outcome.output
    assert "Hosts contacted at runtime" in (out / "report.txt").read_text(encoding="utf-8")


def test_observe_device_checks_the_report_target_before_touching_the_phone(tmp_path):
    scenario, log = adb_fake.write_scenario(tmp_path, phone(tmp_path))
    outcome = runner.invoke(app, ["observe-device", PACKAGE, "--out", str(tmp_path / "out"),
                                  "--output", str(tmp_path / "report.docx"),
                                  "--adb", adb_fake.program(scenario, log)])
    assert outcome.exit_code == 2
    assert adb_fake.calls(log) == []
