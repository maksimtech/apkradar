"""Observe an app on an Android device over adb: the capture `observe` reads, taken.

PCAPdroid (com.emanuelef.remote_capture, F-Droid and Google Play) captures one app's
traffic on the phone itself, without root, through a local VPN, and takes requests
from other apps through its CaptureCtrl activity. adb sends those requests, starts the
app, takes a screenshot and brings the files back. APKRadar never taps the phone:
PCAPdroid asks the operator to allow the capture, and the operator answers.

Everything goes through `adb shell`, which hands its words to the phone's shell, so the
package name is checked before anything is sent. Nothing here reaches the network: the
device is on the USB cable — what reaches the network is the app, on the phone, and
that is what is being observed.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

PCAPDROID = "com.emanuelef.remote_capture"
CONTROL = f"{PCAPDROID}/.activities.CaptureCtrl"
REMOTE_CAPTURE = "/sdcard/Download/PCAPdroid/apkradar-observe.pcap"
REMOTE_SCREENSHOT = "/sdcard/Download/apkradar-observe.png"

# Java package naming as Android applies it: two or more dot-separated identifiers.
_PACKAGE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+")


class DeviceError(RuntimeError):
    """The run on the device could not go on; the message says why, for the operator."""


@dataclass(frozen=True)
class Run:
    apks: tuple[Path, ...]      # base.apk first, then the splits
    capture: Path
    screenshot: Path


class Device:
    """One device as adb reaches it. `adb` is the program, as an argv prefix."""

    def __init__(self, adb: Sequence[str] = ("adb",), serial: str | None = None):
        self._prefix = [*adb, *(["-s", serial] if serial else [])]

    def adb(self, *args: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [*self._prefix, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                check=False,
            )
        except OSError as exc:
            raise DeviceError(f"cannot run adb ({self._prefix[0]}): {exc.strerror or exc}") from exc

    def shell(self, *words: str) -> subprocess.CompletedProcess[str]:
        return self.adb("shell", *words)

    def pull(self, remote: str, local: Path) -> None:
        done = self.adb("pull", remote, str(local))
        if done.returncode != 0:
            raise DeviceError(_said(done) or f"adb could not pull {remote}")

    def capturing(self) -> bool:
        return "CaptureService" in self.shell("dumpsys", "activity", "services", PCAPDROID).stdout


def _said(done: subprocess.CompletedProcess[str]) -> str:
    return done.stderr.strip()


def _wait(phone: Device, capturing: bool, timeout: float, poll: float) -> bool:
    deadline = time.monotonic() + timeout
    while phone.capturing() != capturing:
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll)
    return True


def observe_app(
    phone: Device,
    package: str,
    out: Path,
    *,
    seconds: float,
    say: Callable[[str], object],
    clear_data: bool = False,
    confirm_timeout: float = 60,
    stop_timeout: float = 30,
    poll: float = 1,
) -> Run:
    """Run `package` on the phone for `seconds` while PCAPdroid captures it; bring the files into `out`."""
    if not _PACKAGE.fullmatch(package):
        raise DeviceError(f"{package!r} is not an Android package name")
    found = phone.shell("pm", "path", package)
    paths = [line.removeprefix("package:") for line in found.stdout.split() if line.startswith("package:")]
    if not paths:
        raise DeviceError(_said(found) or f"{package} is not installed on the device")
    if f"package:{PCAPDROID}" not in phone.shell("pm", "list", "packages", PCAPDROID).stdout.split():
        raise DeviceError(
            f"PCAPdroid ({PCAPDROID}) is not installed on the device: install it from F-Droid or Google Play "
            "and start one capture from it, to grant its VPN permission"
        )
    if phone.capturing():
        raise DeviceError("PCAPdroid is already capturing: stop that capture first — it would drop this run's request")

    out.mkdir(parents=True, exist_ok=True)
    paths.sort(key=lambda p: not p.endswith("/base.apk"))
    apks = tuple(out / Path(p).name for p in paths)
    for remote, local in zip(paths, apks, strict=True):
        phone.pull(remote, local)
    phone.shell("rm", "-f", REMOTE_CAPTURE, REMOTE_SCREENSHOT)

    phone.shell("input", "keyevent", "KEYCODE_WAKEUP")
    phone.shell("am", "force-stop", package)
    if clear_data:
        cleared = phone.shell("pm", "clear", package)
        if "Success" not in cleared.stdout:
            raise DeviceError(_said(cleared) or f"could not clear the data of {package}")
    phone.shell("am", "start", "-e", "action", "start", "-e", "pcap_dump_mode", "pcap_file",
                "-e", "pcap_name", Path(REMOTE_CAPTURE).name, "-e", "app_filter", package, "-n", CONTROL)
    if not phone.capturing():
        say(f"PCAPdroid asks on the phone to allow the capture: tap Allow. Waiting up to {confirm_timeout:g} s.")
        if not _wait(phone, True, confirm_timeout, poll):
            # Withdraws the request: allowed later, it would capture under this run's name.
            phone.shell("am", "force-stop", PCAPDROID)
            raise DeviceError(
                f"the capture did not start within {confirm_timeout:g} s; PCAPdroid was closed, so the request "
                "cannot be allowed later. Run again and tap Allow."
            )

    try:
        launched = phone.shell("monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
        if launched.returncode != 0 or "Events injected: 1" not in launched.stdout:
            raise DeviceError(f"{package} has no launcher activity: it could not be started")
        say(f"Capturing {package} for {seconds:g} s.")
        time.sleep(seconds)
        phone.shell("screencap", "-p", REMOTE_SCREENSHOT)
    finally:
        phone.shell("am", "start", "-e", "action", "stop", "-n", CONTROL)
        stopped = _wait(phone, False, stop_timeout, poll)
        phone.shell("am", "force-stop", package)
    if not stopped:
        raise DeviceError(f"PCAPdroid did not stop within {stop_timeout:g} s: its capture would be cut short")

    capture, screenshot = out / "capture.pcap", out / "screenshot.png"
    phone.pull(REMOTE_CAPTURE, capture)
    phone.pull(REMOTE_SCREENSHOT, screenshot)
    phone.shell("rm", "-f", REMOTE_CAPTURE, REMOTE_SCREENSHOT)
    if capture.stat().st_size == 0:
        raise DeviceError("PCAPdroid wrote an empty capture: nothing was recorded")
    return Run(apks=apks, capture=capture, screenshot=screenshot)
