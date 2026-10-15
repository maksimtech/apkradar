"""A stand-in for adb that answers with output recorded from a real device.

    python adb_fake.py <scenario.json> <calls.jsonl> [adb arguments...]

The scenario lists recorded adb calls — fixtures/adb_moto_g17_recorded.json holds
them as they came from a Motorola moto g17 — and each run of this program answers
the one whose arguments match its own, with that call's exit status, stdout and
stderr. A command asked more than once gets the scenario's answers for it in turn,
the last one repeating: that is how PCAPdroid's services dump goes from nothing,
to waiting for the operator, to capturing. Every call is appended to calls.jsonl,
so a test reads back what was run and in which order.

`-s <serial>` is logged and then set aside when matching, as adb applies it before
the command. A `pull` is matched on its remote path alone — the local one belongs
to the machine that recorded it — and copies the scenario entry's `file` to the
local path given. A command the scenario does not hold exits 99: an adb call the
code makes and nobody recorded is a test failure, not a guess.

The program uses the standard library only and runs under `python -I`.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve()


def _key(args: list[str]) -> list[str]:
    if args[:1] == ["-s"]:
        args = args[2:]
    return args[:2] if args[:1] == ["pull"] else args


def main(argv: list[str]) -> int:
    scenario, log, *args = argv
    with open(log, "a", encoding="utf-8") as out:
        out.write(json.dumps(args) + "\n")
    with open(log, encoding="utf-8") as calls:
        earlier = [json.loads(line) for line in calls][:-1]
    key = _key(args)
    with open(scenario, encoding="utf-8") as f:
        answers = [entry for entry in json.load(f) if entry["args"] == key]
    if not answers:
        sys.stderr.write(f"adb_fake: nothing recorded for {args}\n")
        return 99
    answer = answers[min(sum(_key(c) == key for c in earlier), len(answers) - 1)]
    if answer.get("file") and answer["returncode"] == 0:
        target = Path(args[-1])          # pull <remote> <local>
        if target.is_dir():
            target = target / Path(key[1]).name
        shutil.copyfile(answer["file"], target)
    sys.stdout.buffer.write(answer["stdout"].encode("utf-8"))
    sys.stderr.buffer.write(answer["stderr"].encode("utf-8"))
    return answer["returncode"]


# --- for the tests ----------------------------------------------------------------


def write_scenario(directory: Path, entries: list[dict]) -> tuple[Path, Path]:
    """The scenario file and the (empty) call log a fake adb in `directory` will use."""
    scenario, log = directory / "adb-scenario.json", directory / "adb-calls.jsonl"
    scenario.write_text(json.dumps(entries), encoding="utf-8")
    log.write_text("", encoding="utf-8")
    return scenario, log


def command(scenario: Path, log: Path) -> list[str]:
    """The fake as an argv prefix, the way `apkradar.device.Device` takes adb."""
    return [sys.executable, "-I", str(HERE), str(scenario), str(log)]


def program(scenario: Path, log: Path) -> str:
    """The fake as one executable path, the way `--adb` takes it on the command line."""
    if os.name == "nt":
        path = scenario.with_name("adb.cmd")
        path.write_text(f'@"{sys.executable}" -I "{HERE}" "{scenario}" "{log}" %*\r\n', encoding="utf-8")
    else:
        path = scenario.with_name("adb")
        path.write_text(f'#!/bin/sh\nexec "{sys.executable}" -I "{HERE}" "{scenario}" "{log}" "$@"\n', encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def calls(log: Path) -> list[list[str]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
