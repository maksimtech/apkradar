"""What docs/nis2-compliance.md tells a customer has to stay true of this code.

The document answers the seven questions a customer subject to NIS2 (directive
2022/2555, in Italy d.lgs. 138/2024) can ask a software supplier, and a customer
reads it as evidence. Every statement in it that the repository can prove is
checked here, so that the document goes red when the code moves away from it
instead of quietly turning false: the hosts the tool contacts, directly and
through the three Radar-family and Play libraries it calls, the SDK domains
`--full` analyses, which commands reach the network at all, what the DPO letter
carries, the user the image runs as, the cache it writes, the files each release
carries, the scanners it names, and the words a supplier cannot honestly use.

What the repository cannot prove is not claimed as proven. The required status
checks live in GitHub's settings, so the document gives the date they were read
on; there is no penetration test, so the document says there is none.
"""

from __future__ import annotations

import ast
import importlib.util
import inspect
import re
from pathlib import Path

import pytest
import yaml

from apkradar import __version__, cli, law_cache, law_checker, law_fetcher
from apkradar.scanner import ScanResult, TrackerFound, scan
from apkradar.sender import render_letter
from apkradar.utils import SDK_DOMAINS, get_all_domains

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "apkradar"
DOC = ROOT / "docs" / "nis2-compliance.md"
SECURITY = ROOT / "SECURITY.md"
README = ROOT / "README.md"
DOCKERFILE = ROOT / "Dockerfile"
WORKFLOWS = ROOT / ".github" / "workflows"
EVIDENCE = WORKFLOWS / "sbom.yml"
DOCKER = WORKFLOWS / "docker.yml"

# A module that imports one of these can reach the network; one that does not
# cannot, whatever URLs its constants mention (tlp.py prints the FIRST standard's
# address in letters, hosts.py and content.py only cite URL shapes in comments).
# The last three are the libraries apkradar hands a domain or a package name to:
# a module importing them sends something out through them.
NETWORK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+"
    r"(?:httpx|smtplib|dns|requests|urllib\.request|socket|google_play_scraper|mailradar|cookieradar)\b",
    re.M,
)
URL_HOST = re.compile(r"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# The contact URL the law requests carry in their User-Agent. It names this
# repository; nothing is sent to it.
USER_AGENT_LINK = re.compile(r"\(\+https://github\.com/maksimtech/")
# A link printed for the user to open, in Rich markup: `search` with an app name
# prints the Play search page and contacts nothing.
PRINTED_LINK = re.compile(r"\[link\]https?://")


def _docstring_nodes(tree: ast.AST) -> set[int]:
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                found.add(id(first.value))
    return found


def _hosts_in(path: Path) -> set[str]:
    """Fixed hosts in the string constants of one module, docstrings and links left out."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = _docstring_nodes(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in skip or USER_AGENT_LINK.search(node.value) or PRINTED_LINK.search(node.value):
            continue
        found.update(host.lower().rstrip(".") for host in URL_HOST.findall(node.value))
    return found


def hosts_in_code() -> dict[str, set[str]]:
    """Fixed hosts named in string constants of the modules that can reach the network.

    A host built from a domain (f"https://{domain}") has no fixed name and is
    declared in prose, not in the table this is compared with.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        if not NETWORK_IMPORT.search(path.read_text(encoding="utf-8")):
            continue
        for host in _hosts_in(path):
            found.setdefault(host, set()).add(path.name)
    return found


# What apkradar calls in each library that reaches the network for it, and the
# modules of that library those calls run. mailradar.checker imports
# mailradar.gpg for the key lookup, cookieradar.scanner imports its tracker list.
DEPENDENCY_CALLS = {
    ("mailradar.checker", "analyze_domain"),
    ("cookieradar.scanner", "scan"),
    ("google_play_scraper", "app"),
    ("google_play_scraper.exceptions", "NotFoundError"),
}
DEPENDENCY_MODULES = {
    "mailradar": ("checker.py", "gpg.py"),
    "cookieradar": ("scanner.py", "trackerdb.py"),
    "google_play_scraper": None,  # the whole package: `app` builds its URL in constants/
}


def _package_dir(name: str) -> Path:
    spec = importlib.util.find_spec(name)
    assert spec and spec.origin, f"{name} is not installed"
    return Path(spec.origin).parent


def hosts_through_dependencies() -> dict[str, set[str]]:
    """Fixed hosts named in the dependency modules apkradar's calls run."""
    found: dict[str, set[str]] = {}
    for name, files in DEPENDENCY_MODULES.items():
        base = _package_dir(name)
        paths = sorted(base.rglob("*.py")) if files is None else [base / f for f in files]
        for path in paths:
            for host in _hosts_in(path):
                found.setdefault(host, set()).add(name)
    return found


def section(text: str, name: str) -> str:
    """The text between `<!-- name:start -->` and `<!-- name:end -->`."""
    match = re.search(rf"<!-- {name}:start -->(.*?)<!-- {name}:end -->", text, re.S)
    assert match, f"docs/nis2-compliance.md has no {name} section between its markers"
    return match.group(1)


def table_first_column(block: str) -> set[str]:
    """The backticked value in the first cell of every row of a markdown table."""
    values = set()
    for line in block.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if line.lstrip().startswith("|") and cells and cells[0].startswith("`"):
            values.add(cells[0].strip("`"))
    return values


def prose(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture(scope="module")
def doc() -> str:
    return DOC.read_text(encoding="utf-8")


# --- Question 3: what leaves the machine ------------------------------------


def test_every_host_the_code_contacts_is_declared_and_no_other(doc):
    declared = table_first_column(section(doc, "hosts"))
    in_code = set(hosts_in_code())
    assert declared == in_code, (
        f"declared but not in the code: {sorted(declared - in_code)}; "
        f"in the code but not declared: {sorted(in_code - declared)}"
    )


def test_the_host_rule_looks_at_something():
    """A rule that found no host would pass for the wrong reason."""
    assert len(hosts_in_code()) >= 4


def test_the_host_rule_skips_what_is_only_cited():
    """The law requests name github.com/maksimtech/apkradar in their User-Agent;
    `search` with an app name prints the Play search page as a link; tlp.py
    prints www.first.org/tlp in letters. None of them is a host apkradar's own
    code talks to — play.google.com is reached, by google-play-scraper, and is
    declared with the dependencies."""
    hosts = hosts_in_code()
    for cited in ("github.com", "play.google.com", "www.first.org"):
        assert cited not in hosts


def test_apkradar_calls_only_these_functions_of_the_libraries_that_reach_out():
    """The dependency table covers the modules these calls run. A new call into
    mailradar (its `discover` reaches crt.sh and rdap.org) would reach hosts the
    table does not list, so it has to show up here first."""
    calls = set()
    for path in PACKAGE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in DEPENDENCY_MODULES:
                calls.update((node.module, alias.name) for alias in node.names)
            if isinstance(node, ast.Import):
                assert not any(a.name.split(".")[0] in DEPENDENCY_MODULES for a in node.names), (
                    f"{path.name} imports a whole network library"
                )
    assert calls == DEPENDENCY_CALLS


def test_every_host_reached_through_a_dependency_is_declared_and_no_other(doc):
    """Read from the installed libraries, so a release of mailradar that adds a
    keyserver turns the document red here."""
    declared = table_first_column(section(doc, "hosts-deps"))
    found = set(hosts_through_dependencies())
    assert declared == found, (
        f"declared but not in the libraries: {sorted(declared - found)}; "
        f"in the libraries but not declared: {sorted(found - declared)}"
    )
    for entry in ("`mailradar.checker.analyze_domain`", "`cookieradar.scanner.scan`", "`google_play_scraper.app`"):
        assert entry in doc


def test_the_sdk_domains_full_analyses_are_listed_whole(doc):
    """`--full` sends MailRadar, a TLS handshake and a browser to these, for every
    tracker it finds: a customer has to know them by name."""
    listed = set(re.findall(r"`([a-z0-9.-]+\.[a-z]+)`", section(doc, "sdk-domains")))
    in_code = {domain for domains in SDK_DOMAINS.values() for domain in domains}
    assert listed == in_code, f"missing: {sorted(in_code - listed)}; extra: {sorted(listed - in_code)}"


def test_the_hosts_in_the_dex_are_reported_and_never_contacted(doc):
    """The host list of the report is what the code can reach. None of it goes
    into the domains `--full` analyses."""
    result = ScanResult(apk_path="app.apk", package_name="org.example.app", dex_hosts=["only-in-the-dex.example.net"])
    assert "only-in-the-dex.example.net" not in get_all_domains(result)
    assert "elencati nel report e non vengono mai contattati" in prose(doc)


def test_the_commands_table_names_every_command(doc):
    names = {command.name or command.callback.__name__ for command in cli.app.registered_commands}
    assert table_first_column(section(doc, "commands")) == {f"apkradar {name}" for name in names}


NETWORK_CALLS = {
    "_full_stack_domain",
    "_check_mailradar",
    "_check_ssl",
    "_law_check",
    "lookup",
    "without_parked",
    "send_letter",
    "_domains_to_analyse",
}


def _command(name: str) -> ast.FunctionDef:
    tree = ast.parse((PACKAGE / "cli.py").read_text(encoding="utf-8"))
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _called(node: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def _name(call: ast.Call) -> str:
    func = call.func
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""


def test_the_network_calls_named_here_exist():
    """A renamed function would make the two tests below pass on nothing."""
    source = "".join(path.read_text(encoding="utf-8") for path in PACKAGE.glob("*.py"))
    for name in NETWORK_CALLS:
        assert f"def {name}(" in source, name
    assert inspect.signature(scan).parameters["lookup_publisher"].default is False


def test_batch_excel_reaches_nothing():
    body = _command("batch_excel")
    for call in _called(body):
        assert _name(call) not in NETWORK_CALLS, _name(call)
        if _name(call) == "scan":
            assert not call.keywords, "batch-excel asks Google Play"


def test_observe_reaches_nothing():
    """It reads a capture already on disk and the APK; the law check, which asks the
    law sources, is left to `audit`."""
    body = _command("observe")
    for call in _called(body):
        assert _name(call) not in NETWORK_CALLS, _name(call)
        if _name(call) == "scan":
            assert not call.keywords, "observe asks Google Play"


def test_the_capture_observe_reads_stays_on_the_machine(doc):
    assert "La cattura letta da `apkradar observe` resta sulla macchina" in prose(doc)
    assert "il traffico decifrato letto con `--decrypted`" in prose(doc)


def test_observe_device_reaches_nothing_but_the_device():
    """It drives the phone over adb and reads what it brings back, as observe does."""
    body = _command("observe_device")
    for call in _called(body):
        assert _name(call) not in NETWORK_CALLS, _name(call)
        if _name(call) == "scan":
            assert not call.keywords, "observe-device asks Google Play"
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(ast.parse((PACKAGE / "device.py").read_text(encoding="utf-8")))
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in (node.names if isinstance(node, ast.Import) else [ast.alias(node.module or "")])
    }
    assert imported.isdisjoint({"socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp"}), imported


def test_what_observe_device_brings_back_stays_on_the_machine(doc):
    assert "`apkradar observe-device` comanda via adb il dispositivo collegato" in prose(doc)
    assert "con `--clear-data` cancella i dati dell'app sul dispositivo" in prose(doc)


def test_batch_reaches_out_only_under_full():
    body = _command("batch")
    under_full = {
        id(call)
        for node in ast.walk(body)
        if isinstance(node, ast.If) and any(isinstance(n, ast.Name) and n.id == "full" for n in ast.walk(node.test))
        for call in _called(node)
    }
    for call in _called(body):
        if _name(call) in NETWORK_CALLS:
            assert id(call) in under_full, f"batch calls {_name(call)} without --full"
        if _name(call) == "scan":
            assert not call.keywords, "batch asks Google Play"


def test_the_play_lookup_and_the_law_check_are_where_the_document_says(doc):
    """`audit` asks Play only with --full and without --offline; `send` unless
    --offline. `audit` cites the law in every mode, `--offline` included, and only
    when there is something to cite."""
    source = (PACKAGE / "cli.py").read_text(encoding="utf-8")
    assert "scan(apk, lookup_publisher=full and not offline)" in source
    assert "scan(apk, lookup_publisher=not offline)" in source
    audit = _command("audit")
    law_calls = [c for c in _called(audit) if _name(c) == "_law_check"]
    assert law_calls and not any(
        isinstance(node, ast.If) and any(c in _called(node) for c in law_calls) for node in audit.body
    ), "audit no longer cites the law in every mode"
    for other in ("send", "batch", "batch_excel", "search"):
        assert "_law_check" not in {_name(c) for c in _called(_command(other))}, other
    assert "anche con `--offline`" in prose(doc)


def test_a_clean_result_asks_no_law_source(tmp_path):
    """Nothing to cite, nothing fetched: no act is even attempted."""
    clean = ScanResult(apk_path="clean.apk", package_name="org.example.app")
    result = law_checker.check(clean, cache=law_cache.LawCache(tmp_path / "law_cache.json"), consent_violation=False)
    assert result.acts == [] and result.citations == []
    assert not (tmp_path / "law_cache.json").exists()


def test_the_user_agent_claim_is_the_code_s(doc):
    """Only the law requests set one. The others go out with the library's own."""
    declared = law_fetcher.USER_AGENT.replace(__version__, "<versione>")
    assert f"`{declared}`" in doc
    for name in ("search_cmd.py", "publisher.py"):
        assert "User-Agent" not in (PACKAGE / name).read_text(encoding="utf-8"), name
    assert "User-Agent predefinito" in prose(doc)


def test_the_play_library_s_unverified_tls_is_declared(doc):
    """google-play-scraper turns certificate verification off for urllib when it
    is imported. Since 2026-10-11 ApkRadar imports it through
    _import_play_scraper, which puts the default back (tests/test_play_scraper_tls.py
    proves it on a real TLS server); the paragraph says both. If a release of the
    library stops doing so, the paragraph goes."""
    line = "ssl._create_default_https_context = ssl._create_unverified_context"
    request = (_package_dir("google_play_scraper") / "utils" / "request.py").read_text(encoding="utf-8")
    assert line in request
    assert f"`{line}`" in doc and "`google_play_scraper/utils/request.py`" in doc
    search = (PACKAGE / "search_cmd.py").read_text(encoding="utf-8")
    assert "ssl._create_default_https_context = default" in search
    text = prose(doc)
    assert "`_import_play_scraper`" in text
    assert "anche la richiesta a play.google.com verifica il certificato" in text
    assert "La richiesta a play.google.com non verifica quindi il certificato" not in text


def test_the_cache_declared_is_the_one_written(doc, monkeypatch, tmp_path):
    monkeypatch.delenv("APKRADAR_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    written = law_cache.default_cache_path().relative_to(tmp_path).as_posix()
    assert f"~/{written}" in doc
    assert "APKRADAR_HOME" in doc


def test_the_smtp_command_is_declared(doc):
    """`send` is the one command that delivers a document to a recipient: through
    the SMTP server named on the command line, to the address given with --to."""
    sender = (PACKAGE / "sender.py").read_text(encoding="utf-8")
    assert "smtplib.SMTP_SSL(" in sender and "server.starttls(context=context)" in sender
    assert "if smtp_port == 465:" in sender
    assert "getpass.getpass(" in sender
    assert "smtp_password" not in (PACKAGE / "cli.py").read_text(encoding="utf-8")
    assert inspect.signature(cli.send).parameters["smtp_port"].default.default == 465
    text = prose(doc)
    assert "apkradar send" in text
    for phrase in ("465", "STARTTLS", "non viene salvata", "--dry-run"):
        assert phrase in text, phrase


def test_the_letter_carries_the_hash_only_with_trackers(doc):
    common = {
        "publisher": "Example S.p.A.",
        "publisher_domain": "",
        "sender_name": "Mario Rossi",
        "sender_org": "",
        "sender_email": "mario@example.org",
    }
    digest = "ab" * 32
    tracked = ScanResult(apk_path="a.apk", package_name="org.example.app", sha256=digest,
                         trackers=[TrackerFound(package="com.appsflyer", name="AppsFlyer")])
    clean = ScanResult(apk_path="a.apk", package_name="org.example.app", sha256=digest)
    assert digest in render_letter(result=tracked, **common)
    assert digest not in render_letter(result=clean, **common)
    assert "solo quando sono stati rilevati tracker" in prose(doc)


def test_the_image_does_not_ship_the_browser_cookieradar_needs(doc):
    assert "playwright install" not in DOCKERFILE.read_text(encoding="utf-8")
    assert "`playwright install chromium`" in doc


def test_nothing_is_sent_to_the_supplier(doc):
    for host in table_first_column(section(doc, "hosts")) | table_first_column(section(doc, "hosts-deps")):
        assert "maksimtech" not in host and "github" not in host, host


# --- Question 2: who the container runs as -----------------------------------


def test_the_image_runs_as_the_user_the_document_names(doc):
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    user = re.findall(r"^USER\s+(\S+)", dockerfile, re.M)[-1]
    uid = re.search(rf"useradd\b[^\n]*-u\s+(\d+)[^\n]*\b{re.escape(user)}\b", dockerfile)
    assert user not in {"root", "0"}
    assert uid, f"the Dockerfile does not create {user} with an explicit UID"
    assert f"UID {uid.group(1)}" in doc
    assert f"`{user}`" in doc


# --- Questions 1 and 6: what every release carries ---------------------------


@pytest.fixture(scope="module")
def evidence() -> dict:
    return yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))


def test_the_evidence_follows_the_image_of_a_release(evidence):
    """The image SBOM and its scan describe the image of the tag, so the job
    runs when that image has been pushed — not when the tag is, when it does not
    exist yet."""
    triggers = evidence.get(True, evidence.get("on"))
    docker_name = yaml.safe_load(DOCKER.read_text(encoding="utf-8"))["name"]
    assert triggers["workflow_run"]["workflows"] == [docker_name]
    assert triggers["workflow_run"]["types"] == ["completed"]
    assert "tag" in triggers["workflow_dispatch"]["inputs"]
    job = next(iter(evidence["jobs"].values()))
    assert "conclusion == 'success'" in job["if"]
    assert "startsWith(github.event.workflow_run.head_branch, 'v')" in job["if"]


JOB_ENV_CONTEXTS = {"github", "inputs", "matrix", "needs", "secrets", "strategy", "vars"}


def test_the_job_env_uses_only_contexts_github_allows_there(evidence):
    """`runner` is not available in a job's `env`, and GitHub refuses the whole
    file when it finds it: on 2026-10-11 the first dispatch of mailradar's copy
    of this workflow answered HTTP 422, "Unrecognized named-value: 'runner'",
    after the tests and every check had passed."""
    for job in evidence["jobs"].values():
        for name, value in (job.get("env") or {}).items():
            for expression in re.findall(r"\$\{\{(.*?)\}\}", str(value)):
                # The first name of each dotted path: github.event.x names github only.
                used = set(re.findall(r"(?<![\w.])([a-z_]+)\.", expression))
                assert used <= JOB_ENV_CONTEXTS, f"env {name} uses {sorted(used - JOB_ENV_CONTEXTS)}"


def test_the_image_tag_named_is_the_one_docker_yml_pushes(doc):
    """docker.yml pushes the git tag as it is, v included: the image of a release
    is maksimtech/apkradar:v<version>, as Docker Hub's tag list showed on
    2026-10-11 (v2026.45, v2026.44.1, ...). mailradar's first evidence run asked
    for :2026.44 and got MANIFEST_UNKNOWN."""
    image = f"maksimtech/{PACKAGE.name}"
    docker = DOCKER.read_text(encoding="utf-8")
    assert re.search(r"VERSION=(?:\$\{RAW\}|v\$\{RAW#v\})", docker)
    assert f"{image}:${{{{ steps.version.outputs.VERSION }}}}" in docker
    for name, text in (("the document", doc), ("SECURITY.md", SECURITY.read_text(encoding="utf-8"))):
        assert f"{image}:v" in text, f"{name} does not name the image by its v tag"
        assert not re.search(rf"{re.escape(image)}:(?:\d|<)", text), f"{name} names a tag docker.yml never pushes"
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert '"registry:${IMAGE}:${TAG}"' in workflow
    assert "image-ref: ${{ env.IMAGE }}:${{ env.TAG }}" in workflow


def test_the_rollback_does_not_promise_a_tag_that_cannot_move(doc):
    """docker.yml has no schedule, so nothing rebuilds `latest` weekly; but its
    workflow_dispatch rebuilds a published tag and pushes it again, `latest`
    included. Only the digest cannot move, and both documents say so."""
    docker = yaml.safe_load(DOCKER.read_text(encoding="utf-8"))
    triggers = docker.get(True, docker.get("on"))
    assert "schedule" not in triggers
    assert "version" in triggers["workflow_dispatch"]["inputs"]
    security = SECURITY.read_text(encoding="utf-8")
    assert not re.search(r"ricostruit\w* ogni settimana", prose(doc), re.I)
    assert not re.search(r"rebuilt weekly|weekly rebuild", prose(security), re.I)
    assert "ricostruzione manuale" in prose(doc)
    assert "manual rebuild" in prose(security)


def test_the_evidence_note_gives_the_digest_and_not_the_tag_twice():
    """Syft puts the tag in metadata.component.version, and mailradar's first
    EVIDENCE note, on v2026.44, read "digest v2026.44". The digest a customer pins
    comes from Docker Hub, which gives the index digest and one per platform."""
    # Only the step that writes the note: the source SBOM step does write the
    # version into its own metadata.component, which is a different thing.
    describe = _evidence_step("Describe the evidence")
    assert '["metadata"]["component"]' not in describe
    assert "https://hub.docker.com/v2/repositories/${IMAGE}/tags/${TAG}" in describe


def test_the_source_sbom_names_the_package_it_describes():
    """Without --pyproject, cyclonedx-py lists the environment and names no main
    component: the SBOM did not say which product it was the SBOM of."""
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert "--pyproject pyproject.toml --mc-type application" in workflow


def test_the_evidence_job_pins_its_actions():
    for line in EVIDENCE.read_text(encoding="utf-8").splitlines():
        if "uses:" in line:
            ref = line.split("uses:", 1)[1].split("#")[0].strip()
            assert re.search(r"@[0-9a-f]{40}$", ref), f"not pinned to a commit: {line.strip()}"


def test_the_release_carries_the_files_the_document_promises(doc):
    promised = table_first_column(section(doc, "assets"))
    workflow = EVIDENCE.read_text(encoding="utf-8")
    assert promised, "the document promises no release file"
    for name in promised:
        stem = name.split("<")[0].rstrip("-")
        assert stem in workflow, f"{name} is promised but sbom.yml never writes {stem}"
    assert "gh release upload" in workflow


def test_the_scan_is_not_presented_as_a_penetration_test(doc):
    """Question 6 asks for a penetration test. There has been none, and a scan of
    known CVEs is not one: the release note that travels with the files says so."""
    assert "non è un penetration test" in prose(doc)
    assert "not a penetration test" in EVIDENCE.read_text(encoding="utf-8")


# --- Questions 4 and 5: policy and pipeline ----------------------------------

SCANNERS = {
    "CodeQL": "codeql",
    "Bandit": "bandit",
    "Trivy": "trivy",
    "Snyk": "snyk",
    "Docker Scout": "docker-scout",
    "SonarCloud": "sonarcloud",
    "Security Posture": "security-posture",
    "mutmut": "mutation",
    "CodSpeed": "codspeed",
}


def test_every_scanner_named_has_its_workflow_and_none_is_left_out(doc):
    named = table_first_column(section(doc, "scanners"))
    assert named <= set(SCANNERS), f"unknown scanner names: {sorted(named - set(SCANNERS))}"
    for name in named:
        assert (WORKFLOWS / f"{SCANNERS[name]}.yml").is_file(), f"{name} has no workflow"
    present = {n for n, w in SCANNERS.items() if (WORKFLOWS / f"{w}.yml").is_file()}
    assert present <= named, f"workflows the document does not name: {sorted(present - named)}"


def test_docker_scout_is_said_to_run_when_it_runs(doc):
    """It reads `latest` from Docker Hub on a push to main, weekly, on demand, and
    since 2026-10-24 once the image workflow has pushed a new one (until then
    nothing started it on a build, and the document said so)."""
    scout = yaml.safe_load((WORKFLOWS / "docker-scout.yml").read_text(encoding="utf-8"))
    triggers = scout.get(True, scout.get("on"))
    assert set(triggers) == {"workflow_dispatch", "push", "schedule", "workflow_run"}
    assert triggers["workflow_run"]["workflows"] == ["Build and Push Docker Image"]
    assert "maksimtech/apkradar:latest" in (WORKFLOWS / "docker-scout.yml").read_text(encoding="utf-8")
    row = next(line for line in section(doc, "scanners").splitlines() if line.startswith("| `Docker Scout`"))
    assert "ogni build dell'immagine" in row


def test_dependabot_is_named_because_it_is_configured(doc):
    """Alerts and security updates were enabled on 2026-10-11 (repository
    settings); version updates are this file."""
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    assert {u["package-ecosystem"] for u in config["updates"]} == {"pip", "github-actions"}
    assert "Dependabot" in doc
    assert "Dependabot" in SECURITY.read_text(encoding="utf-8")


def test_security_md_answers_the_fourth_question():
    text = SECURITY.read_text(encoding="utf-8")
    for heading in (
        "## Reporting a vulnerability",
        "## How vulnerabilities are found",
        "## Response times",
        "## Customer notification",
        "## Rollback",
    ):
        assert heading in text, f"SECURITY.md has no {heading!r}"
    assert "single maintainer" in text
    assert "Massimo Moretti" in text


def test_the_document_and_security_md_give_the_same_contact(doc):
    contacts = set(re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", SECURITY.read_text(encoding="utf-8")))
    assert contacts == {"security@maksimtech.com"}, contacts
    assert "security@maksimtech.com" in doc


def test_the_document_does_not_claim_a_second_review(doc):
    """The repository has one maintainer and its ruleset requires no approval.
    Question 5 asks for a second reviewer; the honest answer is that there is none."""
    text = prose(doc)
    assert "manutentore unico" in text
    assert "nessuna revisione obbligatoria da parte di una seconda persona" in text


FORBIDDEN = [
    re.compile(r"NIS2[- ](?:ready|compliant|certified)", re.I),
    re.compile(r"certificat\w* NIS2", re.I),
    re.compile(r"nessun dato (?:è )?inviato a terzi", re.I),
    re.compile(r"no data (?:is )?sent to third parties", re.I),
    re.compile(r"ogni PR richiede", re.I),
    # True of mailradar, not here: DuckDuckGo and the parked-domain check go out
    # with httpx's own User-Agent.
    re.compile(r"ogni richiesta HTTP si presenta", re.I),
]


@pytest.mark.parametrize("path", [DOC, SECURITY, README], ids=lambda p: p.name)
def test_no_claim_this_repository_cannot_back(path):
    text = path.read_text(encoding="utf-8")
    for pattern in FORBIDDEN:
        assert not pattern.search(text), f"{path.name} says {pattern.search(text).group(0)!r}"


# --- Question 1: the licence gate the document cites --------------------------


def test_the_licence_gate_matches_the_names_packages_actually_declare():
    """Without --partial-match, pip-licenses fails only on a licence string equal
    to "GPL", and no package declares that: they declare classifiers such as
    "GNU Lesser General Public License v2 or later (LGPLv2+)". Measured in
    mailradar on 2026-10-11 with chardet 5.2.0 installed: `--fail-on="GPL;AGPL;LGPL"`
    exited 0, the same with --partial-match exited 1. The gate had never refused
    anything."""
    licences = (WORKFLOWS / "licenses.yml").read_text(encoding="utf-8")
    gate = next(line for line in licences.splitlines() if "--fail-on" in line)
    assert "--partial-match" in gate


# --- The lockfile the document points to ------------------------------------


def test_quality_keeps_the_lockfile_in_step_with_pyproject():
    """APKRadar had no uv.lock until 2026-10-11. A lockfile shown to a customer as
    the list of dependencies has to be the current one, so the check that keeps it
    current came with it."""
    assert (ROOT / "uv.lock").is_file()
    quality = (WORKFLOWS / "quality.yml").read_text(encoding="utf-8")
    assert re.search(r"uv lock --check", quality)


def test_the_mutation_run_copies_what_these_tests_read():
    """mutmut copies the package and tests/ into mutants/ and runs the suite from
    there, adding only the paths listed in `also_copy`: a test that reads a file
    left behind dies in the stats phase, before a single mutant is tried. These
    tests read docs/, which was not listed."""
    import tomllib

    also_copy = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mutmut"]["also_copy"]
    for path in (DOC, SECURITY, README, DOCKERFILE, EVIDENCE):
        assert path.relative_to(ROOT).parts[0] in also_copy, path.relative_to(ROOT).as_posix()


# --- What the evidence says about itself --------------------------------------


def _evidence_step(name: str) -> str:
    workflow = yaml.safe_load(EVIDENCE.read_text(encoding="utf-8"))
    job = next(iter(workflow["jobs"].values()))
    return next(s["run"] for s in job["steps"] if s.get("name") == name)


def test_the_source_sbom_says_which_version_it_describes():
    """The version is dynamic in pyproject.toml, so cyclonedx-py names the main
    component and leaves its version out: the sbom-source files attached on
    2026-10-11 named the package and no version. The workflow writes the version
    of the package it installed, and refuses a tag that disagrees with it."""
    import tomllib

    dist = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["name"]
    sbom = _evidence_step("SBOM of the Python environment")
    assert f'm.version("{dist}")' in sbom
    assert '!= "$VERSION"' in sbom
    assert '["version"] =' in sbom


def test_the_source_sbom_leaves_out_what_the_image_removes():
    """The Dockerfile uninstalls pip, and the sbom-source attached on 2026-10-11
    still listed it: the venv's own copy, which the image does not ship. The
    environment described drops what the image drops, before it is described."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    removed = [p for p in ("pip", "setuptools", "wheel") if re.search(rf"pip uninstall[^\n]*\b{p}\b", dockerfile)]
    sbom = _evidence_step("SBOM of the Python environment")
    if not removed:
        # The image keeps pip, so the environment described keeps it too.
        assert "pip uninstall" not in sbom
        return
    install = sbom.index("/tmp/product/bin/pip install")
    uninstall = sbom.index("/tmp/product/bin/python -m pip uninstall --yes --quiet")
    describe = sbom.index("cyclonedx-py environment")
    assert install < uninstall < describe
    line = sbom[uninstall : sbom.index("\n", uninstall)].split()
    assert all(p in line for p in removed), f"the image removes {removed}"


def test_an_empty_repository_scan_is_not_presented_as_a_clean_one(doc):
    """A trivy-fs report with no Results means Trivy found no file it could read
    at that tag, such as a lockfile. Whoever opens it reads "no vulnerabilities",
    so the note and the document say what it is."""
    describe = _evidence_step("Describe the evidence")
    assert "found no file it could analyse" in describe
    assert "non indica l'assenza di vulnerabilità" in " ".join(doc.split())


def test_the_branch_rules_are_described_without_an_exception(doc):
    """On 2026-10-12 the ruleset on main lost the owner's bypass and requires a pull
    request for every change, the version bump included (release.sh opens one). The
    document says so with the date it was read, and keeps the earlier state as past."""
    text = prose(doc)
    assert "lette dalle impostazioni del repository il 2026-10-12" in text
    assert "Non prevedono eccezioni, nemmeno per l'account del manutentore" in text
    for stale in ("è configurato per poter scavalcare", "può scavalcare queste regole",
                  "può scavalcare le regole", "vanno direttamente su `main`",
                  "Non c'è una regola che imponga la pull request"):
        assert stale not in text, stale
