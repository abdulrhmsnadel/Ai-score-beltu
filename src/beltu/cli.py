from __future__ import annotations

from pathlib import Path
import json
import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from beltu import APP_NAME, __version__
from beltu.ai import analyze_finding, triage, build_prompt
from beltu.core.models import ScanContext
from beltu.core.scope import ScopeError, validate_url
from beltu.core.http import redact_url
from beltu.core.store import FindingStore
from beltu.core.scoring import calculate_score
from beltu.engines.engine_catalog import CATALOG
from beltu.engines.registry import get_engine
from beltu.guessing import iter_cases, generate_cases, write_cases
from beltu.ai_router import enrich_findings, ENGINE_ROUTES, route_for_engine

app = typer.Typer(help=f"{APP_NAME} — terminal-first authorized web/API security assessment framework", no_args_is_help=True)
scan_app = typer.Typer(help="Run one dedicated security engine")
mail_app = typer.Typer(help="Controlled local test mailbox helpers")
findings_app = typer.Typer(help="Inspect locally stored findings")
ai_app = typer.Typer(help="AI-assisted local triage and evidence reasoning")
guess_app = typer.Typer(help="Controlled mutation/guessing corpus and bounded fuzz workflows")
app.add_typer(scan_app, name="scan")
app.add_typer(mail_app, name="mail")
app.add_typer(findings_app, name="findings")
app.add_typer(ai_app, name="ai")
app.add_typer(guess_app, name="guess")
console = Console()

SAFE_BASELINE = ("authentication", "misconfiguration", "cryptography", "integrity", "disclosure", "cors", "csrf", "open-redirect")


def _print_banner() -> None:
    title = Text()
    title.append("AI-SCORE-BELTU", style="bold bright_cyan")
    title.append(f"  v{__version__}", style="dim")
    console.print(Panel.fit(title, border_style="bright_blue", padding=(0, 2)))


@app.command()
def version() -> None:
    _print_banner()
    console.print(f"{APP_NAME} {__version__}")


@app.command()
def doctor(
    ollama_check: bool = typer.Option(False, "--ollama-check", help="Probe local Ollama only when explicitly requested."),
) -> None:
    _print_banner()
    import platform

    components: list[tuple[str, str]] = [("Python", platform.python_version())]
    from importlib.metadata import PackageNotFoundError, version as package_version
    for distribution, display in [("httpx", "HTTPX"), ("typer", "Typer"), ("rich", "Rich"), ("pydantic", "Pydantic"), ("PyYAML", "PyYAML"), ("scikit-learn", "scikit-learn")]:
        try:
            components.append((display, package_version(distribution)))
        except PackageNotFoundError:
            components.append((display, "MISSING"))

    if ollama_check:
        try:
            import httpx
            response = httpx.get("http://127.0.0.1:11434/api/version", timeout=1.0)
            ollama = response.json().get("version", "reachable") if response.status_code == 200 else "not detected"
        except Exception:
            ollama = "not detected"
    else:
        ollama = "not checked (use --ollama-check)"
    components.append(("Ollama", str(ollama)))

    table = Table("Component", "Status", border_style="blue", show_header=True)
    for name, status in components:
        table.add_row(name, status if status != "MISSING" else "[red]MISSING[/red]")
    console.print(table)
    console.print(f"Interface: [bold]Terminal / CLI[/bold]    Engines: [bold]{len(CATALOG)}[/bold]")
    console.print("Safety: [bold]explicit host allowlist required[/bold]")
    console.print("Excluded: reconnaissance, XSS, SQL Injection")


@app.command("engines")
def engines() -> None:
    _print_banner()
    table = Table("Command", "Category", "What it needs", border_style="blue")
    for meta in CATALOG:
        table.add_row(meta.name, meta.display_name, ", ".join(meta.inputs))
    console.print(table)


@app.command("engine-info")
def engine_info(name: str) -> None:
    engine = get_engine(name)
    meta = next(m for m in CATALOG if m.name == name.lower())
    _print_banner()
    console.print(f"[bold]{meta.display_name}[/bold]")
    console.print(meta.description)
    console.print("\nInputs:")
    for item in meta.inputs:
        console.print(f"  • {item}")
    console.print("\nEngine requirements:")
    for item in engine.requires:
        console.print(f"  • {item}")


@app.command("scope-check")
def scope_check(url: str, allow_host: list[str] = typer.Option(..., "--allow-host", "-w", help="Explicit host allowlist")) -> None:
    try:
        normalized = validate_url(url, allow_host)
    except ScopeError as exc:
        console.print(f"[red]OUT OF SCOPE:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"[green]IN SCOPE[/green] {normalized}")


def _parse_headers(items: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in items:
        if ":" not in item:
            raise ValueError(f"Invalid header '{item}'. Use 'Name: value'.")
        key, value = item.split(":", 1)
        key = key.strip()
        if key:
            headers[key] = value.strip()
    return headers


def _run_engine(engine_name: str, target: str, allow_host: list[str], output: Path, db: Path, html_report: Path | None, options: dict[str, object] | None = None, headers: list[str] | None = None, details: bool = False, ai_remote: bool = False):
    try:
        normalized = validate_url(target, allow_host)
        request_headers = _parse_headers(headers or [])
        context = ScanContext(target=normalized, allow_hosts=allow_host, options=options or {}, headers=request_headers)
        findings = list(get_engine(engine_name).run(context))
    except (ScopeError, ValueError) as exc:
        console.print(f"[red]STOPPED:[/red] {exc}")
        raise typer.Exit(code=2)
    findings = enrich_findings(findings, remote=ai_remote or os.getenv("BELTU_AI_AUTORUN", "0") == "1")
    store = FindingStore(db)
    for result in findings:
        store.save(result)
    from beltu.reporting.export import write_html, write_json
    write_json(findings, output)
    if html_report:
        write_html(findings, html_report)
    _render_findings(findings, output, details=details)
    return findings


def _redact_display(value):
    if isinstance(value, dict):
        out = {}
        sensitive = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key", "password", "token", "session", "secret"}
        for k, v in value.items():
            if str(k).lower() in sensitive:
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact_display(v)
        return out
    if isinstance(value, list):
        return [_redact_display(v) for v in value]
    if isinstance(value, str) and len(value) > 1200:
        return value[:1200] + "… [truncated]"
    return value


def _render_details(findings) -> None:
    for idx, result in enumerate(findings, 1):
        analysis = analyze_finding(result)
        console.print(Panel.fit(
            f"[bold]{result.title}[/bold]\n"
            f"Engine: {result.engine}   Severity: {result.severity.value}   Verification: {result.verification.value}\n"
            f"Confidence: {result.confidence:.0%}   AI: {analysis.score}/100   Credibility: {analysis.credibility}/100\n"
            f"Target: {redact_url(result.target)}\n\n"
            f"[bold]Why it was flagged[/bold]\n{result.description or '—'}\n\n"
            f"[bold]Recommended action[/bold]\n{result.remediation or '—'}",
            title=f"Finding {idx}: {result.id}",
            border_style="cyan",
        ))
        for ev in result.evidence:
            console.print(f"[bold]Evidence:[/bold] {ev.title} ({ev.kind})")
            console.print_json(data=_redact_display(ev.data))


def _render_findings(findings, output: Path, details: bool = False) -> None:
    table = Table("Severity", "Verify", "Engine", "Title", "Confidence", "AI")
    for result in findings:
        analysis = analyze_finding(result)
        table.add_row(
            result.severity.value,
            result.verification.value,
            result.engine,
            result.title,
            f"{result.confidence:.0%}",
            f"{analysis.score}/100",
        )
    if findings:
        console.print(table)
        top = max((analyze_finding(f) for f in findings), key=lambda a: a.score)
        console.print(f"AI triage: [bold]{top.verdict}[/bold] ({top.score}/100)")
        if details:
            _render_details(findings)
    else:
        console.print("[green]No findings produced by this engine.[/green]")
    console.print(f"Risk score: [bold bright_cyan]{calculate_score(findings)}/100[/bold bright_cyan]")
    confirmed = sum(f.verification.value == "confirmed" for f in findings)
    console.print(f"Credibility: [bold]{round(sum(analyze_finding(f).credibility for f in findings) / len(findings)) if findings else 0}/100[/bold]  Confirmed: [bold]{confirmed}[/bold]")
    console.print(f"[dim]Saved {len(findings)} finding(s) → {output}[/dim]")


def _common_scan_options():
    return None


@scan_app.command("ssrf")
def scan_ssrf(target: str, canary_url: str = typer.Option(..., "--canary-url", "-c"), canary_allow_host: list[str] = typer.Option(..., "--canary-allow-host", "-C"), allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), header: list[str] = typer.Option([], "--header", "-H"), details: bool = typer.Option(False, "--details", "-x")):
    _run_engine("ssrf", target, allow_host, output, db, html_report, {"canary_url": canary_url, "canary_allow_hosts": canary_allow_host}, header, details)


@scan_app.command("csrf")
def scan_csrf(target: str, allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), header: list[str] = typer.Option([], "--header", "-H"), details: bool = typer.Option(False, "--details", "-x")):
    _run_engine("csrf", target, allow_host, output, db, html_report, {}, header, details)


@scan_app.command("api")
def scan_api(target: str, openapi: str = typer.Option(..., "--openapi", "-p"), allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), header: list[str] = typer.Option([], "--header", "-H"), details: bool = typer.Option(False, "--details", "-x")):
    _run_engine("api", target, allow_host, output, db, html_report, {"openapi": openapi}, header, details)


@scan_app.command("access-control")
def scan_access_control(
    target: str,
    identity_a_headers: str | None = typer.Option(None, "--identity-a-headers", "-A", help="Identity A headers; required in comparison mode and object-mutation mode."),
    identity_b_headers: str | None = typer.Option(None, "--identity-b-headers", "-B", help="Identity B headers for two-identity comparison mode."),
    marker_a: list[str] = typer.Option([], "--marker-a", "-M", help="A-only marker in two-identity comparison mode; can repeat."),
    marker_target: list[str] = typer.Option([], "--marker-target", "-N", help="Marker expected only in the mutated target object response; can repeat."),
    identity_b_expected_status: int = typer.Option(403, "--identity-b-expected-status", "-S"),
    object_param: str | None = typer.Option(None, "--object-param", "-P", help="Query parameter containing the object/resource identifier."),
    object_value: str | None = typer.Option(None, "--object-value", "-V", help="Alternate object identifier to request with the same session."),
    allow_host: list[str] = typer.Option(..., "--allow-host", "-w"),
    output: Path = typer.Option(Path("findings.json"), "--output", "-o"),
    db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"),
    html_report: Path | None = typer.Option(None, "--html", "-r"),
    details: bool = typer.Option(False, "--details", "-x"),
):
    options = {
        "identity_a_headers": identity_a_headers or "",
        "identity_b_headers": identity_b_headers or "",
        "markers_a": marker_a,
        "markers_target": marker_target,
        "identity_b_expected_status": identity_b_expected_status,
        "object_param": object_param or "",
        "object_value": object_value or "",
        "identity_headers": identity_a_headers or "",
    }
    _run_engine("access-control", target, allow_host, output, db, html_report, options, details=details)


@scan_app.command("cors")
def scan_cors(target: str, allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), origin: str = typer.Option("https://beltu.invalid", "--origin", "-O"), preflight_method: str = typer.Option("GET", "--preflight-method", "-P"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), header: list[str] = typer.Option([], "--header", "-H"), details: bool = typer.Option(False, "--details", "-x")):
    _run_engine("cors", target, allow_host, output, db, html_report, {"origin": origin, "preflight_method": preflight_method}, header, details)


@scan_app.command("open-redirect")
def scan_open_redirect(target: str, allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), redirect_target: str = typer.Option("https://beltu.invalid/", "--redirect-target", "-R"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), header: list[str] = typer.Option([], "--header", "-H"), details: bool = typer.Option(False, "--details", "-x")):
    _run_engine("open-redirect", target, allow_host, output, db, html_report, {"redirect_target": redirect_target}, header, details)


@scan_app.command("jwt")
def scan_jwt(target: str, token: str = typer.Option(..., "--token", "-k"), allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), details: bool = typer.Option(False, "--details", "-x")):
    _run_engine("jwt", target, allow_host, output, db, html_report, {"token": token}, details=details)


for _name in ("authentication", "misconfiguration", "cryptography", "integrity", "disclosure"):
    def _factory(name: str):
        def command(target: str, allow_host: list[str] = typer.Option(..., "--allow-host", "-w"), output: Path = typer.Option(Path("findings.json"), "--output", "-o"), db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), html_report: Path | None = typer.Option(None, "--html", "-r"), header: list[str] = typer.Option([], "--header", "-H"), details: bool = typer.Option(False, "--details", "-x")) -> None:
            _run_engine(name, target, allow_host, output, db, html_report, {}, header, details)
        command.__name__ = f"scan_{name.replace('-', '_')}"
        return command
    scan_app.command(_name)(_factory(_name))


@app.command("assess")
def assess(
    target: str,
    allow_host: list[str] = typer.Option(..., "--allow-host", "-w"),
    engine: list[str] = typer.Option([], "--engine", "-E", help="Engine to include; repeat for several. Defaults to the safe baseline."),
    header: list[str] = typer.Option([], "--header", "-H"),
    output: Path = typer.Option(Path("assessment.json"), "--output", "-o"),
    db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"),
    html_report: Path | None = typer.Option(None, "--html", "-r"),
    details: bool = typer.Option(False, "--details", "-x"),
) -> None:
    selected = tuple(engine) if engine else SAFE_BASELINE
    try:
        validate_url(target, allow_host)
        request_headers = _parse_headers(header)
        context = ScanContext(target=target, allow_hosts=allow_host, headers=request_headers, options={})
    except (ScopeError, ValueError) as exc:
        console.print(f"[red]STOPPED:[/red] {exc}")
        raise typer.Exit(code=2)
    all_findings = []
    for name in selected:
        try:
            all_findings.extend(get_engine(name).run(context))
        except Exception as exc:
            console.print(f"[yellow]Engine {name} skipped:[/yellow] {exc}")
    store = FindingStore(db)
    for result in all_findings:
        store.save(result)
    from beltu.reporting.export import write_html, write_json
    write_json(all_findings, output)
    if html_report:
        write_html(all_findings, html_report)
    _print_banner()
    console.print(f"Assessment engines: {', '.join(selected)}")
    _render_findings(all_findings, output, details=details)


@app.command("report")
def report(
    db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"),
    output: Path = typer.Option(Path("report.json"), "--output", "-o"),
    html_report: Path | None = typer.Option(None, "--html", "-r"),
    sarif: Path | None = typer.Option(None, "--sarif", "-S"),
    details: bool = typer.Option(False, "--details", "-x"),
) -> None:
    """Generate JSON/HTML/SARIF reports from findings already stored in SQLite."""
    findings = FindingStore(db).all()
    from beltu.reporting.export import write_html, write_json
    write_json(findings, output)
    if html_report:
        write_html(findings, html_report)
    if sarif:
        from beltu.reporting.export import write_sarif
        write_sarif(findings, sarif)
    _print_banner()
    _render_findings(findings, output, details=details)
    if html_report:
        console.print(f"HTML report: {html_report}")
    if sarif:
        console.print(f"SARIF report: {sarif}")


@findings_app.command("list")
def findings_list(db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), severity: str | None = typer.Option(None, "--severity")) -> None:
    rows = FindingStore(db).all()
    if severity:
        rows = [r for r in rows if r.severity.value == severity.lower()]
    table = Table("ID", "Severity", "Engine", "Title", "Status")
    for f in rows[:100]:
        table.add_row(f.id[:8], f.severity.value, f.engine, f.title, f.status.value)
    console.print(table)
    console.print(f"Showing {min(len(rows), 100)} of {len(rows)} finding(s)")


@mail_app.command("latest")
def mail_latest(base_url: str = typer.Option("http://127.0.0.1:8025", "--url", "-u"), extract: str = typer.Option("none", "--extract", "-x", help="none, otp, or link")):
    from beltu.identity.mail import MailpitAdapter
    adapter = MailpitAdapter(base_url)
    try:
        messages = adapter.list_messages()
        if not messages:
            console.print("No messages.")
            return
        message = adapter.get_message(messages[0].message_id)
    except Exception as exc:
        console.print(f"[red]Mailbox unavailable:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"ID: {message.message_id}")
    console.print(f"From: {message.sender}")
    console.print(f"Subject: {message.subject}")
    if extract == "otp":
        console.print(f"OTP: {adapter.find_otp(message) or '-'}")
    elif extract == "link":
        console.print(f"Link: {adapter.find_verification_link(message) or '-'}")
    else:
        console.print(message.text[:4000])


@mail_app.command("doctor")
def mail_doctor(base_url: str = typer.Option("http://127.0.0.1:8025", "--url", "-u")):
    from beltu.identity.mail import MailpitAdapter
    try:
        messages = MailpitAdapter(base_url).list_messages()
    except Exception as exc:
        console.print(f"[red]Mailbox unavailable:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(f"Mailpit reachable. Messages: {len(messages)}")



@guess_app.command("corpus")
def guess_corpus(
    engine: str | None = typer.Option(None, "--engine", "-E", help="Engine corpus; omit for mixed corpus."),
    count: int = typer.Option(10_000, "--count", "-n", min=1, max=1_000_000, help="Offline corpus size (up to 1,000,000)."),
    output: Path = typer.Option(Path("beltu-guess-corpus.jsonl"), "--output", "-o"),
    seed: int = typer.Option(1337, "--seed"),
) -> None:
    """Generate deterministic guess/test cases without making network requests."""
    try:
        cases = iter_cases(engine, count, seed=seed)
    except ValueError as exc:
        console.print(f"[red]Corpus error:[/red] {exc}")
        raise typer.Exit(code=2)
    written = write_cases(output, cases)
    _print_banner()
    console.print(f"Generated [bold]{written:,}[/bold] test cases → {output}")
    console.print("[dim]Corpus generation makes no network requests.[/dim]")


@guess_app.command("access-control")
def guess_access_control(
    target: str,
    identity_headers: str = typer.Option(..., "--identity-headers", "-A", help="Authenticated headers for one dedicated test identity."),
    object_param: str = typer.Option("id", "--object-param", "-P", help="Query parameter containing the object/resource identifier."),
    allow_host: list[str] = typer.Option(..., "--allow-host", "-w"),
    count: int = typer.Option(1_000, "--count", "-n", min=1, max=10_000),
        delay: float = typer.Option(0.15, "--delay", min=0.05, max=10.0, help="Delay between guesses in seconds."),
    marker_target: list[str] = typer.Option([], "--marker", "-M", help="Marker unique to the target object; repeat as needed."),
    stop_on_hit: bool = typer.Option(True, "--stop-on-hit/--continue", help="Stop on the first strong match."),
    confirm_large_run: bool = typer.Option(False, "--confirm-large-run", help="Required for more than 1,000 network requests."),
    output: Path = typer.Option(Path("access-control-guess.json"), "--output", "-o"),
    db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"),
    html_report: Path | None = typer.Option(None, "--html", "-r"),
    details: bool = typer.Option(False, "--details", "-x"),
) -> None:
    """Bounded object-ID guessing for authorized labs/test systems; no credential guessing."""
    from beltu.core.scope import ScopeError, validate_url
    from beltu.engines.access_guess import run_access_control_guess
    from beltu.core.models import ScanContext
    if count > 1_000 and not confirm_large_run:
        console.print("[yellow]Large run blocked:[/yellow] add --confirm-large-run for more than 1,000 requests.")
        raise typer.Exit(code=2)
    try:
        normalized = validate_url(target, allow_host)
        context = ScanContext(target=normalized, allow_hosts=allow_host, options={})
        result = run_access_control_guess(
            context,
            headers_raw=identity_headers,
            object_param=object_param,
            count=count,
            delay_seconds=delay,
            stop_on_hit=stop_on_hit,
            markers=marker_target,
        )
    except (ScopeError, ValueError) as exc:
        console.print(f"[red]STOPPED:[/red] {exc}")
        raise typer.Exit(code=2)
    result.findings = enrich_findings(result.findings, remote=os.getenv("BELTU_AI_AUTORUN", "0") == "1")
    store = FindingStore(db)
    for finding_result in result.findings:
        store.save(finding_result)
    from beltu.reporting.export import write_html
    from beltu.core.http import redact_data
    payload = redact_data({
        "mode": "access-control-guess",
        "target": normalized,
        "object_param": object_param,
        "requested_cases": count,
        "attempted_requests": result.attempted,
        "baseline_status": result.baseline_status,
        "stopped_on_hit": result.stopped_on_hit,
        "findings": [f.model_dump(mode="json") for f in result.findings],
    })
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if html_report:
        write_html(result.findings, html_report)
    _print_banner()
    console.print(f"Guessing: [bold]{count:,}[/bold] cases requested | [bold]{result.attempted:,}[/bold] HTTP requests")
    if result.findings:
        _render_findings(result.findings, output, details=details)
    else:
        console.print("[green]No authorization finding produced by the guess run.[/green]")
        console.print(f"Baseline status: {result.baseline_status} | Stopped on hit: {result.stopped_on_hit}")
        console.print(f"[dim]Saved run summary → {output}[/dim]")


@ai_app.command("status")
def ai_status() -> None:
    _print_banner()
    console.print("Local AI: [green]READY[/green] (deterministic evidence triage)")
    try:
        import httpx
        r = httpx.get("http://127.0.0.1:11434/api/tags", timeout=1.5)
        ollama = r.status_code == 200
    except Exception:
        ollama = False
    console.print(f"Ollama: {'[green]AVAILABLE[/green]' if ollama else '[dim]not detected[/dim]'}")
    console.print("AI policy: no exploit generation, no secret extraction, no invented evidence")


@ai_app.command("triage")
def ai_triage(
    db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"),
    output: Path = typer.Option(Path("ai-triage.json"), "--output", "-o"),
    provider: str = typer.Option("local", "--provider", "-P", help="local, ensemble, openai, claude, deepseek-coder-v2, codellama, pentestgpt, graph"),
) -> None:
    findings = FindingStore(db).all()
    if not findings:
        console.print("[yellow]No stored findings to analyze.[/yellow]")
        return
    rows = triage(findings)
    payload: dict[str, object] = {"provider": provider, "findings": rows}
    if provider == "ensemble":
        from beltu.ai_router import enrich_findings
        enriched = enrich_findings(findings, remote=True)
        payload["enriched_findings"] = [f.model_dump(mode="json") for f in enriched]
    elif provider == "openai":
        from beltu.ai_providers import openai_gpt4o
        result = openai_gpt4o(build_prompt(findings))
        payload["provider_result"] = {"ok": result.ok, "data": result.data, "error": result.error}
    elif provider == "claude":
        from beltu.ai_providers import anthropic_claude
        result = anthropic_claude(build_prompt(findings))
        payload["provider_result"] = {"ok": result.ok, "data": result.data, "error": result.error}
    elif provider == "deepseek-coder-v2":
        from beltu.ai_providers import deepseek_coder_v2
        result = deepseek_coder_v2(build_prompt(findings))
        payload["provider_result"] = {"ok": result.ok, "data": result.data, "error": result.error, "latency_ms": result.latency_ms}
    elif provider == "codellama":
        from beltu.ai_providers import ollama_chat
        result = ollama_chat(build_prompt(findings))
        payload["provider_result"] = {"ok": result.ok, "data": result.data, "error": result.error}
    elif provider == "pentestgpt":
        from beltu.ai_providers import pentestgpt_plan
        result = pentestgpt_plan(build_prompt(findings))
        payload["provider_result"] = {"ok": result.ok, "data": result.data, "error": result.error}
    elif provider == "graph":
        from beltu.ai_graph import run_graph
        payload["graph"] = run_graph(findings, allow_remote=False)
    elif provider != "local":
        console.print("[red]Unknown provider.[/red] Use local, ensemble, openai, claude, deepseek-coder-v2, codellama, pentestgpt, or graph.")
        raise typer.Exit(code=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    table = Table("Score", "Verdict", "Engine", "Finding")
    for row in rows[:30]:
        table.add_row(str(row["analysis"]["score"]), row["analysis"]["verdict"], row["engine"], row["title"])
    console.print(table)
    console.print(f"AI triage saved to {output}")


@ai_app.command("planner")
def ai_planner(engine: str, db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"), output: Path = typer.Option(Path("verification-plan.json"), "--output", "-o")) -> None:
    """Generate a planner-only verification suggestion using PentestGPT when configured."""
    findings = [f for f in FindingStore(db).all() if f.engine == engine]
    if not findings:
        console.print(f"[yellow]No findings for engine: {engine}[/yellow]")
        raise typer.Exit(code=2)
    from beltu.ai_providers import pentestgpt_plan
    result = pentestgpt_plan(build_prompt(findings))
    payload = {"engine": engine, "provider": result.provider, "ok": result.ok, "data": result.data, "error": result.error, "mode": "planner-only"}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print_json(data=payload)


@ai_app.command("explain")
def ai_explain(finding_id: str, db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D")) -> None:
    findings = FindingStore(db).all()
    matches = [f for f in findings if f.id.startswith(finding_id)]
    if not matches:
        console.print("[red]Finding not found.[/red]")
        raise typer.Exit(code=2)
    result = analyze_finding(matches[0])
    console.print(Panel.fit(f"[bold]{matches[0].title}[/bold]\nAI score: {result.score}/100\nVerdict: {result.verdict}"))
    for reason in result.reasons:
        console.print(f"• {reason}")
    console.print(f"Next action: {result.next_action}")




@ai_app.command("providers")
def ai_providers() -> None:
    """Show provider roles and whether configuration is present."""
    _print_banner()
    rows = [
        ("gpt-4o", "OpenAI API", "cross-engine adjudication", bool(os.getenv("BELTU_OPENAI_API_KEY") or os.getenv("OPENAI_API_KEY"))),
        ("claude", "Anthropic", "second-opinion review", bool(os.getenv("BELTU_ANTHROPIC_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))),
        ("codellama", "Ollama / Code Llama", "local HTTP/code semantic review", True),
        ("burp", "Burp bridge", "request/response context from Burp", True),
        ("deepseek-coder-v2", "DeepSeek", "code/HTTP reasoning (configurable endpoint)", bool(os.getenv("BELTU_DEEPSEEK_API_KEY") or os.getenv("DEEPSEEK_API_KEY"))),
        ("pentestgpt", "PentestGPT", "planner-only verification suggestions", True),
        ("langgraph", "LangGraph", "bounded AI workflow orchestration", True),
        ("langchain", "LangChain", "model/chain composition layer", True),
        ("pyjwt", "PyJWT", "local JWT parsing/validation helper", True),
        ("interactsh", "Interactsh", "OOB canary/polling integration", True),
        ("sklearn", "scikit-learn", "duplicate/anomaly signal", True),
    ]
    table = Table("Provider", "Role", "Configuration")
    for name, role, purpose, configured in rows:
        table.add_row(name, purpose, "[green]READY/OPTIONAL[/green]" if configured else "[yellow]NOT CONFIGURED[/yellow]")
    console.print(table)
    console.print("[dim]No provider is allowed to invent evidence or replace manual verification.[/dim]")


@ai_app.command("route")
def ai_route(engine: str) -> None:
    """Show the logical AI route for an engine."""
    route = route_for_engine(engine)
    _print_banner()
    console.print(f"[bold]{engine}[/bold] → " + " → ".join(route))
    console.print("Burp bridge and Interactsh are on-demand; scikit-learn and PyJWT are local helpers; LangGraph/LangChain orchestrate AI only.")


@ai_app.command("graph")
def ai_graph(
    db: Path = typer.Option(Path("beltu.sqlite3"), "--db", "-D"),
    output: Path = typer.Option(Path("ai-graph.json"), "--output", "-o"),
    remote: bool = typer.Option(False, "--remote", help="Allow configured remote AI providers."),
) -> None:
    """Run the bounded AI review graph; remote calls are opt-in."""
    findings = FindingStore(db).all()
    if not findings:
        console.print("[yellow]No stored findings to analyze.[/yellow]")
        return
    from beltu.ai_graph import run_graph
    result = run_graph(findings, allow_remote=remote)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print_json(data=result)
    console.print(f"[dim]Saved → {output}[/dim]")


@ai_app.command("interactsh")
def ai_interactsh(
    server: str | None = typer.Option(None, "--server", "-s"),
    token: str | None = typer.Option(None, "--token", "-T", help="Protected self-hosted Interactsh token."),
) -> None:
    """Generate an OOB canary through the official interactsh client."""
    from beltu.integrations.interactsh import generate_payload
    try:
        payload = generate_payload(server=server, token=token)
    except Exception as exc:
        console.print(f"[red]Interactsh failed:[/red] {exc}")
        raise typer.Exit(code=2)
    console.print(Panel.fit(f"[bold]OOB Canary[/bold]\n{payload}", border_style="bright_cyan"))


@ai_app.command("burp")
def ai_burp(
    input_file: Path = typer.Option(..., "--input", "-F", exists=True, readable=True, help="Redacted Burp HTTP message JSON/text export."),
    provider: str = typer.Option("openai", "--provider", "-P"),
    output: Path = typer.Option(Path("burp-ai.json"), "--output", "-o"),
) -> None:
    from beltu.integrations.burp_bridge import analyze_burp_message, load_message
    result = analyze_burp_message(load_message(input_file), provider=provider)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print_json(data=result)
    console.print(f"[dim]Saved → {output}[/dim]")


SHORTCUTS = {
    "-I": ["ai", "triage"],
    "-G": ["guess"],
    "-a": ["assess"],
    "-d": ["doctor"],
    "-e": ["engines"],
    "-f": ["findings", "list"],
    "-g": ["report"],
    "-i": ["engine-info"],
    "-m": ["mail", "latest"],
    "-s": ["scope-check"],
    "-t": ["scan"],
    "-v": ["version"],
    "-h": ["--help"],
}


def expand_shortcuts(argv: list[str]) -> list[str]:
    """Translate only the first compact action into the regular Typer command tree."""
    if not argv:
        return argv
    action = argv[0]
    replacement = SHORTCUTS.get(action)
    if replacement is None:
        return argv
    return replacement + argv[1:]


def main(argv: list[str] | None = None) -> None:
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    app(args=expand_shortcuts(args), prog_name="beltu")


if __name__ == "__main__":
    main()
