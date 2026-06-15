from core.context import PipelineContext
from rich.table import Table
from rich.panel import Panel
from typing import List
from rich.console import Group, RenderableType
from rich.rule import Rule
from rich.text import Text


def _verdict_style(verdict: str | None) -> str:
    if verdict == "ALLOW":
        return "bold green"
    if verdict == "REVIEW":
        return "bold yellow"
    return "bold red"


def _bool_str(v: bool) -> str:
    return "yes" if v else "no"


def format_human(ctx: PipelineContext, verbose: bool = False) -> Group:
    parts: List[RenderableType] = []

    header = Text()
    header.append(f"{ctx.package}", style="bold")
    header.append("  -  ")
    score = str(ctx.risk_score) if ctx.risk_score is not None else "-"
    level = ctx.risk_level if ctx.risk_level else "-"
    header.append(f"risk {score} ({level})", style=_verdict_style(ctx.verdict))
    parts.append(header)

    if ctx.static_score is not None and ctx.ai_score is not None:
        breakdown = Text("  [ ")
        breakdown.append(f"static {ctx.static_score}", style="cyan")
        breakdown.append(" + ")
        breakdown.append(f"AI {ctx.ai_score}", style="dim")
        breakdown.append(f" = final {score} ]", style=_verdict_style(ctx.verdict))
        parts.append(breakdown)

    if ctx.features and ctx.metadata:
        table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
        table.add_column("Signal", style="cyan", no_wrap=True)
        table.add_column("Value")
        table.add_row("remote exec calls", str(ctx.features.remote_exec_count))
        table.add_row("external calls", str(ctx.features.external_calls))
        table.add_row(
            "package managers",
            ", ".join(ctx.features.package_manager_usage) if ctx.features.package_manager_usage else "-",
        )
        table.add_row("obfuscation score", str(ctx.features.obfuscation_score))
        table.add_row("system modification", _bool_str(ctx.features.system_modification))
        table.add_row("orphan", _bool_str(ctx.metadata.orphan_status))
        table.add_row("maintainer changed", ctx.metadata.maintainer_changed)
        table.add_row("package age (days)", str(ctx.metadata.package_age_days))
        table.add_row("last update (days ago)", str(ctx.metadata.last_update_delta_days))
        parts.append(Panel(table, title="Signals", border_style="dim", expand=True))

    if verbose and ctx.features and ctx.metadata:
        from rich.pretty import Pretty

        parts.append(Rule(style="dim"))
        parts.append(Text("Verbose Details", style="underline"))
        parts.append(Pretty(ctx.features))
        parts.append(Pretty(ctx.metadata))

    if ctx.ai_analysis:
        ai_lines = []
        score_text = Text()
        score_text.append("AI risk score ", style="bold cyan")
        score_text.append(f"{ctx.ai_analysis.ai_risk_score}", style="bold yellow")
        score_text.append(f" ({ctx.ai_analysis.ai_risk_level})", style=_verdict_style(ctx.ai_analysis.ai_risk_level))
        ai_lines.append(score_text)

        if ctx.ai_analysis.ai_risk_details:
            d = Text()
            d.append("Details       ", style="bold cyan")
            d.append(ctx.ai_analysis.ai_risk_details)
            ai_lines.append(d)

        s = Text()
        s.append("Summary       ", style="bold cyan")
        s.append(ctx.ai_analysis.summary, style="green")
        ai_lines.append(s)

        p = Text()
        p.append("Patterns      ", style="bold cyan")
        p.append(", ".join(ctx.ai_analysis.suspicious_patterns), style="yellow")
        ai_lines.append(p)

        a = Text()
        a.append("Attack vector ", style="bold cyan")
        a.append(ctx.ai_analysis.attack_surface)
        ai_lines.append(a)

        r_text = Text("Rationale", style="bold cyan")
        ai_lines.append(r_text)
        for r in ctx.ai_analysis.rationale:
            ai_lines.append(Text(f"  - {r}"))
        parts.append(Panel(Group(*ai_lines), title="AI Analysis", border_style="dim", expand=True))

    if ctx.errors:
        err_lines = []
        for err in ctx.errors:
            tag = f"[{err.code}]"
            err_lines.append(f"  {tag} stage={err.stage}  {err.message}  (recoverable: {_bool_str(err.recoverable)})")
        parts.append(Panel("\n".join(err_lines), title="Errors", border_style="red", expand=True))

    verdict_text = Text()
    verdict_text.append(ctx.verdict or "-", style=_verdict_style(ctx.verdict))
    parts.append(
        Panel(verdict_text, title="Verdict", border_style=_verdict_style(ctx.verdict).split()[-1], expand=True)
    )

    return Group(*parts)
