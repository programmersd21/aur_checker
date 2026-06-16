from core.context import PipelineContext
from rich.table import Table
from rich.panel import Panel
from typing import List
from rich.console import Group, RenderableType
from rich.text import Text


def _verdict_style(verdict: str | None) -> str:
    if verdict == "ALLOW":
        return "bold green"
    if verdict == "REVIEW":
        return "bold yellow"
    return "bold red"


def _verdict_label(verdict: str | None) -> str:
    """Convert verdict to user-friendly label."""
    if verdict == "ALLOW":
        return "✓ Safe to review"
    if verdict == "REVIEW":
        return "⚠ Needs attention"
    return "✗ High risk"


def _bool_str(v: bool) -> str:
    return "yes" if v else "no"


def format_human(ctx: PipelineContext, verbose: bool = False) -> Group:
    parts: List[RenderableType] = []

    # ── USER SUMMARY ──
    summary_lines = []

    header = Text()
    header.append("Package: ", style="bold")
    header.append(f"{ctx.package}", style="cyan")
    summary_lines.append(header)

    verdict_text = Text()
    verdict_text.append(_verdict_label(ctx.verdict), style=_verdict_style(ctx.verdict))
    summary_lines.append(verdict_text)

    score_text = Text()
    score = str(ctx.risk_score) if ctx.risk_score is not None else "-"
    score_text.append(f"Risk score: {score}/100", style="bold")
    if ctx.risk_level:
        score_text.append(f" ({ctx.risk_level})", style=_verdict_style(ctx.verdict))
    summary_lines.append(score_text)

    # Analysis mode indicator
    if ctx.ai_enabled and ctx.ai_analysis:
        mode_text = Text("Analysis: Static + AI (heuristic)", style="dim")
    else:
        mode_text = Text("Analysis: Static only", style="dim")
    summary_lines.append(mode_text)

    # Key findings in plain language
    findings = []
    if ctx.features:
        if ctx.features.remote_exec_count > 0:
            findings.append(
                f"⚠ Downloads and executes code from the internet ({ctx.features.remote_exec_count} instances)"
            )
        if ctx.features.obfuscation_score > 1:
            findings.append(f"⚠ Uses encoding/obfuscation techniques (score {ctx.features.obfuscation_score}/3)")
        if ctx.features.system_modification:
            findings.append("⚠ Modifies system directories")
        if ctx.metadata and ctx.metadata.orphan_status:
            findings.append("⚠ Package has no active maintainer")
        if ctx.trust_signals and ctx.trust_signals.out_of_date:
            findings.append("⚠ Package is marked out of date")

    if findings:
        summary_lines.append(Text())
        summary_lines.append(Text("Key concerns:", style="bold yellow"))
        for finding in findings[:5]:  # Limit to 5 most important
            summary_lines.append(Text(f"  {finding}"))
    elif ctx.risk_score and ctx.risk_score <= 20:
        summary_lines.append(Text())
        summary_lines.append(Text("✓ No major concerns detected", style="green"))

    parts.append(Panel(Group(*summary_lines), title="[bold]User Summary[/bold]", border_style="blue", expand=True))

    # ── TECHNICAL DETAILS (always shown, but can be expanded with --verbose) ──
    if ctx.score_breakdown:
        breakdown_table = Table(show_header=True, box=None, padding=(0, 2))
        breakdown_table.add_column("Factor", style="cyan", no_wrap=True)
        breakdown_table.add_column("Score", justify="right")

        if ctx.score_breakdown.remote_exec > 0:
            breakdown_table.add_row("Remote execution", str(ctx.score_breakdown.remote_exec))
        if ctx.score_breakdown.obfuscation > 0:
            breakdown_table.add_row("Obfuscation", str(ctx.score_breakdown.obfuscation))
        if ctx.score_breakdown.system_modification > 0:
            breakdown_table.add_row("System modification", str(ctx.score_breakdown.system_modification))
        if ctx.score_breakdown.external_calls > 0:
            breakdown_table.add_row("External calls", str(ctx.score_breakdown.external_calls))
        if ctx.score_breakdown.pkg_manager > 0:
            breakdown_table.add_row("Package managers", str(ctx.score_breakdown.pkg_manager))
        if ctx.score_breakdown.orphan_adopted > 0:
            breakdown_table.add_row("Orphan status", str(ctx.score_breakdown.orphan_adopted))
        if ctx.score_breakdown.maintainer_changed > 0:
            breakdown_table.add_row("Maintainer changed", str(ctx.score_breakdown.maintainer_changed))
        if ctx.score_breakdown.trust_penalty > 0:
            breakdown_table.add_row("Trust penalty", str(ctx.score_breakdown.trust_penalty))

        breakdown_table.add_row("", "")
        breakdown_table.add_row("Total (static)", str(ctx.score_breakdown.total_static), style="bold")

        if ctx.static_score is not None and ctx.ai_score is not None:
            breakdown_table.add_row("AI adjustment", f"+{ctx.ai_score - ctx.static_score}", style="dim")
            breakdown_table.add_row("Final score", str(ctx.risk_score), style="bold yellow")

        parts.append(Panel(breakdown_table, title="Score Breakdown", border_style="dim", expand=True))

    # Trust signals
    if ctx.trust_signals:
        trust_table = Table(show_header=False, box=None, padding=(0, 2))
        trust_table.add_column("Signal", style="cyan")
        trust_table.add_column("Value")
        trust_table.add_row("Package age", f"{ctx.trust_signals.package_age_days} days")
        trust_table.add_row("Maintainer history", ctx.trust_signals.maintainer_history)
        trust_table.add_row("Last update", f"{ctx.trust_signals.update_frequency_days} days ago")
        trust_table.add_row("Popular (>100 votes)", _bool_str(ctx.trust_signals.is_popular))
        trust_table.add_row("Out of date", _bool_str(ctx.trust_signals.out_of_date))
        parts.append(Panel(trust_table, title="Trust Signals", border_style="dim", expand=True))

    if ctx.ai_analysis:
        ai_lines = []

        notice = Text(
            "Note: AI analysis provides heuristic insights and may miss sophisticated attacks.", style="dim italic"
        )
        ai_lines.append(notice)
        ai_lines.append(Text())

        s = Text()
        s.append("Summary: ", style="bold")
        s.append(ctx.ai_analysis.summary)
        ai_lines.append(s)

        if ctx.ai_analysis.suspicious_patterns:
            ai_lines.append(Text())
            ai_lines.append(Text("Patterns: ", style="bold"))
            for p in ctx.ai_analysis.suspicious_patterns:
                ai_lines.append(Text(f"  • {p}", style="yellow"))

        parts.append(Panel(Group(*ai_lines), title="AI Analysis (Heuristic)", border_style="dim", expand=True))

    # Verbose details
    if verbose and ctx.features and ctx.metadata:
        verbose_table = Table(show_header=False, box=None, padding=(0, 2))
        verbose_table.add_column("Signal", style="cyan")
        verbose_table.add_column("Value")
        verbose_table.add_row("Remote exec count", str(ctx.features.remote_exec_count))
        verbose_table.add_row("External calls", str(ctx.features.external_calls))
        verbose_table.add_row("Package managers", ", ".join(ctx.features.package_manager_usage) or "-")
        verbose_table.add_row("Obfuscation score", f"{ctx.features.obfuscation_score}/3")
        verbose_table.add_row("System modification", _bool_str(ctx.features.system_modification))
        verbose_table.add_row("Maintainer", ctx.metadata.maintainer)
        verbose_table.add_row("Votes", str(ctx.metadata.votes))
        verbose_table.add_row("Popularity", f"{ctx.metadata.popularity:.2f}")
        parts.append(Panel(verbose_table, title="Detailed Signals (--verbose)", border_style="dim", expand=True))

    if ctx.errors:
        err_lines = []
        for err in ctx.errors:
            if err.recoverable:
                style = "yellow"
            else:
                style = "red"
            err_lines.append(Text(f"[{err.code}] {err.message}", style=style))
        parts.append(Panel(Group(*err_lines), title="Warnings & Errors", border_style="red", expand=True))

    return Group(*parts)
