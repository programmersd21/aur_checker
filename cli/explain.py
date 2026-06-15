import sys
import json
import typer
from cli.root import app, state
from core.context import PipelineContext, FeatureSet, Metadata
from ai.client import analyze_with_gemini
from output.json import format_json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


@app.command("explain", help="Run AI analysis on a structured JSON analysis result.")
def explain_command(input_file: str = typer.Option(..., "--input", help="Input JSON file matching AI input contract")):
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        features = FeatureSet(**data.get("features", {}))
        metadata = Metadata(**data.get("metadata", {}))

        ctx_obj = PipelineContext(
            package=data.get("package", ""),
            features=features,
            metadata=metadata,
            risk_score=data.get("risk_score"),
            risk_level=data.get("risk_level"),
        )

        ctx_obj = analyze_with_gemini(ctx_obj)

        if state.json:
            console.print_json(format_json(ctx_obj))
        else:
            if ctx_obj.ai_analysis:
                table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
                table.add_column("Field", style="cyan", no_wrap=True)
                table.add_column("Value")
                table.add_row("Summary", ctx_obj.ai_analysis.summary)
                table.add_row("Patterns", ", ".join(ctx_obj.ai_analysis.suspicious_patterns))
                table.add_row("Surface", ctx_obj.ai_analysis.attack_surface)
                rationale_lines = "\n".join(f"  - {r}" for r in ctx_obj.ai_analysis.rationale)
                table.add_row("Rationale", rationale_lines)
                console.print(Panel(table, title="AI Analysis", border_style="dim", expand=True))
            else:
                console.print(
                    Panel(
                        "[red]AI Analysis failed or was disabled.[/red]", title="Error", border_style="red", expand=True
                    )
                )
                sys.exit(1)

    except Exception as e:
        console.print(Panel(f"[red]{str(e)}[/red]", title="Error", border_style="red", expand=True))
        sys.exit(1)

    sys.exit(0)
