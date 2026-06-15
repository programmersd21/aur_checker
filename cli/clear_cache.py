import sys
import shutil
from cli.root import app
from compat_platform.paths import get_cache_dir
from rich.console import Console
from rich.panel import Panel

console = Console()


@app.command("clear-cache", help="Delete all cached analysis results.")
def clear_cache_command():
    cache_dir = get_cache_dir()
    try:
        shutil.rmtree(cache_dir)
        console.print(
            Panel(f"[green]Cache cleared:[/green] {cache_dir}", title="Success", border_style="green", expand=True)
        )
    except FileNotFoundError:
        console.print(Panel("[yellow]Cache directory does not exist.[/yellow]", border_style="yellow", expand=True))
    except Exception as e:
        console.print(Panel(f"[red]Failed to clear cache: {e}[/red]", title="Error", border_style="red", expand=True))
        sys.exit(1)
    sys.exit(0)
