import sys
import logging
from collections import defaultdict
from parser.engine import parse_line

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

LOG_OUTPUT_FILE = "security_events.log"
ALERT_THRESHOLD = 5

console = Console()

def setup_logger():
    """Configures logging: Rich for console, File for storage."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)]
    )
    logger = logging.getLogger("LogGuarder")
    
    file_handler = logging.FileHandler(LOG_OUTPUT_FILE)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    return logger

def generate_report(stats: dict):
    """Creates a beautiful table for the final report."""
    table = Table(title="Security Analysis Report", show_header=True, header_style="bold magenta")
    
    table.add_column("IP Address", style="cyan")
    table.add_column("Failed Attempts", justify="right")
    table.add_column("Status", justify="center")

    for ip, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        if count >= ALERT_THRESHOLD:
            status = "[bold red]THREAT DETECTED[/bold red]"
            count_display = f"[red]{count}[/red]"
        else:
            status = "[green]Safe[/green]"
            count_display = str(count)
            
        table.add_row(ip, count_display, status)

    console.print("\n")
    console.print(table)

def main():
    if len(sys.argv) < 2:
        console.print("[bold red]Usage:[/bold red] python3 main.py <path_to_log>")
        sys.exit(1)

    log_file = sys.argv[1]
    logger = setup_logger()
    failed_attempts = defaultdict(int)
    
    logger.info(f"Starting analysis on: [bold]{log_file}[/bold]")

    try:
        with open(log_file, "r") as f:
            for line in f:
                entry = parse_line(line)
                if not entry:
                    continue
                
                if entry.status.lower() == "failed":
                    failed_attempts[entry.ip_address] += 1
                    
                    if failed_attempts[entry.ip_address] == ALERT_THRESHOLD:
                        logger.warning(f"High failure rate detected from {entry.ip_address}!")

        generate_report(failed_attempts)

    except FileNotFoundError:
        logger.critical(f"File not found: {log_file}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user.[/yellow]")

if __name__ == "__main__":
    main()
