import sys
import argparse
import logging
from collections import defaultdict, Counter
from parser.engine import parse_line

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich.markup import escape

console = Console()

def setup_logger(debug_mode: bool = False):
    """Configures logging: Rich for console, File for storage."""
    log_level = logging.DEBUG if debug_mode else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=debug_mode)]
    )
    logger = logging.getLogger("LogGuarder")
    
    file_handler = logging.FileHandler("security_events.log")
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    file_handler.setLevel(logging.DEBUG) 
    logger.addHandler(file_handler)
    
    return logger

def generate_dashboard(ip_stats: dict, user_stats: dict, threshold: int, skipped: int):
    """Creates a dual-table dashboard for the final report."""
    console.print("\n")

    ip_table = Table(title=" Top Attackers (Source IPs)", show_header=True, header_style="bold red")
    ip_table.add_column("IP Address", style="cyan")
    ip_table.add_column("Failures", justify="right")
    ip_table.add_column("Status", justify="center")

    found_threat = False
    for ip, count in sorted(ip_stats.items(), key=lambda x: x[1], reverse=True):
        if count >= threshold:
            status = "[bold red]THREAT[/bold red]"
            count_display = f"[red]{count}[/red]"
            found_threat = True
        else:
            status = "[green]Monitor[/green]"
            count_display = str(count)
        
        if count > 0:
            ip_table.add_row(ip, count_display, status)

    if not found_threat:
        console.print("[green]No IP threats detected above threshold.[/green]")
    else:
        console.print(ip_table)

    console.print("\n")
    user_table = Table(title=" Most Targeted Accounts", show_header=True, header_style="bold yellow")
    user_table.add_column("Username", style="white")
    user_table.add_column("Attack Attempts", justify="right", style="yellow")
    
    for user, count in user_stats.most_common(5):
        safe_user = escape(user) if user else "[italic dim]<empty>[/italic dim]"
        user_table.add_row(safe_user, str(count))
        
    console.print(user_table)
    
    if skipped > 0:
        console.print(f"\n[italic dim]Note: {skipped} malformed lines were skipped during parsing.[/italic dim]")

def main():
    parser = argparse.ArgumentParser(description="LogGuarder: Linux Security Log Analyzer")
    parser.add_argument("logfile", help="Path to the log file (e.g., /var/log/auth.log)")
    parser.add_argument("--threshold", "-t", type=int, default=5, help="Failure count to trigger alert (default: 5)")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug mode for verbose output")
    
    args = parser.parse_args()

    logger = setup_logger(args.debug)
    failed_attempts = defaultdict(int)
    targeted_users = Counter()
    skipped_lines = 0
    
    logger.info(f"Starting analysis on: [bold]{args.logfile}[/bold] (Threshold: {args.threshold})")

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()
            if not first_line:
                logger.warning("File is empty.")
                return
            f.seek(0)

            for line in f:
                entry = parse_line(line)
                
                if not entry:
                    skipped_lines += 1
                    logger.debug(f"Skipped malformed line: {line.strip()[:50]}...")
                    continue
                
                if entry.status.lower() == "failed":
                    failed_attempts[entry.ip_address] += 1
                    targeted_users[entry.username] += 1
                    
                    if failed_attempts[entry.ip_address] == args.threshold:
                        logger.warning(f"High failure rate detected from {entry.ip_address}!")

        generate_dashboard(failed_attempts, targeted_users, args.threshold, skipped_lines)

    except FileNotFoundError:
        logger.critical(f"[bold red]Error:[/bold red] File '{args.logfile}' not found.")
        sys.exit(1)
    except PermissionError:
        logger.critical(f"[bold red]Permission Denied:[/bold red] You do not have permission to read '{args.logfile}'.\nTry running with: [bold]sudo python3 main.py {args.logfile}[/bold]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user. Exiting...[/yellow]")
        sys.exit(0)

if __name__ == "__main__":
    main()