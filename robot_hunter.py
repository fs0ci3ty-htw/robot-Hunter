import argparse
from rich.console import Console
from .site_crawler import SmartCrawler
from console_manager import ConsoleManager
from .report_generator import ReportGenerator
import asyncio
import time
import logging
import os
import sys

# Configure basic logging for libraries that use it
# logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def display_banner(console):
    # Banner from instructions.md
    banner = r"""
██████╗  ██████╗ ██████╗  ██████╗ ████████╗   ██╗   ██╗██╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██╔══██╗██╔═══██╗╚══██╔══╝   ██║   ██║██║   ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ███████╗██████╔╝
██╔══██╗██║   ██║██╔══██╗██║   ██║   ██║      ██║   ██║██║   ██║   ██║   ╚════██║██╔══██╗
██║  ██║╚██████╔╝██████╔╝╚██████╔╝   ██║      ╚██████╔╝╚██████╔╝   ██║   ███████║██║  ██║
╚═╝  ╚═╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝       ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝
                                Version 1.1.0 - Advanced Web Recon & Analysis
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]\n", highlight=False)

def main():
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Robot Hunter - Advanced Web Reconnaissance and Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter, # Keep formatting
        epilog="Example: python robot_hunter.py https://example.com -d 3 -o report -v --rate-limit 5"
    )
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("-d", "--depth", type=int, default=2, metavar='N', help="Maximum crawl depth (default: 2)")
    parser.add_argument("-o", "--output", metavar='PREFIX', help="Output file prefix for JSON report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug output")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--rate-limit", type=int, default=10, metavar='RPS', help="Approx. requests per second for crawler (default: 10)")
    parser.add_argument("--timeout", type=int, default=30, metavar='SEC', help="Default navigation/request timeout in seconds (default: 30)")
    parser.add_argument("--interactsh-url", metavar='URL', help="Interactsh server URL for OOB testing (e.g., xyz.oast.me)")
    # Add more flags as needed: --proxy, --headers-file, --cookies-file, --skip-attacks, --attack-aggressiveness, etc.

    # Handle case where no arguments are given
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # --- Initialization ---
    console_manager = ConsoleManager(verbose=args.verbose, no_color=args.no_color)
    display_banner(console_manager.console) # Use the console instance from ConsoleManager

    # Setup Playwright logging level (optional)
    # os.environ["DEBUG"] = "pw:api" # Very verbose Playwright logs if needed

    console_manager.print_info(f"Target: [bold blue]{args.target}[/bold blue]")
    console_manager.print_info(f"Max Depth: {args.depth}, Rate Limit: ~{args.rate_limit}/s, Timeout: {args.timeout}s")
    if args.output:
        console_manager.print_info(f"Report Prefix: {args.output}")
    if args.interactsh_url:
        console_manager.print_info(f"Interactsh URL: {args.interactsh_url}")
    if args.verbose:
        console_manager.print_debug("Verbose mode enabled.")

    report_generator = ReportGenerator(console_manager)
    report_generator.set_scan_target(args.target)

    # Pass relevant args to crawler/engine
    crawler = SmartCrawler(
        console_manager=console_manager,
        report_generator=report_generator,
        max_depth=args.depth,
        rate_limit=args.rate_limit,
        interactsh_url=args.interactsh_url
        # Pass timeout if needed by crawler components
    )

    start_time = time.time()
    scan_status = "failed" # Default status

    # --- Run Scan ---
    try:
        asyncio.run(crawler.start_crawl(args.target))
        scan_status = "completed" # Set status if crawl finishes without error/interruption
        console_manager.print_success("Scan Crawling Phase Completed.")

    except KeyboardInterrupt:
        console_manager.print_warning("\nScan interrupted by user.")
        scan_status = "interrupted"
    except pw.Error as e:
         console_manager.print_error(f"A Playwright error occurred: {e}", fatal=True)
    except httpx.RequestError as e:
         console_manager.print_error(f"A network request error occurred: {e}", fatal=True)
    except Exception as e:
        console_manager.print_error(f"An unexpected error occurred during scan: {e}", fatal=False) # Don't exit fatally here, try reporting
        import traceback
        console_manager.console.print_exception(show_locals=args.verbose) # Print rich traceback

    finally:
        # --- Reporting Phase ---
        duration = time.time() - start_time
        console_manager.print_info(f"Scan finished in {duration:.2f} seconds.")

        report_generator.set_scan_status(scan_status)

        # Display summary on console
        summary = report_generator.generate_summary()
        console_manager.print_summary(summary)

        # Generate file report if requested
        if args.output:
             report_generator.generate_report(args.output)

        console_manager.print_info("Robot Hunter finished.")


if __name__ == "__main__":
    main()