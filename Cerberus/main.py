import argparse
import json
import os
import sys
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# Rich UI
# ---------------------------
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

# ---------------------------
# Recon Modules
# ---------------------------
from module.recon.host_discovery import ping_host
from module.recon.dns_resolver import resolve_dns
from module.recon.tcp_check import tcp_ping

# ---------------------------
# Port Scanning
# ---------------------------
from module.ports.port_scanner import scan_multiple_ports, grab_banner_enhanced
from module.ports.service_fingerprint import fingerprint_service

# ---------------------------
# CVE Database
# ---------------------------
from module.cve.cve_auto_fetcher import auto_cve_lookup

# ---------------------------
# Web Scanner
# ---------------------------
from module.web.xss_scanner import check_xss
from module.web.sql_scanner import check_sqli
from module.web.headers import check_headers
from module.web.admin_finder import find_admin_panels
from module.web.dir_enum import brute_force_dirs, load_wordlist

# ---------------------------
# Logging & PDF
# ---------------------------
from reporting.pdf_report import generate_pdf
from utils.logger import log_message


# ======================================================
# Helper utilities
# ======================================================
def timestamp():
    """Get current timestamp for file naming"""
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def display_banner():
    """Display Cerberus ASCII banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║                ╔═╗╔═╗╦═╗╔╗ ╔═╗╦═╗╦ ╦╔═╗                   ║
    ║                ║  ║╣ ╠╦╝╠╩╗║╣ ╠╦╝║ ║╚═╗                   ║
    ║                ╚═╝╚═╝╩╚═╚═╝╚═╝╩╚═╚═╝╚═╝                   ║
    ║                                                           ║
    ║        Professional Vulnerability Scanner v1.0            ║
    ║           Network & Web Security Assessment               ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")

def verify_authorization(target):
    """Verify user has authorization to scan target"""
    console.print(Panel.fit(
        "[bold red]⚠️  LEGAL WARNING[/]\n\n"
        f"You are about to scan: [yellow]{target}[/]\n\n"
        "• Unauthorized port scanning may be illegal in your jurisdiction\n"
        "• You must have explicit written permission from the target owner\n"
        "• Violating this may result in criminal prosecution\n"
        "• This tool is for authorized security testing only\n\n"
        "[bold]By continuing, you confirm you have proper authorization.[/]",
        title="⚖️  Authorization Required",
        border_style="red"
    ))
    
    response = console.input("\n[yellow]Type 'I ACCEPT' to continue:[/] ").strip()
    if response != "I ACCEPT":
        console.print("[red]❌ Scan aborted - Authorization not confirmed[/]")
        append_log(f"Scan aborted - Authorization not confirmed for {target}")
        sys.exit(1)
    
    append_log(f"Authorization confirmed for target: {target}")
    console.print("[green]✓ Authorization confirmed[/]\n")

def interactive(args):
    """Interactive mode for getting user input"""
    console.print("\n[bold cyan]=== Cerberus Interactive Mode ===[/]")

    if not args.target:
        args.target = console.input("[yellow]Enter target IP/domain:[/] ").strip()
        if not args.target:
            console.print("[red]Error: Target is required![/]")
            sys.exit(1)

    if not args.url:
        val = console.input("[yellow]Enter target URL for web scan (or press Enter to skip):[/] ").strip()
        args.url = val if val else None

    if not args.wordlist and args.url:
        use_default = console.input("[yellow]Use default wordlist for directory scan? (y/n):[/] ").strip().lower()
        if use_default == 'y':
            args.wordlist = "wordlists/directory-list.txt"

    return args


def create_output_dirs():
    """Create necessary output directories"""
    try:
        os.makedirs("outputs", exist_ok=True)
        console.print("[green]✓[/] Output directories ready")
    except Exception as e:
        console.print(f"[red]Error creating directories: {e}[/]")


# ======================================================
# Network + Port Scan with Progress Bar
# ======================================================
def run_port_scan(ip):
    """Run port scan with progress tracking"""
    console.rule("[bold cyan]PORT SCAN & SERVICE DETECTION")

    port_list = [21, 22, 23, 25, 53, 80, 110, 143, 139, 443, 445, 3306, 3389, 5432, 8080, 8443]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        # Port scanning
        scan_task = progress.add_task("[cyan]Scanning ports...", total=len(port_list))
        open_ports = scan_multiple_ports(ip, port_list)
        progress.update(scan_task, completed=len(port_list))

        results = []

        if not open_ports:
            console.print("[yellow]⚠ No open ports detected[/]")
            return results

        # Banner grabbing and fingerprinting
        banner_task = progress.add_task("[cyan]Analyzing services...", total=len(open_ports))
        
        for p in open_ports:
            try:
                banner = grab_banner_enhanced(ip, p)
                fingerprint = fingerprint_service(banner)
                
                # CVE lookup
                cves = []
                if fingerprint["service"] != "unknown" and fingerprint["version"] != "unknown":
                    try:
                        cves = auto_cve_lookup(fingerprint["service"], fingerprint["version"])
                    except Exception as e:
                        console.print(f"[yellow]Warning: CVE lookup failed for port {p}: {e}[/]")

                results.append({
                    "port": p,
                    "banner": banner,
                    "service": fingerprint["service"],
                    "version": fingerprint["version"],
                    "cves": cves if isinstance(cves, list) else []
                })

                # Display finding
                cve_count = len(cves) if isinstance(cves, list) else 0
                status = "[red]●[/]" if cve_count > 0 else "[green]●[/]"
                console.print(
                    f"{status} Port [bold]{p}[/bold] - {fingerprint['service']} "
                    f"{fingerprint['version']} ({cve_count} CVEs)"
                )

            except Exception as e:
                console.print(f"[yellow]Warning: Error processing port {p}: {e}[/]")
            
            progress.update(banner_task, advance=1)

    return results


# ======================================================
# Recon Phase with Progress
# ======================================================
def run_recon(target):
    """Run reconnaissance with progress tracking"""
    console.rule("[bold blue]RECONNAISSANCE PHASE")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Running reconnaissance...", total=3)
        
        # Host reachability
        progress.update(task, description="[cyan]Checking host reachability...")
        reachable = False
        try:
            reachable = ping_host(target)
        except Exception as e:
            console.print(f"[yellow]Warning: Ping check failed: {e}[/]")
        progress.advance(task)
        
        # DNS resolution
        progress.update(task, description="[cyan]Resolving DNS...")
        dns_info = {}
        try:
            dns_info = resolve_dns(target)
        except Exception as e:
            console.print(f"[yellow]Warning: DNS resolution failed: {e}[/]")
        progress.advance(task)
        
        # TCP check
        progress.update(task, description="[cyan]TCP connectivity check...")
        tcp_80 = False
        try:
            tcp_80 = tcp_ping(target, 80)
        except Exception as e:
            console.print(f"[yellow]Warning: TCP check failed: {e}[/]")
        progress.advance(task)

    recon = {
        "reachable": reachable,
        "dns": dns_info,
        "tcp_port_80": tcp_80
    }

    # Display recon summary
    table = Table(title="Reconnaissance Results", box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")
    
    table.add_row("Host Reachable", "✓ Yes" if reachable else "✗ No")
    table.add_row("DNS Resolved", "✓ Yes" if dns_info.get('ip') else "✗ No")
    table.add_row("TCP Port 80", "✓ Open" if tcp_80 else "✗ Closed")
    
    console.print(table)

    return recon


# ======================================================
# Threaded Web Scanner with Progress
# ======================================================
def run_web_scan(url, wordlist=None, workers=10, rate=0.0):
    """Run web vulnerability scan with progress tracking"""
    console.rule("[bold green]WEB VULNERABILITY SCAN")
    
    # Safety warning
    console.print(Panel.fit(
        "[yellow]⚠ Warning: Web vulnerability testing may affect target systems.\n"
        "Ensure you have proper authorization before proceeding.[/]",
        title="[bold red]Legal Notice[/]",
        border_style="red"
    ))
    
    if not console.input("\n[yellow]Continue? (yes/no):[/] ").strip().lower() == "yes":
        console.print("[red]Web scan cancelled by user.[/]")
        return {}

    tasks = {
        "xss": (check_xss, (url,), "XSS Detection"),
        "sqli": (check_sqli, (url,), "SQL Injection"),
        "headers": (check_headers, (url,), "Security Headers"),
        "admin_panels": (find_admin_panels, (url,), "Admin Panels"),
        "directories": (brute_force_dirs, (url, wordlist, workers, 3.5, rate), "Directory Enum")
    }

    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        
        main_task = progress.add_task("[cyan]Running web scans...", total=len(tasks))
        
        with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
            future_map = {ex.submit(func, *args): (name, desc) for name, (func, args, desc) in tasks.items()}

            for fut in as_completed(future_map):
                name, desc = future_map[fut]
                try:
                    results[name] = fut.result()
                    console.print(f"[green]✓[/] Completed: {desc}")
                except Exception as e:
                    results[name] = {"error": str(e)}
                    console.print(f"[red]✗[/] Failed: {desc} - {e}")
                
                progress.advance(main_task)

    return results


# ======================================================
# Scan Summary Table
# ======================================================
def display_scan_summary(data):
    """Display comprehensive scan summary"""
    console.rule("[bold magenta]SCAN SUMMARY")
    
    # Count vulnerabilities
    total_cves = 0
    critical = high = medium = low = 0
    
    for port in data.get("ports", []):
        cves = port.get("cves", [])
        total_cves += len(cves)
        for cve in cves:
            sev = str(cve.get("severity", "")).upper()
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            elif sev == "LOW":
                low += 1

    # Summary table
    summary = Table(title="Vulnerability Summary", box=box.DOUBLE_EDGE)
    summary.add_column("Category", style="cyan", no_wrap=True)
    summary.add_column("Count", justify="right", style="yellow")
    summary.add_column("Status", justify="center")

    summary.add_row("Open Ports", str(len(data.get("ports", []))), 
                    "[green]✓[/]" if data.get("ports") else "[yellow]⚠[/]")
    summary.add_row("Total CVEs", str(total_cves), 
                    "[red]![/]" if total_cves > 0 else "[green]✓[/]")
    summary.add_row("Critical", str(critical), 
                    "[red]![/]" if critical > 0 else "[green]✓[/]")
    summary.add_row("High", str(high), 
                    "[red]![/]" if high > 0 else "[green]✓[/]")
    summary.add_row("Medium", str(medium), 
                    "[yellow]⚠[/]" if medium > 0 else "[green]✓[/]")
    summary.add_row("Low", str(low), 
                    "[blue]i[/]" if low > 0 else "[green]✓[/]")

    console.print(summary)

    # Web findings
    if data.get("web"):
        web_table = Table(title="Web Security Findings", box=box.ROUNDED)
        web_table.add_column("Test", style="cyan")
        web_table.add_column("Result", style="yellow")
        
        web_data = data["web"]
        
        # XSS
        xss_found = web_data.get("xss", {}).get("xss", False)
        web_table.add_row("XSS", "[red]Vulnerable[/]" if xss_found else "[green]Secure[/]")
        
        # SQLi
        sqli_found = web_data.get("sqli", {}).get("sqli", False)
        web_table.add_row("SQL Injection", "[red]Vulnerable[/]" if sqli_found else "[green]Secure[/]")
        
        # Headers
        headers_secure = web_data.get("headers", {}).get("secure", True)
        web_table.add_row("Security Headers", "[green]Secure[/]" if headers_secure else "[yellow]Missing[/]")
        
        console.print(web_table)


# ======================================================
# JSON & Logging
# ======================================================
def save_json(data):
    """Save scan results to JSON"""
    try:
        os.makedirs("outputs", exist_ok=True)
        file = f"outputs/cerberus_output_{timestamp()}.json"

        with open(file, "w") as f:
            json.dump(data, f, indent=4)

        console.print(f"[green]✓ JSON saved → {file}[/]")
        return file
    except Exception as e:
        console.print(f"[red]Error saving JSON: {e}[/]")
        return None


def append_log(text):
    """Append to log file"""
    try:
        log_message(text)
    except Exception as e:
        console.print(f"[yellow]Warning: Logging error: {e}[/]")


# ======================================================
# Main Function
# ======================================================
def main():
    """Main entry point"""
    display_banner()
    
    parser = argparse.ArgumentParser(
        description="Cerberus - Professional Vulnerability Scanner",
        epilog="""
Examples:
  python main.py --target 192.168.1.1
  python main.py --target example.com --url https://example.com
  python main.py --target example.com --url https://example.com --wordlist custom.txt
        """
    )

    parser.add_argument("--target", help="Target IP/Domain")
    parser.add_argument("--url", help="Target URL for Web Scan (https://example.com)")
    parser.add_argument("--wordlist", help="Wordlist for directory brute force")
    parser.add_argument("--workers", type=int, default=15, help="Number of worker threads")
    parser.add_argument("--rate", type=float, default=0.0, help="Rate limit (seconds between requests)")
    parser.add_argument("--no-interactive", action="store_true", help="Disable interactive mode")
    parser.add_argument("--skip-auth-check", action="store_true", help="Skip authorization verification (use with caution)")

    args = parser.parse_args()

    # Interactive mode
    if not args.no_interactive:
        args = interactive(args)

    if not args.skip_auth_check:
        verify_authorization(args.target)
        
    # Create output directories
    create_output_dirs()

    # Start logging
    append_log("=== NEW CERBERUS SCAN STARTED ===")
    append_log(f"Target: {args.target}")

    try:
        # -----------------------------
        # Recon Phase
        # -----------------------------
        recon = run_recon(args.target)

        # -----------------------------
        # Port Scan + CVE Lookup
        # -----------------------------
        ports = run_port_scan(args.target)

        # -----------------------------
        # Web Scan (optional)
        # -----------------------------
        web_results = {}

        if args.url:
            # Load wordlist safely
            wl = None
            if args.wordlist:
                if os.path.exists(args.wordlist):
                    wl = load_wordlist(args.wordlist, limit=200)
                    if wl:
                        console.print(f"[green]✓[/] Loaded {len(wl)} entries from wordlist")
                else:
                    console.print(f"[yellow]Warning: Wordlist not found: {args.wordlist}[/]")
        
            web_results = run_web_scan(args.url, wl, args.workers, args.rate)

        # -----------------------------
        # Collect Data
        # -----------------------------
        data = {
            "target": args.target,
            "url": args.url,
            "timestamp": timestamp(),
            "recon": recon,
            "ports": ports,
            "web": web_results
        }

        # -----------------------------
        # Display Summary
        # -----------------------------
        display_scan_summary(data)

        # -----------------------------
        # Save Outputs
        # -----------------------------
        console.rule("[bold cyan]GENERATING REPORTS")
        
        # Save JSON
        json_file = save_json(data)
        if json_file:
            append_log(f"JSON saved as {json_file}")

        # Generate PDF
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Generating PDF report...", total=None)
                pdf_file = generate_pdf(data)
                progress.update(task, completed=True)
            
            console.print(f"[green]✓ PDF report saved → {pdf_file}[/]")
            append_log(f"PDF saved as {pdf_file}")
        except Exception as e:
            console.print(f"[red]✗ PDF generation failed: {e}[/]")
            append_log(f"PDF generation error: {e}")
            pdf_file = None

        # -----------------------------
        # Final Summary
        # -----------------------------
        console.rule("[bold green]SCAN COMPLETE", style="green")
        
        final_table = Table(box=box.DOUBLE_EDGE, show_header=False, title="[bold green]Output Files[/]")
        final_table.add_column("Type", style="cyan")
        final_table.add_column("Location", style="yellow")
        
        if json_file:
            final_table.add_row("JSON Report", json_file)
        if pdf_file:
            final_table.add_row("PDF Report", pdf_file)
        final_table.add_row("Log File", "outputs/cerberus_log.txt")
        
        console.print(final_table)
        console.print("\n[bold green]Thank you for using Cerberus! 🛡️[/]\n")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        append_log("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Fatal error: {e}[/]")
        append_log(f"Fatal error: {e}")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
