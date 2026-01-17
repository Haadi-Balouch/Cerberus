import argparse
import json
import os
import sys
# Force UTF-8 encoding for Windows consoles
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ---------------------------
# Rich UI
# ---------------------------
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box
from rich.prompt import Confirm, Prompt

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
try:
    from reporting.pdf_report import generate_pdf
except ImportError:
    def generate_pdf(results):
        print("Warning: PDF generation disabled (missing reportlab)")
        return None
from utils.logger import log_message


# ======================================================
# SCAN PROFILES & MODULE DEFINITIONS
# ======================================================

class ModuleRisk:
    """Module risk level classification"""
    SAFE = "SAFE"
    MODERATE = "MODERATE"
    AGGRESSIVE = "AGGRESSIVE"

class ScanModule:
    """Defines a security scan module"""
    def __init__(self, name, description, risk_level, category, enabled_by_default=False):
        self.name = name
        self.description = description
        self.risk_level = risk_level
        self.category = category
        self.enabled_by_default = enabled_by_default

# Define all available modules
WEB_MODULES = {
    "headers": ScanModule(
        "headers",
        "HTTP Security Headers Analysis",
        ModuleRisk.SAFE,
        "web",
        enabled_by_default=True
    ),
    "admin": ScanModule(
        "admin",
        "Admin Panel Discovery",
        ModuleRisk.SAFE,
        "web",
        enabled_by_default=True
    ),
    "xss": ScanModule(
        "xss",
        "Cross-Site Scripting (XSS) Detection",
        ModuleRisk.MODERATE,
        "web",
        enabled_by_default=False
    ),
    "sqli": ScanModule(
        "sqli",
        "SQL Injection Detection",
        ModuleRisk.AGGRESSIVE,
        "web",
        enabled_by_default=False
    ),
    "dir": ScanModule(
        "dir",
        "Directory Enumeration",
        ModuleRisk.MODERATE,
        "web",
        enabled_by_default=False
    )
}

NETWORK_MODULES = {
    "recon": ScanModule(
        "recon",
        "Host Discovery & DNS Resolution",
        ModuleRisk.SAFE,
        "network",
        enabled_by_default=True
    ),
    "ports": ScanModule(
        "ports",
        "Port Scanning & Service Detection",
        ModuleRisk.SAFE,
        "network",
        enabled_by_default=True
    ),
    "cve": ScanModule(
        "cve",
        "CVE Vulnerability Lookup",
        ModuleRisk.SAFE,
        "network",
        enabled_by_default=True
    )
}

# Scan Profiles
SCAN_PROFILES = {
    "quick": {
        "name": "Quick Scan",
        "description": "Fast, non-intrusive reconnaissance",
        "modules": ["headers", "admin", "recon", "ports"]
    },
    "standard": {
        "name": "Standard Scan",
        "description": "Balanced security assessment",
        "modules": ["headers", "admin", "xss", "recon", "ports", "cve"]
    },
    "aggressive": {
        "name": "Aggressive Scan",
        "description": "Comprehensive vulnerability testing",
        "modules": ["headers", "admin", "xss", "sqli", "dir", "recon", "ports", "cve"]
    },
    "web-only": {
        "name": "Web Application Scan",
        "description": "Focus on web vulnerabilities",
        "modules": ["headers", "admin", "xss", "sqli", "dir"]
    },
    "network-only": {
        "name": "Network Infrastructure Scan",
        "description": "Focus on network vulnerabilities",
        "modules": ["recon", "ports", "cve"]
    }
}


# ======================================================
# TARGET DETECTION & CLASSIFICATION
# ======================================================

class TargetType:
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"

def detect_target_type(target):
    """Auto-detect target type"""
    target = target.strip()
    
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        return TargetType.URL, target
    
    # Check if it's an IP address
    parts = target.replace(':', '').split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return TargetType.IP, target
    
    # Otherwise treat as domain
    return TargetType.DOMAIN, target

def extract_hostname(target, target_type):
    """Extract hostname from target"""
    if target_type == TargetType.URL:
        parsed = urlparse(target)
        return parsed.netloc or parsed.path
    return target


# ======================================================
# AUTHORIZATION & RISK WARNINGS
# ======================================================

def verify_authorization(target):
    """Verify user has authorization to scan target"""
    console.print(Panel.fit(
        "[bold red]⚠️  LEGAL WARNING[/]\n\n"
        f"You are about to scan: [yellow]{target}[/]\n\n"
        "• Unauthorized security scanning may be illegal in your jurisdiction\n"
        "• You must have explicit written permission from the target owner\n"
        "• Violating this may result in criminal prosecution\n"
        "• This tool is for authorized security testing only\n\n"
        "[bold]By continuing, you confirm you have proper authorization.[/]",
        title="⚖️  Authorization Required",
        border_style="red"
    ))
    
    if not Confirm.ask("\n[yellow]Do you have written authorization to scan this target?[/]", default=False):
        console.print("[red]✗ Scan aborted - Authorization not confirmed[/]")
        append_log(f"Scan aborted - Authorization not confirmed for {target}")
        sys.exit(1)
    
    append_log(f"Authorization confirmed for target: {target}")
    console.print("[green]✓ Authorization confirmed[/]\n")

def show_risk_warning(modules):
    """Show risk warning for aggressive modules"""
    aggressive_modules = [m for m in modules if get_module(m).risk_level == ModuleRisk.AGGRESSIVE]
    moderate_modules = [m for m in modules if get_module(m).risk_level == ModuleRisk.MODERATE]
    
    if not aggressive_modules and not moderate_modules:
        return True
    
    warning_text = "[bold yellow]⚠️  RISK WARNING[/]\n\n"
    warning_text += "The following modules will perform intrusive tests:\n\n"
    
    if aggressive_modules:
        warning_text += "[bold red]AGGRESSIVE (High Risk):[/]\n"
        for mod in aggressive_modules:
            module = get_module(mod)
            warning_text += f"  • {module.description}\n"
        warning_text += "\n"
    
    if moderate_modules:
        warning_text += "[bold yellow]MODERATE (Medium Risk):[/]\n"
        for mod in moderate_modules:
            module = get_module(mod)
            warning_text += f"  • {module.description}\n"
    
    warning_text += "\n[bold]These tests may:\n"
    warning_text += "• Generate significant traffic\n"
    warning_text += "• Trigger security alerts\n"
    warning_text += "• Affect system performance\n"
    warning_text += "• Be logged by target systems[/]"
    
    console.print(Panel.fit(warning_text, title="[bold red]Risk Assessment[/]", border_style="yellow"))
    
    if not Confirm.ask("\n[yellow]Do you want to proceed with these tests?[/]", default=False):
        console.print("[yellow]⚠ Aggressive modules disabled[/]")
        return False
    
    return True


# ======================================================
# MODULE MANAGEMENT
# ======================================================

def get_module(module_name):
    """Get module by name"""
    if module_name in WEB_MODULES:
        return WEB_MODULES[module_name]
    if module_name in NETWORK_MODULES:
        return NETWORK_MODULES[module_name]
    return None

def get_modules_for_profile(profile_name):
    """Get modules for a scan profile"""
    if profile_name in SCAN_PROFILES:
        return SCAN_PROFILES[profile_name]["modules"]
    return []

def filter_modules_by_target(modules, target_type):
    """Filter modules based on target type"""
    filtered = []
    
    for mod in modules:
        module = get_module(mod)
        if not module:
            continue
        
        # Web modules require URL
        if module.category == "web" and target_type == TargetType.IP:
            continue
        
        # Network modules work with all types
        filtered.append(mod)
    
    return filtered

def display_scan_plan(target, target_type, modules):
    """Display what will be scanned"""
    table = Table(title="Scan Plan", box=box.DOUBLE_EDGE)
    table.add_column("Module", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Risk", style="yellow")
    table.add_column("Status", justify="center")
    
    for mod in modules:
        module = get_module(mod)
        if not module:
            continue
        
        risk_color = {
            ModuleRisk.SAFE: "green",
            ModuleRisk.MODERATE: "yellow",
            ModuleRisk.AGGRESSIVE: "red"
        }.get(module.risk_level, "white")
        
        status = "[green]✓[/]"
        
        table.add_row(
            module.description,
            f"[dim]{module.name}[/]",
            f"[{risk_color}]{module.risk_level}[/]",
            status
        )
    
    console.print(table)
    
    # Show disabled modules if any
    all_modules = list(WEB_MODULES.keys()) + list(NETWORK_MODULES.keys())
    disabled = [m for m in all_modules if m not in modules]
    
    if disabled:
        filtered_disabled = filter_modules_by_target(disabled, target_type)
        if filtered_disabled:
            console.print("\n[dim]Disabled modules:[/]")
            for mod in filtered_disabled:
                module = get_module(mod)
                if module:
                    console.print(f"  [dim]✗ {module.description}[/]")


# ======================================================
# INTERACTIVE MODULE SELECTION
# ======================================================

def interactive_module_selection(target_type):
    """Let user select modules interactively"""
    console.print("\n[bold cyan]Available Scan Profiles:[/]\n")
    
    profile_table = Table(box=box.ROUNDED)
    profile_table.add_column("Profile", style="cyan")
    profile_table.add_column("Description", style="white")
    profile_table.add_column("Modules", style="yellow")
    
    for key, profile in SCAN_PROFILES.items():
        modules = filter_modules_by_target(profile["modules"], target_type)
        profile_table.add_row(
            f"[bold]{key}[/]",
            profile["description"],
            f"{len(modules)} modules"
        )
    
    console.print(profile_table)
    
    choice = Prompt.ask(
        "\n[yellow]Select scan profile[/]",
        choices=list(SCAN_PROFILES.keys()) + ["custom"],
        default="standard"
    )
    
    if choice == "custom":
        return custom_module_selection(target_type)
    
    modules = get_modules_for_profile(choice)
    modules = filter_modules_by_target(modules, target_type)
    
    return modules

def custom_module_selection(target_type):
    """Custom module selection"""
    console.print("\n[bold cyan]Custom Module Selection:[/]\n")
    
    selected = []
    
    # Web modules
    if target_type != TargetType.IP:
        console.print("[bold]Web Security Modules:[/]")
        for key, module in WEB_MODULES.items():
            risk_color = {
                ModuleRisk.SAFE: "green",
                ModuleRisk.MODERATE: "yellow",
                ModuleRisk.AGGRESSIVE: "red"
            }.get(module.risk_level, "white")
            
            if Confirm.ask(
                f"  [{risk_color}][{module.risk_level}][/] {module.description}",
                default=module.enabled_by_default
            ):
                selected.append(key)
    
    # Network modules
    console.print("\n[bold]Network Security Modules:[/]")
    for key, module in NETWORK_MODULES.items():
        if Confirm.ask(
            f"  [green][{module.risk_level}][/] {module.description}",
            default=module.enabled_by_default
        ):
            selected.append(key)
    
    return selected


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
    ║        Professional Vulnerability Scanner v2.0            ║
    ║           Network & Web Security Assessment               ║
    ║                Enterprise-Grade Security Framework        ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")

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
        
        scan_task = progress.add_task("[cyan]Scanning ports...", total=len(port_list))
        open_ports = scan_multiple_ports(ip, port_list)
        progress.update(scan_task, completed=len(port_list))

        results = []

        if not open_ports:
            console.print("[yellow]⚠  No open ports detected[/]")
            return results

        banner_task = progress.add_task("[cyan]Analyzing services...", total=len(open_ports))
        
        for p in open_ports:
            try:
                banner = grab_banner_enhanced(ip, p)
                fingerprint = fingerprint_service(banner)
                
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
        
        progress.update(task, description="[cyan]Checking host reachability...")
        reachable = False
        try:
            reachable = ping_host(target)
        except Exception as e:
            console.print(f"[yellow]Warning: Ping check failed: {e}[/]")
        progress.advance(task)
        
        progress.update(task, description="[cyan]Resolving DNS...")
        dns_info = {}
        try:
            dns_info = resolve_dns(target)
        except Exception as e:
            console.print(f"[yellow]Warning: DNS resolution failed: {e}[/]")
        progress.advance(task)
        
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

    table = Table(title="Reconnaissance Results", box=box.ROUNDED)
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="green")
    
    table.add_row("Host Reachable", "✓ Yes" if reachable else "✗ No")
    table.add_row("DNS Resolved", "✓ Yes" if dns_info.get('ip') else "✗ No")
    table.add_row("TCP Port 80", "✓ Open" if tcp_80 else "✗ Closed")
    
    console.print(table)

    return recon


# ======================================================
# Web Scanner with Progress
# ======================================================

def run_web_scan(url, enabled_modules, wordlist=None, workers=10, rate=0.0):
    """Run web vulnerability scan with selected modules"""
    console.rule("[bold green]WEB VULNERABILITY SCAN")
    
    tasks = {}
    
    if "headers" in enabled_modules:
        tasks["headers"] = (check_headers, (url,), "Security Headers")
    
    if "admin" in enabled_modules:
        tasks["admin_panels"] = (find_admin_panels, (url,), "Admin Panels")
    
    if "xss" in enabled_modules:
        tasks["xss"] = (check_xss, (url,), "XSS Detection")
    
    if "sqli" in enabled_modules:
        tasks["sqli"] = (check_sqli, (url,), "SQL Injection")
    
    if "dir" in enabled_modules:
        tasks["directories"] = (brute_force_dirs, (url, wordlist, workers, 3.5, rate), "Directory Enum")

    if not tasks:
        console.print("[yellow]No web modules enabled[/]")
        return {}

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

    if data.get("web"):
        web_table = Table(title="Web Security Findings", box=box.ROUNDED)
        web_table.add_column("Test", style="cyan")
        web_table.add_column("Result", style="yellow")
        
        web_data = data["web"]
        
        xss_found = web_data.get("xss", {}).get("xss", False)
        web_table.add_row("XSS", "[red]Vulnerable[/]" if xss_found else "[green]Secure[/]")
        
        sqli_found = web_data.get("sqli", {}).get("sqli", False)
        web_table.add_row("SQL Injection", "[red]Vulnerable[/]" if sqli_found else "[green]Secure[/]")
        
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
        description="Cerberus - Professional Vulnerability Scanner v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Profiles:
  quick        Fast, non-intrusive reconnaissance
  standard     Balanced security assessment (default)
  aggressive   Comprehensive vulnerability testing
  web-only     Focus on web vulnerabilities
  network-only Focus on network vulnerabilities
  custom       Manual module selection

Examples:
  # Standard scan with auto-detection
  python main.py --target 192.168.1.1
  
  # Quick web application scan
  python main.py --target https://example.com --profile quick
  
  # Aggressive scan with all modules
  python main.py --target example.com --profile aggressive
  
  # Custom module selection
  python main.py --target example.com --profile custom
  
  # Network-only scan
  python main.py --target 192.168.1.1 --profile network-only
  
  # Specific modules
  python main.py --target https://example.com --modules xss,sqli,headers
        """
    )

    parser.add_argument("--target", required=True, help="Target IP/Domain/URL")
    parser.add_argument("--profile", choices=list(SCAN_PROFILES.keys()) + ["custom"], 
                       default="standard", help="Scan profile (default: standard)")
    parser.add_argument("--modules", help="Comma-separated list of modules (overrides profile)")
    parser.add_argument("--wordlist", help="Wordlist for directory brute force")
    parser.add_argument("--workers", type=int, default=15, help="Number of worker threads")
    parser.add_argument("--rate", type=float, default=0.0, help="Rate limit (seconds between requests)")
    parser.add_argument("--skip-auth", action="store_true", help="Skip authorization check (dangerous!)")
    parser.add_argument("--dry-run", action="store_true", help="Show scan plan without executing")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF report generation")

    args = parser.parse_args()

    # Detect target type
    target_type, normalized_target = detect_target_type(args.target)
    
    console.print(f"\n[cyan]Target detected:[/] [bold]{normalized_target}[/]")
    console.print(f"[cyan]Target type:[/] [bold]{target_type.upper()}[/]\n")

    # Authorization check
    if not args.skip_auth:
        verify_authorization(normalized_target)
    else:
        console.print("[yellow]⚠ Skipping authorization check - use with caution![/]\n")
        
    # Create output directories
    create_output_dirs()

    # Determine modules to run
    if args.modules:
        # User specified modules directly
        enabled_modules = [m.strip() for m in args.modules.split(",")]
    else:
        # Use profile
        enabled_modules = get_modules_for_profile(args.profile)
    
    # Filter modules based on target type
    enabled_modules = filter_modules_by_target(enabled_modules, target_type)
    
    if not enabled_modules:
        console.print("[red]Error: No valid modules for this target type![/]")
        sys.exit(1)
    
    # Display scan plan
    console.rule("[bold cyan]SCAN CONFIGURATION")
    display_scan_plan(normalized_target, target_type, enabled_modules)
    
    # Risk warning for aggressive modules
    if not show_risk_warning(enabled_modules):
        # Remove aggressive modules if user declined
        enabled_modules = [m for m in enabled_modules if get_module(m).risk_level != ModuleRisk.AGGRESSIVE]
        console.print("\n[yellow]Scan plan updated - aggressive modules removed[/]\n")
        display_scan_plan(normalized_target, target_type, enabled_modules)
    
    # Dry run mode
    if args.dry_run:
        console.print("\n[bold yellow]DRY RUN MODE[/] - No actual scanning will be performed\n")
        console.print("[green]✓ Scan plan validated successfully[/]")
        sys.exit(0)
    
    # Confirm execution
    if not Confirm.ask("\n[yellow]Proceed with scan?[/]", default=True):
        console.print("[yellow]Scan cancelled by user[/]")
        sys.exit(0)

    # Start logging
    append_log("=== NEW CERBERUS SCAN STARTED ===")
    append_log(f"Target: {normalized_target} (Type: {target_type})")
    append_log(f"Profile: {args.profile}")
    append_log(f"Modules: {', '.join(enabled_modules)}")

    try:
        # Extract hostname for network operations
        hostname = extract_hostname(normalized_target, target_type)
        
        # Initialize results
        recon = {}
        ports = []
        web_results = {}
        
        # -----------------------------
        # Recon Phase
        # -----------------------------
        if "recon" in enabled_modules:
            recon = run_recon(hostname)

        # -----------------------------
        # Port Scan + CVE Lookup
        # -----------------------------
        if "ports" in enabled_modules:
            ports = run_port_scan(hostname)

        # -----------------------------
        # Web Scan
        # -----------------------------
        web_modules = [m for m in enabled_modules if m in WEB_MODULES]
        
        if web_modules and target_type != TargetType.IP:
            # Load wordlist if directory enumeration is enabled
            wl = None
            if "dir" in web_modules and args.wordlist:
                if os.path.exists(args.wordlist):
                    wl = load_wordlist(args.wordlist, limit=200)
                    if wl:
                        console.print(f"[green]✓[/] Loaded {len(wl)} entries from wordlist")
                else:
                    console.print(f"[yellow]Warning: Wordlist not found: {args.wordlist}[/]")
        
            web_results = run_web_scan(normalized_target, web_modules, wl, args.workers, args.rate)

        # -----------------------------
        # Collect Data
        # -----------------------------
        data = {
            "target": normalized_target,
            "target_type": target_type,
            "url": normalized_target if target_type == TargetType.URL else None,
            "profile": args.profile,
            "modules": enabled_modules,
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
        pdf_file = None
        if not args.no_pdf:
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