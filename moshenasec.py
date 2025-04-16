#!/usr/bin/env python3

import argparse
import sys
import os
from colorama import init, Fore, Style

# Import modules
from modules.recon import recon_cli
from modules.intel import intel_cli
from modules.logdetector import logdetector_cli
from modules.phishing import phishing_cli
from modules.hygiene import hygiene_cli

# Initialize colorama
init(autoreset=True)

BANNER = f"""
{Fore.RED}███╗   ███╗ ██████╗ ███████╗██╗  ██╗███████╗███╗   ██╗ █████╗ ███████╗███████╗ ██████╗{Style.RESET_ALL}
{Fore.RED}████╗ ████║██╔═══██╗██╔════╝██║  ██║██╔════╝████╗  ██║██╔══██╗██╔════╝██╔════╝██╔════╝{Style.RESET_ALL}
{Fore.RED}██╔████╔██║██║   ██║███████╗███████║█████╗  ██╔██╗ ██║███████║███████╗█████╗  ██║     {Style.RESET_ALL}
{Fore.RED}██║╚██╔╝██║██║   ██║╚════██║██╔══██║██╔══╝  ██║╚██╗██║██╔══██║╚════██║██╔══╝  ██║     {Style.RESET_ALL}
{Fore.RED}██║ ╚═╝ ██║╚██████╔╝███████║██║  ██║███████╗██║ ╚████║██║  ██║███████║███████╗╚██████╗{Style.RESET_ALL}
{Fore.RED}╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝{Style.RESET_ALL}
                                                                                  
{Fore.YELLOW}[*] Cybersecurity Toolkit for Penetration Testing{Style.RESET_ALL}
{Fore.CYAN}[*] Version: 1.0.0{Style.RESET_ALL}
{Fore.CYAN}[*] Author: MoshenaSec Team{Style.RESET_ALL}
"""

def main():
    parser = argparse.ArgumentParser(
        description="MoshenaSec - A comprehensive cybersecurity toolkit for penetration testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: moshenasec recon --domain example.com"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Recon & OSINT CLI Aggregator
    recon_parser = subparsers.add_parser("recon", help="Reconnaissance and OSINT tools")
    recon_cli.setup_parser(recon_parser)
    
    # Threat Intel Feed CLI
    intel_parser = subparsers.add_parser("intel", help="Threat intelligence feed aggregator")
    intel_cli.setup_parser(intel_parser)
    
    # Log File Threat Detector
    logdetector_parser = subparsers.add_parser("logdetect", help="Log file threat detector")
    logdetector_cli.setup_parser(logdetector_parser)
    
    # Phishing Link Analyzer
    phishing_parser = subparsers.add_parser("phishing", help="Phishing link analyzer")
    phishing_cli.setup_parser(phishing_parser)
    
    # Digital Hygiene Toolkit
    hygiene_parser = subparsers.add_parser("hygiene", help="Digital hygiene toolkit")
    hygiene_cli.setup_parser(hygiene_parser)
    
    # Version
    parser.add_argument("-v", "--version", action="store_true", help="Show version information")
    
    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    
    if args.version:
        print(f"MoshenaSec v1.0.0")
        sys.exit(0)
        
    if args.command == "recon":
        recon_cli.run(args)
    elif args.command == "intel":
        intel_cli.run(args)
    elif args.command == "logdetect":
        logdetector_cli.run(args)
    elif args.command == "phishing":
        phishing_cli.run(args)
    elif args.command == "hygiene":
        hygiene_cli.run(args)
    else:
        print(BANNER)
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
