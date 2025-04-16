#!/usr/bin/env python3

import argparse
import json
import os
import sys
import requests
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import socket
import whois
import dns.resolver
import time

def setup_parser(parser):
    parser.add_argument("--domain", "-d", help="Target domain for reconnaissance")
    parser.add_argument("--email", "-e", help="Target email for reconnaissance")
    parser.add_argument("--ip", "-i", help="Target IP for reconnaissance")
    parser.add_argument("--output", "-o", help="Output file (JSON or HTML)")
    parser.add_argument("--all", "-a", action="store_true", help="Run all reconnaissance modules")
    parser.add_argument("--whois", "-w", action="store_true", help="Run WHOIS lookup")
    parser.add_argument("--dns", "-n", action="store_true", help="Run DNS enumeration")
    parser.add_argument("--shodan", "-s", action="store_true", help="Run Shodan lookup")
    parser.add_argument("--crtsh", "-c", action="store_true", help="Run crt.sh certificate lookup")
    parser.add_argument("--metadata", "-m", action="store_true", help="Extract metadata from website")
    parser.add_argument("--threads", "-t", type=int, default=5, help="Number of threads for parallel processing")

def run(args):
    if not any([args.domain, args.email, args.ip]):
        print(f"{Fore.RED}[!] Error: You must specify at least one target (domain, email, or IP){Style.RESET_ALL}")
        sys.exit(1)
        
    print(f"{Fore.GREEN}[+] Starting reconnaissance...{Style.RESET_ALL}")
    
    results = {}
    
    # Determine which modules to run
    run_all = args.all
    modules_to_run = []
    
    if args.domain:
        if run_all or args.whois:
            modules_to_run.append(("WHOIS", whois_lookup, args.domain))
        if run_all or args.dns:
            modules_to_run.append(("DNS", dns_enumeration, args.domain))
        if run_all or args.crtsh:
            modules_to_run.append(("Certificate", crtsh_lookup, args.domain))
        if run_all or args.metadata:
            modules_to_run.append(("Metadata", extract_metadata, args.domain))
    
    if args.ip and (run_all or args.shodan):
        modules_to_run.append(("Shodan", shodan_lookup, args.ip))
    
    if args.email and run_all:
        modules_to_run.append(("Email", email_lookup, args.email))
    
    # Run modules in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for name, func, target in modules_to_run:
            futures.append(executor.submit(run_module, name, func, target))
        
        for future in futures:
            name, data = future.result()
            results[name] = data
    
    # Output results
    if args.output:
        output_results(results, args.output)
    else:
        print_results(results)
    
    print(f"{Fore.GREEN}[+] Reconnaissance completed{Style.RESET_ALL}")

def run_module(name, func, target):
    print(f"{Fore.BLUE}[*] Running {name} lookup for {target}...{Style.RESET_ALL}")
    try:
        result = func(target)
        print(f"{Fore.GREEN}[+] {name} lookup completed{Style.RESET_ALL}")
        return name, result
    except Exception as e:
        print(f"{Fore.RED}[!] Error in {name} lookup: {str(e)}{Style.RESET_ALL}")
        return name, {"error": str(e)}

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "dnssec": w.dnssec,
            "name": w.name,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "zipcode": w.zipcode,
            "country": w.country
        }
    except Exception as e:
        return {"error": str(e)}

def dns_enumeration(domain):
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(answer) for answer in answers]
        except Exception:
            results[record_type] = []
    
    return results

def shodan_lookup(ip):
    # Note: This is a placeholder. In a real implementation, you would use the Shodan API
    return {
        "ip": ip,
        "note": "This is a placeholder. You need a Shodan API key for real implementation."
    }

def crtsh_lookup(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to get data from crt.sh: {response.status_code}"}

def extract_metadata(domain):
    url = f"http://{domain}"
    try:
        response = requests.get(url, timeout=10)
        headers = dict(response.headers)
        
        metadata = {
            "server": headers.get("Server", "Unknown"),
            "content_type": headers.get("Content-Type", "Unknown"),
            "status_code": response.status_code,
            "headers": headers
        }
        
        return metadata
    except Exception as e:
        return {"error": str(e)}

def email_lookup(email):
    # Placeholder for email lookup functionality
    return {
        "email": email,
        "note": "This is a placeholder. You would implement email lookup functionality here."
    }

def print_results(results):
    for module, data in results.items():
        print(f"\n{Fore.YELLOW}=== {module} Results ==={Style.RESET_ALL}")
        print(json.dumps(data, indent=2))

def output_results(results, output_file):
    file_ext = os.path.splitext(output_file)[1].lower()
    
    if file_ext == '.json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
    elif file_ext == '.html':
        html_content = generate_html_report(results)
        with open(output_file, 'w') as f:
            f.write(html_content)
        print(f"{Fore.GREEN}[+] Results saved to {output_file}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] Unsupported output format. Use .json or .html{Style.RESET_ALL}")

def generate_html_report(results):
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>MoshenaSec Reconnaissance Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #c00; }
            h2 { color: #333; margin-top: 30px; }
            pre { background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto; }
            .container { max-width: 1200px; margin: 0 auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>MoshenaSec Reconnaissance Report</h1>
            <p>Generated on: """ + time.strftime("%Y-%m-%d %H:%M:%S") + """</p>
    """
    
    for module, data in results.items():
        html += f"<h2>{module} Results</h2>"
        html += f"<pre>{json.dumps(data, indent=2)}</pre>"
    
    html += """
        </div>
    </body>
    </html>
    """
    
    return html
