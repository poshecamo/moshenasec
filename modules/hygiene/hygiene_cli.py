#!/usr/bin/env python3

import argparse
import json
import os
import sys
import requests
import re
import socket
import dns.resolver
import urllib.parse
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import time

def setup_parser(parser):
    parser.add_argument("--target", "-t", help="Target URL or domain to check")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--timeout", "-m", type=int, default=10, help="Timeout for requests in seconds")
    parser.add_argument("--threads", "-n", type=int, default=5, help="Number of threads for parallel processing")
    parser.add_argument("--all", "-a", action="store_true", help="Run all checks")
    parser.add_argument("--git", "-g", action="store_true", help="Check for exposed .git folders")
    parser.add_argument("--admin", "-d", action="store_true", help="Check for default admin portals")
    parser.add_argument("--headers", "-e", action="store_true", help="Check for weak security headers")
    parser.add_argument("--sensitive", "-s", action="store_true", help="Check for sensitive endpoints")
    parser.add_argument("--dns", "-x", action="store_true", help="Check DNS configuration")

def run(args):
    if not args.target:
        print(f"{Fore.RED}[!] Error: You must specify a target URL or domain{Style.RESET_ALL}")
        sys.exit(1)
    
    # Ensure target has a scheme
    target = args.target
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    print(f"{Fore.GREEN}[+] Starting digital hygiene check for {target}...{Style.RESET_ALL}")
    
    # Determine which checks to run
    run_all = args.all
    checks_to_run = []
    
    if run_all or args.git:
        checks_to_run.append(("Git Exposure", check_git_exposure))
    
    if run_all or args.admin:
        checks_to_run.append(("Admin Portals", check_admin_portals))
    
    if run_all or args.headers:
        checks_to_run.append(("Security Headers", check_security_headers))
    
    if run_all or args.sensitive:
        checks_to_run.append(("Sensitive Endpoints", check_sensitive_endpoints))
    
    if run_all or args.dns:
        checks_to_run.append(("DNS Configuration", check_dns_configuration))
    
    if not checks_to_run:
        print(f"{Fore.YELLOW}[!] No checks selected. Use --all or specify individual checks.{Style.RESET_ALL}")
        return
    
    results = {
        "target": target,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "checks": {}
    }
    
    # Run checks in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for name, func in checks_to_run:
            futures.append(executor.submit(run_check, name, func, target, args.timeout, args.verbose))
        
        for future in futures:
            name, check_result = future.result()
            results["checks"][name] = check_result
    
    # Calculate overall risk score
    risk_score = 0
    issues_count = 0
    
    for check_name, check_result in results["checks"].items():
        risk_score += check_result.get("risk_score", 0)
        issues_count += len(check_result.get("issues", []))
    
    results["risk_score"] = risk_score
    results["issues_count"] = issues_count
    
    # Output results
    print(f"\n{Fore.GREEN}[+] Digital Hygiene Check Results:{Style.RESET_ALL}")
    print(f"Target: {target}")
    print(f"Risk Score: {risk_score}")
    print(f"Issues Found: {issues_count}")
    
    for check_name, check_result in results["checks"].items():
        print(f"\n{Fore.YELLOW}=== {check_name} ==={Style.RESET_ALL}")
        print(f"Risk Score: {check_result.get('risk_score', 0)}")
        
        if check_result.get("issues", []):
            for issue in check_result["issues"]:
                severity = issue.get("severity", "unknown")
                severity_color = get_severity_color(severity)
                print(f"  {severity_color}[{severity.upper()}] {issue['description']}{Style.RESET_ALL}")
                if "details" in issue and issue["details"]:
                    print(f"    Details: {issue['details']}")
        else:
            print(f"  {Fore.GREEN}[+] No issues found{Style.RESET_ALL}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.  f, indent=2)
        print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Digital hygiene check completed{Style.RESET_ALL}")

def run_check(name, func, target, timeout, verbose):
    """Run a single check and return the results"""
    if verbose:
        print(f"{Fore.BLUE}[*] Running {name} check for {target}...{Style.RESET_ALL}")
    
    try:
        result = func(target, timeout)
        if verbose:
            print(f"{Fore.GREEN}[+] Completed {name} check{Style.RESET_ALL}")
        return name, result
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}[!] Error in {name} check: {str(e)}{Style.RESET_ALL}")
        return name, {
            "error": str(e),
            "risk_score": 0,
            "issues": []
        }

def check_git_exposure(target, timeout):
    """Check for exposed .git folders"""
    result = {
        "risk_score": 0,
        "issues": []
    }
    
    git_paths = [
        "/.git/",
        "/.git/config",
        "/.git/HEAD",
        "/.git/logs/HEAD",
        "/.git/index"
    ]
    
    for path in git_paths:
        url = f"{target}{path}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            
            if response.status_code == 200:
                result["risk_score"] += 20
                result["issues"].append({
                    "severity": "critical",
                    "description": f"Exposed Git repository found at {path}",
                    "details": f"Status code: {response.status_code}, Content length: {len(response.content)}"
                })
                break  # One finding is enough
        except:
            pass
    
    return result

def check_admin_portals(target, timeout):
    """Check for default admin portals"""
    result = {
        "risk_score": 0,
        "issues": []
    }
    
    admin_paths = [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/admin.php",
        "/login",
        "/wp-login.php",
        "/admincp",
        "/admin/login",
        "/admin/dashboard",
        "/manager",
        "/management",
        "/panel",
        "/cpanel",
        "/webadmin",
        "/adminer",
        "/phpmyadmin"
    ]
    
    for path in admin_paths:
        url = f"{target}{path}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            
            if response.status_code in [200, 301, 302, 307, 308]:
                result["risk_score"] += 5
                result["issues"].append({
                    "severity": "medium",
                    "description": f"Potential admin portal found at {path}",
                    "details": f"Status code: {response.status_code}, Content length: {len(response.content)}"
                })
        except:
            pass
    
    return result

def check_security_headers(target, timeout):
    """Check for weak or missing security headers"""
    result = {
        "risk_score": 0,
        "issues": []
    }
    
    try:
        response = requests.get(target, timeout=timeout)
        headers = response.headers
        
        # Check for important security headers
        security_headers = {
            "Strict-Transport-Security": {
                "severity": "high",
                "description": "Missing HTTP Strict Transport Security (HSTS) header"
            },
            "Content-Security-Policy": {
                "severity": "high",
                "description": "Missing Content Security Policy (CSP) header"
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "Missing X-Frame-Options header (clickjacking protection)"
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "Missing X-Content-Type-Options header"
            },
            "X-XSS-Protection": {
                "severity": "medium",
                "description": "Missing X-XSS-Protection header"
            },
            "Referrer-Policy": {
                "severity": "low",
                "description": "Missing Referrer-Policy header"
            },
            "Permissions-Policy": {
                "severity": "low",
                "description": "Missing Permissions-Policy header"
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                severity_score = {"high": 10, "medium": 5, "low": 2}
                result["risk_score"] += severity_score[info["severity"]]
                result["issues"].append({
                    "severity": info["severity"],
                    "description": info["description"]
                })
        
        # Check for server information disclosure
        if "Server" in headers:
            result["risk_score"] += 2
            result["issues"].append({
                "severity": "low",
                "description": "Server header reveals software information",
                "details": f"Server: {headers['Server']}"
            })
        
        # Check for PHP version disclosure
        if "X-Powered-By" in headers:
            result["risk_score"] += 3
            result["issues"].append({
                "severity": "medium",
                "description": "X-Powered-By header reveals technology information",
                "details": f"X-Powered-By: {headers['X-Powered-By']}"
            })
    except Exception as e:
        result["issues"].append({
            "severity": "low",
            "description": f"Could not check security headers: {str(e)}"
        })
    
    return result

def check_sensitive_endpoints(target, timeout):
    """Check for sensitive endpoints"""
    result = {
        "risk_score": 0,
        "issues": []
    }
    
    sensitive_paths = [
        "/.env",
        "/config.php",
        "/config.js",
        "/wp-config.php",
        "/config.json",
        "/settings.json",
        "/database.yml",
        "/credentials.json",
        "/secrets.json",
        "/backup",
        "/backup.zip",
        "/dump.sql",
        "/db.sql",
        "/debug",
        "/api/debug",
        "/test",
        "/phpinfo.php",
        "/info.php",
        "/.htaccess",
        "/server-status",
        "/server-info",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/api/v1/swagger",
        "/swagger",
        "/swagger-ui.html",
        "/api-docs"
    ]
    
    for path in sensitive_paths:
        url = f"{target}{path}"
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
            
            if response.status_code == 200:
                result["risk_score"] += 10
                result["issues"].append({
                    "severity": "high",
                    "description": f"Sensitive endpoint found at {path}",
                    "details": f"Status code: {response.status_code}, Content length: {len(response.content)}"
                })
        except:
            pass
    
    return result

def check_dns_configuration(target, timeout):
    """Check DNS configuration for security issues"""
    result = {
        "risk_score": 0,
        "issues": []
    }
    
    # Extract domain from URL
    domain = urllib.parse.urlparse(target).netloc
    if ':' in domain:  # Remove port if present
        domain = domain.split(':')[0]
    
    # Check for SPF record
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        
        for rdata in answers:
            if 'v=spf1' in str(rdata):
                spf_found = True
                break
        
        if not spf_found:
            result["risk_score"] += 5
            result["issues"].append({
                "severity": "medium",
                "description": "Missing SPF record",
                "details": "SPF record helps prevent email spoofing"
            })
    except:
        pass
    
    # Check for DMARC record
    try:
        dmarc_domain = f"_dmarc.{domain}"
        try:
            dns.resolver.resolve(dmarc_domain, 'TXT')
        except:
            result["risk_score"] += 5
            result["issues"].append({
                "severity": "medium",
                "description": "Missing DMARC record",
                "details": "DMARC helps prevent email spoofing and phishing"
            })
    except:
        pass
    
    # Check for DNSSEC
    try:
        answers = dns.resolver.resolve(domain, 'DS')
        # If we get here, DNSSEC is configured
    except dns.resolver.NoAnswer:
        result["risk_score"] += 3
        result["issues"].append({
            "severity": "low",
            "description": "DNSSEC not configured",
            "details": "DNSSEC helps prevent DNS spoofing attacks"
        })
    except:
        pass
    
    # Check for CAA record
    try:
        try:
            dns.resolver.resolve(domain, 'CAA')
        except dns.resolver.NoAnswer:
            result["risk_score"] += 3
            result["issues"].append({
                "severity": "low",
                "description": "Missing CAA record",
                "details": "CAA records help control which CAs can issue certificates for your domain"
            })
    except:
        pass
    
    return result

def get_severity_color(severity):
    """Get color for severity level"""
    if severity == "critical":
        return Fore.RED + Style.BRIGHT
    elif severity == "high":
        return Fore.RED
    elif severity == "medium":
        return Fore.YELLOW
    elif severity == "low":
        return Fore.CYAN
    else:
        return Fore.WHITE
