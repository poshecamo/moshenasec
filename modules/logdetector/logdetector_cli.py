#!/usr/bin/env python3

import argparse
import json
import os
import sys
import re
import gzip
import zipfile
import csv
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import datetime

def setup_parser(parser):
    parser.add_argument("--file", "-f", help="Log file to analyze")
    parser.add_argument("--directory", "-d", help="Directory of log files to analyze")
    parser.add_argument("--pattern", "-p", help="Custom regex pattern to search for")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--threads", "-t", type=int, default=4, help="Number of threads for parallel processing")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--list-patterns", "-l", action="store_true", help="List built-in detection patterns")
    parser.add_argument("--format", choices=["auto", "apache", "nginx", "iis", "json", "csv", "syslog"], 
                      default="auto", help="Log format (default: auto-detect)")

def run(args):
    if args.list_patterns:
        list_patterns()
        return
        
    if not args.file and not args.directory:
        print(f"{Fore.RED}[!] Error: You must specify a file or directory to analyze{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[+] Starting log file threat detection...{Style.RESET_ALL}")
    
    # Load detection patterns
    patterns = load_detection_patterns()
    
    # Add custom pattern if provided
    if args.pattern:
        patterns.append({
            "name": "Custom Pattern",
            "pattern": args.pattern,
            "description": "User-provided custom pattern",
            "severity": "medium"
        })
    
    # Collect files to analyze
    files_to_analyze = []
    
    if args.file:
        files_to_analyze.append(args.file)
    
    if args.directory:
        for root, _, files in os.walk(args.directory):
            for file in files:
                if file.endswith(('.log', '.txt', '.json', '.csv', '.pcap', '.gz', '.zip')):
                    files_to_analyze.append(os.path.join(root, file))
    
    if not files_to_analyze:
        print(f"{Fore.YELLOW}[!] No log files found to analyze{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(files_to_analyze)} log files to analyze{Style.RESET_ALL}")
    
    results = []
    
    # Process files in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for file_path in files_to_analyze:
            futures.append(executor.submit(analyze_file, file_path, patterns, args.format, args.verbose))
        
        for future in futures:
            file_results = future.result()
            if file_results["matches"]:
                results.append(file_results)
    
    # Output results
    if results:
        print(f"{Fore.RED}[!] Found potential threats in {len(results)} files{Style.RESET_ALL}")
        
        for file_result in results:
            print(f"\n{Fore.YELLOW}=== {file_result['file']} ==={Style.RESET_ALL}")
            print(f"Format: {file_result['format']}")
            print(f"Matches: {len(file_result['matches'])}")
            
            for match in file_result['matches']:
                print(f"\n  {Fore.RED}[ALERT] {match['pattern_name']} ({match['severity']}){Style.RESET_ALL}")
                print(f"  Description: {match['description']}")
                print(f"  Line {match['line_number']}: {match['line']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] No threats detected in the analyzed files{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Log file threat detection completed{Style.RESET_ALL}")

def load_detection_patterns():
    """Load built-in detection patterns"""
    return [
        {
            "name": "SQL Injection",
            "pattern": r"(?i)(\'|\"|\s+or\s+|\s+and\s+|\s+union\s+|\s+select\s+|\s+from\s+|\s+where\s+|\s+drop\s+|\s+truncate\s+|\s+delete\s+|\s+insert\s+|\s+exec\s+|\s+xp_cmdshell\s+)",
            "description": "Potential SQL injection attempt",
            "severity": "high"
        },
        {
            "name": "XSS Attack",
            "pattern": r"(?i)(<script>|<\/script>|javascript:|onerror=|onload=|eval\(|document\.cookie)",
            "description": "Potential Cross-Site Scripting (XSS) attack",
            "severity": "high"
        },
        {
            "name": "Command Injection",
            "pattern": r"(?i)(;|\||\`|\$\(|\&\&|\|\|)(\s*)(cat|nc|ncat|wget|curl|bash|sh|python|perl|ruby|php|chmod|chown|rm|mv|cp)",
            "description": "Potential command injection attempt",
            "severity": "critical"
        },
        {
            "name": "Path Traversal",
            "pattern": r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)",
            "description": "Potential directory traversal attempt",
            "severity": "high"
        },
        {
            "name": "File Inclusion",
            "pattern": r"(?i)(=\s*https?:\/\/|=\s*ftp:\/\/|=\s*php:\/\/|=\s*data:)",
            "description": "Potential remote file inclusion attempt",
            "severity": "high"
        },
        {
            "name": "Brute Force",
            "pattern": r"(?i)(failed login|authentication failure|invalid password|login failed)",
            "description": "Potential brute force attack",
            "severity": "medium"
        },
        {
            "name": "Web Shell",
            "pattern": r"(?i)(c99shell|r57shell|wso\.php|b374k|weevely|phpspy|webadmin\.php)",
            "description": "Potential web shell upload or access",
            "severity": "critical"
        },
        {
            "name": "Suspicious User Agent",
            "pattern": r"(?i)(nikto|sqlmap|nessus|nmap|acunetix|burpsuite|w3af|hydra|libwww-perl|python-requests|go-http-client|zgrab)",
            "description": "Suspicious user agent indicating scanning or exploitation tools",
            "severity": "medium"
        },
        {
            "name": "Server-Side Request Forgery",
            "pattern": r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
            "description": "Potential Server-Side Request Forgery (SSRF) attempt",
            "severity": "high"
        },
        {
            "name": "CVE Indicators",
            "pattern": r"(?i)(CVE-\d{4}-\d{4,7}|shellshock|heartbleed|struts|log4j|log4shell|spring4shell)",
            "description": "Potential exploitation of known vulnerabilities",
            "severity": "critical"
        }
    ]

def list_patterns():
    """List all built-in detection patterns"""
    patterns = load_detection_patterns()
    
    print(f"{Fore.GREEN}[+] Built-in Detection Patterns:{Style.RESET_ALL}")
    print(f"\n{'Name':<20} {'Severity':<10} {'Description':<50}")
    print(f"{'-'*20} {'-'*10} {'-'*50}")
    
    for pattern in patterns:
        print(f"{pattern['name']:<20} {pattern['severity']:<10} {pattern['description']:<50}")

def analyze_file(file_path, patterns, format_type, verbose):
    """Analyze a log file for potential threats"""
    if verbose:
        print(f"{Fore.BLUE}[*] Analyzing {file_path}...{Style.RESET_ALL}")
    
    results = {
        "file": file_path,
        "format": "unknown",
        "matches": []
    }
    
    try:
        # Determine file format if auto
        if format_type == "auto":
            format_type = detect_file_format(file_path)
        
        results["format"] = format_type
        
        # Open and read file based on extension
        lines = read_file_lines(file_path, format_type)
        
        # Process each line
        for line_number, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern["pattern"], line):
                    results["matches"].append({
                        "line_number": line_number,
                        "line": line.strip(),
                        "pattern_name": pattern["name"],
                        "description": pattern["description"],
                        "severity": pattern["severity"]
                    })
        
        if verbose:
            print(f"{Fore.GREEN}[+] Completed analysis of {file_path}{Style.RESET_ALL}")
        
        return results
    
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}[!] Error analyzing {file_path}: {str(e)}{Style.RESET_ALL}")
        
        results["error"] = str(e)
        return results

def detect_file_format(file_path):
    """Detect the format of a log file"""
    # Check by extension first
    if file_path.endswith('.json'):
        return "json"
    elif file_path.endswith('.csv'):
        return "csv"
    elif file_path.endswith('.pcap'):
        return "pcap"
    
    # Check content of the file
    try:
        with open(file_path, 'r', errors='ignore') as f:
            first_lines = [f.readline() for _ in range(5)]
            content = ''.join(first_lines)
            
            if '{' in content and '}' in content and ('"' in content or "'" in content):
                return "json"
            elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', content) and re.search(r'\[.*?\]', content):
                if 'nginx' in content.lower():
                    return "nginx"
                else:
                    return "apache"
            elif re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', content):
                return "syslog"
            elif ',' in content and content.count(',') > 3:
                return "csv"
            else:
                return "text"
    except:
        return "text"

def read_file_lines(file_path, format_type):
    """Read lines from a file based on its format and extension"""
    lines = []
    
    # Handle compressed files
    if file_path.endswith('.gz'):
        with gzip.open(file_path, 'rt', errors='ignore') as f:
            lines = f.readlines()
    elif file_path.endswith('.zip'):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            for name in zip_ref.namelist():
                with zip_ref.open(name) as f:
                    lines = [line.decode('utf-8', errors='ignore') for line in f.readlines()]
    # Handle special formats
    elif format_type == "json":
        with open(file_path, 'r', errors='ignore') as f:
            try:
                data = json.load(f)
                if isinstance(data, list):
                    lines = [json.dumps(item) for item in data]
                else:
                    lines = [json.dumps(data)]
            except:
                # If not valid JSON, read as text
                f.seek(0)
                lines = f.readlines()
    elif format_type == "csv":
        with open(file_path, 'r', errors='ignore') as f:
            reader = csv.reader(f)
            lines = [','.join(row) for row in reader]
    # Handle regular text files
    else:
        with open(file_path, 'r', errors='ignore') as f:
            lines = f.readlines()
    
    return lines
