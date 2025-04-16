#!/usr/bin/env python3

import argparse
import json
import os
import sys
import requests
import sqlite3
import datetime
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor

def setup_parser(parser):
    parser.add_argument("--fetch", "-f", action="store_true", help="Fetch latest threat intelligence")
    parser.add_argument("--check", "-c", help="Check IP, domain, or file hash against threat intel")
    parser.add_argument("--list-sources", "-l", action="store_true", help="List available threat intel sources")
    parser.add_argument("--source", "-s", help="Specify threat intel source (default: all)")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--db", "-d", help="Path to local database (default: ~/.moshenasec/intel.db)")
    parser.add_argument("--days", "-n", type=int, default=7, help="Number of days of intel to fetch (default: 7)")
    parser.add_argument("--alert", "-a", action="store_true", help="Enable alert mode for log monitoring")

def run(args):
    # Initialize database
    db_path = args.db if args.db else os.path.expanduser("~/.moshenasec/intel.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    db = initialize_database(db_path)
    
    if args.list_sources:
        list_sources()
        return
        
    if args.fetch:
        fetch_intel(db, args.days, args.source)
        return
        
    if args.check:
        check_intel(db, args.check, args.output)
        return
        
    if args.alert:
        start_alert_mode(db)
        return
        
    print(f"{Fore.YELLOW}[!] No action specified. Use --fetch, --check, --list-sources, or --alert{Style.RESET_ALL}")

def initialize_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables if they don't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE,
        url TEXT,
        description TEXT,
        last_updated TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS indicators (
        id INTEGER PRIMARY KEY,
        type TEXT,
        value TEXT,
        source_id INTEGER,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        confidence REAL,
        description TEXT,
        FOREIGN KEY (source_id) REFERENCES sources(id),
        UNIQUE(type, value, source_id)
    )
    ''')
    
    # Initialize default sources if table is empty
    cursor.execute("SELECT COUNT(*) FROM sources")
    if cursor.fetchone()[0] == 0:
        default_sources = [
            ("alienvault", "https://otx.alienvault.com", "AlienVault Open Threat Exchange"),
            ("abuseipdb", "https://www.abuseipdb.com", "AbuseIPDB"),
            ("misp", "https://www.misp-project.org", "MISP Threat Sharing"),
            ("emergingthreats", "https://rules.emergingthreats.net", "Emerging Threats"),
            ("phishtank", "https://www.phishtank.com", "PhishTank")
        ]
        
        cursor.executemany(
            "INSERT INTO sources (name, url, description) VALUES (?, ?, ?)",
            default_sources
        )
    
    conn.commit()
    return conn

def list_sources():
    print(f"{Fore.GREEN}[+] Available Threat Intelligence Sources:{Style.RESET_ALL}")
    print(f"\n{'Name':<15} {'Description':<40} {'URL':<30}")
    print(f"{'-'*15} {'-'*40} {'-'*30}")
    
    sources = [
        ("alienvault", "AlienVault Open Threat Exchange", "https://otx.alienvault.com"),
        ("abuseipdb", "AbuseIPDB", "https://www.abuseipdb.com"),
        ("misp", "MISP Threat Sharing", "https://www.misp-project.org"),
        ("emergingthreats", "Emerging Threats", "https://rules.emergingthreats.net"),
        ("phishtank", "PhishTank", "https://www.phishtank.com")
    ]
    
    for name, desc, url in sources:
        print(f"{name:<15} {desc:<40} {url:<30}")

def fetch_intel(db, days, source=None):
    print(f"{Fore.GREEN}[+] Fetching threat intelligence...{Style.RESET_ALL}")
    
    cursor = db.cursor()
    
    if source:
        cursor.execute("SELECT id, name FROM sources WHERE name = ?", (source,))
        sources = cursor.fetchall()
        if not sources:
            print(f"{Fore.RED}[!] Source '{source}' not found{Style.RESET_ALL}")
            return
    else:
        cursor.execute("SELECT id, name FROM sources")
        sources = cursor.fetchall()
    
    for source_id, source_name in sources:
        print(f"{Fore.BLUE}[*] Fetching from {source_name}...{Style.RESET_ALL}")
        
        # This is a placeholder. In a real implementation, you would use the API for each source
        # to fetch actual threat intelligence data.
        
        # Simulate fetching data
        indicators = simulate_fetch_indicators(source_name, days)
        
        # Update database
        for indicator in indicators:
            try:
                cursor.execute('''
                INSERT OR REPLACE INTO indicators 
                (type, value, source_id, first_seen, last_seen, confidence, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    indicator['type'],
                    indicator['value'],
                    source_id,
                    indicator['first_seen'],
                    indicator['last_seen'],
                    indicator['confidence'],
                    indicator['description']
                ))
            except sqlite3.Error as e:
                print(f"{Fore.RED}[!] Database error: {e}{Style.RESET_ALL}")
        
        # Update last_updated timestamp for the source
        cursor.execute(
            "UPDATE sources SET last_updated = ? WHERE id = ?",
            (datetime.datetime.now().isoformat(), source_id)
        )
        
        db.commit()
        
        print(f"{Fore.GREEN}[+] Successfully fetched data from {source_name}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Threat intelligence fetch completed{Style.RESET_ALL}")

def simulate_fetch_indicators(source_name, days):
    """Simulate fetching indicators from a threat intel source"""
    # In a real implementation, this would make API calls to the actual sources
    
    # Generate some fake indicators for demonstration
    indicators = []
    
    # IP indicators
    for i in range(5):
        ip = f"192.168.{i}.{i+10}"
        indicators.append({
            'type': 'ip',
            'value': ip,
            'first_seen': (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(),
            'last_seen': datetime.datetime.now().isoformat(),
            'confidence': 0.8,
            'description': f"Malicious IP from {source_name}"
        })
    
    # Domain indicators
    for i in range(5):
        domain = f"malicious{i}.example.com"
        indicators.append({
            'type': 'domain',
            'value': domain,
            'first_seen': (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(),
            'last_seen': datetime.datetime.now().isoformat(),
            'confidence': 0.9,
            'description': f"Malicious domain from {source_name}"
        })
    
    # Hash indicators
    for i in range(5):
        file_hash = f"a1b2c3d4e5f6{i*10}"
        indicators.append({
            'type': 'hash',
            'value': file_hash,
            'first_seen': (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat(),
            'last_seen': datetime.datetime.now().isoformat(),
            'confidence': 0.7,
            'description': f"Malicious file hash from {source_name}"
        })
    
    return indicators

def check_intel(db, indicator, output=None):
    print(f"{Fore.GREEN}[+] Checking indicator: {indicator}{Style.RESET_ALL}")
    
    # Determine indicator type
    indicator_type = determine_indicator_type(indicator)
    
    cursor = db.cursor()
    cursor.execute('''
    SELECT i.type, i.value, s.name, i.first_seen, i.last_seen, i.confidence, i.description
    FROM indicators i
    JOIN sources s ON i.source_id = s.id
    WHERE i.type = ? AND i.value = ?
    ''', (indicator_type, indicator))
    
    results = cursor.fetchall()
    
    if not results:
        print(f"{Fore.YELLOW}[!] No threat intelligence found for {indicator}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.RED}[!] Found {len(results)} threat intelligence matches for {indicator}{Style.RESET_ALL}")
    
    formatted_results = []
    for result in results:
        type_, value, source, first_seen, last_seen, confidence, description = result
        
        formatted_result = {
            "type": type_,
            "value": value,
            "source": source,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "confidence": confidence,
            "description": description
        }
        
        formatted_results.append(formatted_result)
        
        print(f"\n{Fore.YELLOW}=== Match from {source} ==={Style.RESET_ALL}")
        print(f"Type: {type_}")
        print(f"Value: {value}")
        print(f"First Seen: {first_seen}")
        print(f"Last Seen: {last_seen}")
        print(f"Confidence: {confidence}")
        print(f"Description: {description}")
    
    if output:
        with open(output, 'w') as f:
            json.dump(formatted_results, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to {output}{Style.RESET_ALL}")

def determine_indicator_type(indicator):
    """Determine the type of an indicator based on its format"""
    import re
    
    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, indicator):
        return 'ip'
    
    # Check if it's a domain
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, indicator):
        return 'domain'
    
    # Check if it's a hash (simple check for now)
    hash_pattern = r'^[a-fA-F0-9]{32,64}$'
    if re.match(hash_pattern, indicator):
        return 'hash'
    
    # Default to 'unknown'
    return 'unknown'

def start_alert_mode(db):
    print(f"{Fore.GREEN}[+] Starting alert mode...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] This is a placeholder for the alert mode functionality.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] In a real implementation, this would monitor log files for indicators.{Style.RESET_ALL}")
    
    # This is a placeholder. In a real implementation, this would:
    # 1. Monitor log files for new entries
    # 2. Extract potential indicators (IPs, domains, hashes)
    # 3. Check them against the threat intel database
    # 4. Alert if matches are found
    
    try:
        while True:
            print(f"{Fore.BLUE}[*] Monitoring logs...{Style.RESET_ALL}")
            time.sleep(10)  # Simulate checking every 10 seconds
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Alert mode stopped{Style.RESET_ALL}")
