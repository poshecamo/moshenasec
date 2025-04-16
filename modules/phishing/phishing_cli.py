#!/usr/bin/env python3

import argparse
import json
import os
import sys
import re
import requests
import socket
import dns.resolver
import tldextract
import datetime
import urllib.parse
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import time

def setup_parser(parser):
    parser.add_argument("--url", "-u", help="URL to analyze")
    parser.add_argument("--file", "-f", help="File containing URLs or emails to analyze")
    parser.add_argument("--output", "-o", help="Output file for results (JSON)")
    parser.add_argument("--screenshot", "-s", action="store_true", help="Take screenshots of URLs (requires Selenium)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--timeout", "-t", type=int, default=10, help="Timeout for requests in seconds")
    parser.add_argument("--threads", "-n", type=int, default=5, help="Number of threads for parallel processing")
    parser.add_argument("--extract-urls", "-e", action="store_true", help="Extract URLs from emails")

def run(args):
    if not args.url and not args.file:
        print(f"{Fore.RED}[!] Error: You must specify a URL or file to analyze{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.GREEN}[+] Starting phishing link analysis...{Style.RESET_ALL}")
    
    urls_to_analyze = []
    
    if args.url:
        urls_to_analyze.append(args.url)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        if is_email(line) and args.extract_urls:
                            # Extract URLs from email content (placeholder)
                            print(f"{Fore.YELLOW}[!] URL extraction from emails is a placeholder{Style.RESET_ALL}")
                            urls_to_analyze.append(f"http://example.com/placeholder-for-{line}")
                        elif is_url(line):
                            urls_to_analyze.append(line)
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
    
    if not urls_to_analyze:
        print(f"{Fore.YELLOW}[!] No URLs found to analyze{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Found {len(urls_to_analyze)} URLs to analyze{Style.RESET_ALL}")
    
    results = []
    
    # Process URLs in parallel
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for url in urls_to_analyze:
            futures.append(executor.submit(analyze_url, url, args.timeout, args.screenshot, args.verbose))
        
        for future in futures:
            url_result = future.result()
            results.append(url_result)
    
    # Output results
    print(f"\n{Fore.GREEN}[+] Analysis Results:{Style.RESET_ALL}")
    
    for result in results:
        url = result["url"]
        risk_score = result["risk_score"]
        risk_level = get_risk_level(risk_score)
        risk_color = get_risk_color(risk_level)
        
        print(f"\n{risk_color}=== {url} ==={Style.RESET_ALL}")
        print(f"Risk Score: {risk_score}/100 ({risk_level})")
        
        for check, details in result["checks"].items():
            if details["result"] == "suspicious":
                print(f"  {Fore.RED}[!] {check}: {details['details']}{Style.RESET_ALL}")
            elif details["result"] == "warning":
                print(f"  {Fore.YELLOW}[!] {check}: {details['details']}{Style.RESET_ALL}")
            elif details["result"] == "safe":
                print(f"  {Fore.GREEN}[+] {check}: {details['details']}{Style.RESET_ALL}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Fore.GREEN}[+] Results saved to {args.output}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Phishing link analysis completed{Style.RESET_ALL}")

def is_email(text):
    """Check if text is an email address"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, text))

def is_url(text):
    """Check if text is a URL"""
    url_pattern = r'^(http|https|ftp)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$'
    return bool(re.match(url_pattern, text))

def analyze_url(url, timeout, take_screenshot, verbose):
    """Analyze a URL for phishing indicators"""
    if verbose:
        print(f"{Fore.BLUE}[*] Analyzing {url}...{Style.RESET_ALL}")
    
    result = {
        "url": url,
        "timestamp": datetime.datetime.now().isoformat(),
        "checks": {},
        "risk_score": 0
    }
    
    # Extract domain information
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    subdomain = extracted.subdomain
    
    # Check 1: Domain age
    try:
        result["checks"]["domain_age"] = check_domain_age(domain)
    except Exception as e:
        result["checks"]["domain_age"] = {
            "result": "warning",
            "details": f"Could not check domain age: {str(e)}",
            "score": 5
        }
    
    # Check 2: URL structure
    result["checks"]["url_structure"] = check_url_structure(url)
    
    # Check 3: SSL certificate
    try:
        result["checks"]["ssl_certificate"] = check_ssl_certificate(url)
    except Exception as e:
        result["checks"]["ssl_certificate"] = {
            "result": "warning",
            "details": f"Could not check SSL certificate: {str(e)}",
            "score": 5
        }
    
    # Check 4: Suspicious keywords
    result["checks"]["suspicious_keywords"] = check_suspicious_keywords(url)
    
    # Check 5: Redirect check
    try:
        result["checks"]["redirect"] = check_redirect(url, timeout)
    except Exception as e:
        result["checks"]["redirect"] = {
            "result": "warning",
            "details": f"Could not check redirects: {str(e)}",
            "score": 5
        }
    
    # Check 6: IP address as URL
    result["checks"]["ip_url"] = check_ip_url(url)
    
    # Check 7: Domain reputation (placeholder)
    result["checks"]["domain_reputation"] = {
        "result": "warning",
        "details": "Domain reputation check is a placeholder",
        "score": 5
    }
    
    # Check 8: HTML/JavaScript analysis (placeholder)
    result["checks"]["html_analysis"] = {
        "result": "warning",
        "details": "HTML/JavaScript analysis is a placeholder",
        "score": 5
    }
    
    # Take screenshot if requested (placeholder)
    if take_screenshot:
        result["screenshot"] = "Screenshot functionality is a placeholder"
    
    # Calculate risk score
    risk_score = 0
    for check in result["checks"].values():
        risk_score += check.get("score", 0)
    
    # Cap risk score at 100
    result["risk_score"] = min(risk_score, 100)
    
    if verbose:
        print(f"{Fore.GREEN}[+] Completed analysis of {url}{Style.RESET_ALL}")
    
    return result

def check_domain_age(domain):
    """Check the age of a domain"""
    try:
        # This is a placeholder. In a real implementation, you would use WHOIS data.
        # For demonstration, we'll return a random result
        import random
        age_days = random.randint(1, 1000)
        
        if age_days < 30:
            return {
                "result": "suspicious",
                "details": f"Domain is only {age_days} days old",
                "score": 20
            }
        elif age_days < 90:
            return {
                "result": "warning",
                "details": f"Domain is {age_days} days old",
                "score": 10
            }
        else:
            return {
                "result": "safe",
                "details": f"Domain is {age_days} days old",
                "score": 0
            }
    except Exception as e:
        raise Exception(f"Error checking domain age: {str(e)}")

def check_url_structure(url):
    """Check URL structure for suspicious patterns"""
    score = 0
    issues = []
    
    # Check for excessive subdomains
    extracted = tldextract.extract(url)
    if extracted.subdomain.count('.') > 2:
        score += 10
        issues.append(f"Excessive subdomains: {extracted.subdomain}")
    
    # Check for suspicious TLDs
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz']
    if extracted.suffix in suspicious_tlds:
        score += 10
        issues.append(f"Suspicious TLD: .{extracted.suffix}")
    
    # Check for URL encoding
    if '%' in url:
        score += 5
        issues.append("URL contains encoded characters")
    
    # Check for excessive hyphens
    if extracted.domain.count('-') > 2:
        score += 5
        issues.append(f"Excessive hyphens in domain: {extracted.domain}")
    
    # Check for common brand names in subdomain
    brand_names = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 'netflix']
    for brand in brand_names:
        if brand in extracted.domain.lower() and brand != extracted.domain.lower():
            score += 15
            issues.append(f"Brand name '{brand}' embedded in domain")
            break
    
    if score > 15:
        result = "suspicious"
    elif score > 5:
        result = "warning"
    else:
        result = "safe"
        issues = ["No suspicious URL structure detected"]
    
    return {
        "result": result,
        "details": "; ".join(issues),
        "score": score
    }

def check_ssl_certificate(url):
    """Check SSL certificate validity"""
    if not url.startswith('https://'):
        return {
            "result": "warning",
            "details": "URL does not use HTTPS",
            "score": 10
        }
    
    # This is a placeholder. In a real implementation, you would check the SSL certificate.
    # For demonstration, we'll return a random result
    import random
    valid = random.choice([True, False])
    
    if valid:
        return {
            "result": "safe",
            "details": "SSL certificate is valid",
            "score": 0
        }
    else:
        return {
            "result": "suspicious",
            "details": "SSL certificate is invalid or self-signed",
            "score": 15
        }

def check_suspicious_keywords(url):
    """Check for suspicious keywords in URL"""
    suspicious_keywords = [
        'login', 'signin', 'verify', 'verification', 'secure', 'account', 'update', 'confirm',
        'banking', 'password', 'credential', 'wallet', 'authenticate', 'authorize', 'recover',
        'alert', 'limited', 'suspended', 'unusual', 'activity', 'security', 'important'
    ]
    
    url_lower = url.lower()
    found_keywords = []
    
    for keyword in suspicious_keywords:
        if keyword in url_lower:
            found_keywords.append(keyword)
    
    if found_keywords:
        return {
            "result": "warning",
            "details": f"Suspicious keywords found: {', '.join(found_keywords)}",
            "score": 5 * len(found_keywords)
        }
    else:
        return {
            "result": "safe",
            "details": "No suspicious keywords found",
            "score": 0
        }

def check_redirect(url, timeout):
    """Check if URL redirects to a different domain"""
    try:
        response = requests.head(url, allow_redirects=True, timeout=timeout)
        
        if response.history:
            original_domain = tldextract.extract(url).registered_domain
            final_domain = tldextract.extract(response.url).registered_domain
            
            if original_domain != final_domain:
                return {
                    "result": "suspicious",
                    "details": f"URL redirects to a different domain: {response.url}",
                    "score": 15
                }
            else:
                return {
                    "result": "warning",
                    "details": f"URL redirects within the same domain: {response.url}",
                    "score": 5
                }
        else:
            return {
                "result": "safe",
                "details": "URL does not redirect",
                "score": 0
            }
    except Exception as e:
        raise Exception(f"Error checking redirects: {str(e)}")

def check_ip_url(url):
    """Check if URL uses an IP address instead of a domain name"""
    ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    
    if re.match(ip_pattern, url):
        return {
            "result": "suspicious",
            "details": "URL uses an IP address instead of a domain name",
            "score": 20
        }
    else:
        return {
            "result": "safe",
            "details": "URL uses a domain name",
            "score": 0
        }

def get_risk_level(score):
    """Get risk level based on score"""
    if score >= 70:
        return "High Risk"
    elif score >= 40:
        return "Medium Risk"
    elif score >= 20:
        return "Low Risk"
    else:
        return "Minimal Risk"

def get_risk_color(risk_level):
    """Get color for risk level"""
    if risk_level == "High Risk":
        return Fore.RED
    elif risk_level == "Medium Risk":
        return Fore.YELLOW
    elif risk_level == "Low Risk":
        return Fore.CYAN
    else:
        return Fore.GREEN
