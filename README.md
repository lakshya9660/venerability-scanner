# Vulnerability Scanner

A powerful, modular, and fully automated vulnerability scanner tool written in Python.

## Features

- Web application vulnerability scanning
- Network and port-based vulnerability detection
- Source code analysis for security issues
- Support for multiple target types (URLs, IPs, files)
- Asynchronous scanning for improved performance
- Detailed JSON reports with vulnerability summaries

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd vulnerability-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python scanner.py <target>
```

Where `<target>` can be:
- A URL (e.g., `https://example.com`)
- An IP address (e.g., `192.168.1.1`)
- A file or directory path (e.g., `./src/`)

## Supported Vulnerability Checks

### Web Application Scanning
- SQL Injection
- Cross-Site Scripting (XSS)
- Open Redirects
- Sensitive File Exposure
- Security Headers
- Directory Traversal

### Network Scanning
- Open Port Detection
- Service Version Identification
- Common Service Vulnerabilities

### Source Code Analysis
- Hardcoded Secrets
- Dangerous Function Usage
- Common Security Misconfigurations

## Output Format

The scanner generates a JSON report containing:
- Scan target
- Scan timestamp
- List of discovered vulnerabilities
- Summary of findings by severity level

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. #   v e n e r a b i l i t y - s c a n n e r  
 