# so1scan

## Overview
This Python script is a command-line tool for performing reconnaissance on a specified domain, gathering information such as its IP address, server type, HTTP security headers, VirusTotal reputation score, and WHOIS data. It supports output in JSON or text format and includes a quiet mode to suppress terminal output.

## Features
- **DNS Resolution**: Resolves the domain’s IP address using DNS `A` record queries.
- **Server Identification**: Extracts the web server type (e.g., Apache, Nginx) from HTTP response headers.
- **HTTP Security Headers Analysis**: Checks for key security headers (CSP, HSTS, X-Frame-Options, CORS, X-Content-Type-Options, Referrer-Policy), flagging missing or weak configurations.
- **VirusTotal Integration**: Retrieves the domain’s reputation score (malicious vendors vs. total) using the VirusTotal API.
- **WHOIS Lookup**: Collects registrar, country, city, creation/expiration dates, and abuse email.
- **Output Options**: Saves results in JSON or text format, with customizable file names.
- **Quiet Mode**: Suppresses terminal output for silent operation.
- **Color-Coded Feedback**: Uses `colorama` for visually distinct output (e.g., red for missing headers, green for secure configurations).


## Installation and Setup
1. **Install Dependencies**:
   ```bash
   pip install requests python-whois dnspython vt-py colorama
   ```
2. **VirusTotal API Key**:
   - Sign up at `virustotal.com` and obtain an API key.
   - Replace `'API KEY'` in the script with your key.
3. **Python Version**: Requires Python 3.6+.

## Usage
Run the script from the command line with the following options:
```bash
python so1scan.v1.0.4.py -d <url> [-f <json|txt>] [-n <filename>] [-q]
```
- **Examples**:
  - Basic scan: `python so1scan.v1.0.4.py -d https://example.com`
  - Save as JSON: `python so1scan.v1.0.4.py -d https://example.com -f json -n output.json`
  - Save as text, quiet mode: `pythonso1scan.v1.0.4.py -d https://example.com -f txt -n output.txt -q`

### Example Output
**Terminal**:
```
Querying https://example.com
IP address of example.com: 93.184.216.34
MALICIOUS 0/90 vendors
Server: ECS (ewr/15CD)

HTTP SECURITY HEADERS
NO CSP
NO HSTS
NO X-FRAME
NO CORS
OK X-CONTENT-TYPE
BAD REFERRER POLICY

WHOIS LOOKUP
Registrar: MarkMonitor Inc.
Country: US
City: None
Creation date: 1995-08-13 04:00:00
Expiring on: 2026-08-12 04:00:00
Abuse email: abusecomplaints@markmonitor.com
```

**JSON Output** (`output.json`):
```json
{
  "Url": "https://example.com",
  "IP": "93.184.216.34",
  "VT Score": "0/90",
  "Server": "ECS (ewr/15CD)"
}
{
  "CSP": "NO CSP",
  "HSTS": "NO HSTS",
  "XFRAME": "NO X-FRAME",
  "CORS": "NO CORS",
  "XCONT": "OK X-CONTENT-TYPE",
  "REF_POL": "BAD REFERRER POLICY"
}
{
  "Registrar": "MarkMonitor Inc.",
  "Country": "US",
  "City": null,
  "Creation date": "1995-08-13T04:00:00",
  "Expiring on": "2026-08-12T04:00:00",
  "Abuse email": "abusecomplaints@markmonitor.com"
}
```

## Disclaimer
Use this tool responsibly and only on domains you have permission to analyze. Unauthorized scanning may violate laws or terms of service. Ensure compliance with VirusTotal’s API terms and handle sensitive data securely.
