# Nginx Attack Parser

A powerful Python tool that scans Nginx logs for potential security threats, analyzes attack patterns, and generates detailed reports with IP reputation data from AbuseIPDB.

## Features

- **Interactive Startup:**
    - Displays a welcome message with version information
    - Prompts for the number of days to analyze logs (default: 7)
    - Prompts for the Nginx log directory (default: `/var/log/nginx`)


<img width="1124" alt="Capture d'écran 2025-03-08 à 17 38 46" src="https://github.com/user-attachments/assets/612cfaa1-0f22-43f2-b178-08044bfa7477" />


- **Smart Log File Selection:**
    - Lists available log files in a clean table with information on last modified date and size
    - Automatically selects `access.log` by default or processes all log files
    - Sorts log files by date (newest first) for easier navigation

- **Comprehensive Attack Detection:**
    - **SQL Injection:** Detects classic SQL injection patterns (`union select`, `or '1'='1`, etc.)
    - **Brute-force:** Identifies login attempts targeting admin pages or authentication endpoints
    - **File Inclusion:** Detects path traversal attempts targeting sensitive files
    - **Malicious Bots:** Identifies known malicious scanning tools (sqlmap, nmap, nikto, etc.)
    - **Hex Encoded Attacks:** Detects hex-encoded payloads often used to bypass WAFs
    - **Solr Exploits:** Identifies attacks targeting Apache Solr vulnerabilities
    - **Path Traversal:** Detects attempts to navigate to unauthorized directories
    - **Command Injection:** Identifies attempts to execute system commands
    - **XSS Attacks:** Detects Cross-Site Scripting attempts

- **IP Reputation Analysis:**
    - Automatically retrieves IP reputation data via the AbuseIPDB API
    - Classifies IPs into risk levels (DANGER, SUSPICIOUS, Low Risk) based on reputation scores
    - Provides country and ISP information for each suspicious IP
    - Implements efficient IP reputation caching system (30-day cache by default)

- **Optimized Performance with IP Caching:**
    - Stores IP reputation data locally to minimize API calls
    - Automatically reuses cached data for previously queried IPs
    - Reduces API usage and speeds up repeat analyses
    - Self-maintaining cache system that removes outdated entries

- **Color-Coded Reporting:**
    - Detailed event logs with color-highlighted risk levels and attack types
    - HTTP status codes colored according to security implications (200-299 & 500-599 in red, etc.)
    - Consolidated final report with attack distribution by country
    - Professional table formatting with proper box-drawing characters


<img width="684" alt="Capture d'écran 2025-03-08 à 17 34 13" src="https://github.com/user-attachments/assets/8b82a1c7-be6b-4d1d-9837-d26084c6fb83" />





## Prerequisites

- Python 3.x
- An API key from [AbuseIPDB](https://www.abuseipdb.com/) (free tier available)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cchopin/nginx-attack-parser.git
   cd nginx-attack-parser
   ```

2. **Run the setup script:**
   ```bash
   chmod +x run.sh
   ./run.sh
   ```

   The script will:
    - Create a Python virtual environment if it doesn't exist
    - Activate the virtual environment
    - Upgrade pip and install required dependencies
    - Launch the Nginx attack parser

3. **Alternative manual setup:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install --upgrade pip
   pip install -r requirements.txt
   python nginx_attack_parser.py
   ```

## Usage

1. When prompted, enter the number of days of logs to analyze
2. Specify the Nginx log directory path
3. Select a specific log file or press Enter to analyze all logs
4. If running for the first time, you'll be prompted to enter your AbuseIPDB API key
    - The key will be saved in `config.json` for future use

### IP Reputation Cache

The tool automatically creates and maintains an IP reputation cache file (`ip_cache.json`) to:
- Avoid repeatedly querying the AbuseIPDB API for the same IP addresses
- Stay within API rate limits, especially for free tier users
- Significantly speed up analysis when scanning multiple log files

Cache entries expire after 30 days by default. The cache is automatically cleaned of expired entries on startup.

## Sample Output

The tool generates two main types of output:

1. **Detailed Log Events** - For each suspicious request:
   ```
   Level     : ‼ DANGER
   IP        : 192.168.1.1
   IP Info   : Country: US, ISP: Example Provider
   Reports   : 253
   Timestamp : 07/Mar/2025:09:31:49 +0100
   Status    : 404
   Attack    : SQL Injection
   Log       : 192.168.1.1 - - [07/Mar/2025:09:31:49 +0100] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 404 117 "-" "Mozilla/5.0"
   ```

2. **Consolidated Security Attack Report** - A unified table showing:
    - Distribution of attacks by country
    - Breakdown of attack types
    - Total metrics and percentages

## How It Works

- **Log Parsing:** Handles multi-line log entries and normalizes them for consistent analysis
- **Attack Classification:** Each request is classified by a single attack type to avoid duplicates
- **Risk Assessment:** IP addresses are evaluated based on their AbuseIPDB reputation scores
- **IP Caching System:** Saves IP reputation data with timestamps for efficient reuse
- **Consolidated Reporting:** All metrics are combined into a single, easy-to-read table

## Requirements

- requests

## License

This project is available under the MIT License.