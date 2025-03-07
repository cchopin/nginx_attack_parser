# Nginx Attack Parser

A powerful Python tool that scans Nginx logs for potential security threats, analyzes attack patterns, and generates detailed reports with IP reputation data from AbuseIPDB.

## Features

- **Interactive Startup:**  
  - Displays a welcome message with version information
  - Prompts for the number of days to analyze logs (default: 7)
  - Prompts for the Nginx log directory (default: `/var/log/nginx`)
 
    <img width="809" alt="Capture d’écran 2025-03-07 à 15 59 55" src="https://github.com/user-attachments/assets/4c7989f9-1ded-49e6-a5f4-1683eeb1fa13" />


- **Smart Log File Selection:**  
  - Lists available log files in a clean table with information on last modified date and size
  - Automatically selects `access.log` by default or processes all log files

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

- **Color-Coded Reporting:**  
  - Detailed event logs with color-highlighted risk levels and attack types
  - HTTP status codes colored according to security implications (200-299 & 500-599 in red, etc.)
  - Consolidated final report with attack distribution by country


<img width="724" alt="Capture d’écran 2025-03-07 à 16 00 10" src="https://github.com/user-attachments/assets/6087b6f3-6806-49f4-8838-249a85739530" />



## Prerequisites

- Python 3.x
- An API key from [AbuseIPDB](https://www.abuseipdb.com/) (free tier available)

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your_username/nginx-attack-parser.git
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
- **Consolidated Reporting:** All metrics are combined into a single, easy-to-read table

## Requirements

- requests

## License

This project is available under the MIT License.
