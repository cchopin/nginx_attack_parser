#!/usr/bin/env python3
import re
import requests
import os
import json
import glob
import datetime
import textwrap
from collections import defaultdict

CACHE_FILE = "ip_cache.json"
CACHE_DURATION_DAYS = 30

# Charger le cache depuis un fichier

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

def check_ip_reputation_cached(ip, api_key, cache):
    current_time = datetime.datetime.now().timestamp()
    if ip in cache:
        cached_entry = cache[ip]
        if current_time - cached_entry["timestamp"] < CACHE_DURATION_DAYS * 86400:
            return cached_entry["data"]

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    headers = {"Key": api_key, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()
        if response.status_code == 200 and "data" in data:
            cache[ip] = {"timestamp": current_time, "data": data["data"]}
            return data["data"]
        else:
            return None
    except requests.RequestException as e:
        print(f"Connection error for IP {ip}: {e}")
        return None

def print_single_line_table(header, rows):
    col_widths = [max(len(str(item)) for item in [header[i]] + [row[i] for row in rows]) for i in range(len(header))]

    horizontal_border = "┌" + "┬".join("─" * (w + 2) for w in col_widths) + "┐"
    separator = "├" + "┼".join("─" * (w + 2) for w in col_widths) + "┤"
    bottom_border = "└" + "┴".join("─" * (w + 2) for w in col_widths) + "┘"

    print(horizontal_border)
    print("│" + "│".join(f" {str(header[i]).ljust(col_widths[i])} " for i in range(len(header))) + "│")
    print(separator)

    for row in rows:
        print("│" + "│".join(f" {str(row[i]).ljust(col_widths[i])} " for i in range(len(row))) + "│")

    print(bottom_border)


def save_cache_to_file(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f)

# ANSI color codes for terminal output
COLORS = {
    "RESET": "\033[0m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "GREEN": "\033[92m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "BOLD": "\033[1m",
}

VERSION = "v1.2.0"

def print_ascii_banner():
    ascii_banner = r"""
▗▖  ▗▖ ▗▄▄▖▗▄▄▄▖▗▖  ▗▖▗▖  ▗▖    
▐▛▚▖▐▌▐▌     █  ▐▛▚▖▐▌ ▝▚▞▘     
▐▌ ▝▜▌▐▌▝▜▌  █  ▐▌ ▝▜▌  ▐▌      
▐▌  ▐▌▝▚▄▞▘▗▄█▄▖▐▌  ▐▌▗▞▘▝▚▖    
 ▗▄▖▗▄▄▄▖▗▄▄▄▖▗▄▖  ▗▄▄▖▗▖ ▗▖    
▐▌ ▐▌ █    █ ▐▌ ▐▌▐▌   ▐▌▗▞▘    
▐▛▀▜▌ █    █ ▐▛▀▜▌▐▌   ▐▛▚▖     
▐▌ ▐▌ █    █ ▐▌ ▐▌▝▚▄▄▖▐▌ ▐▌    
▗▄▄▖  ▗▄▖ ▗▄▄▖  ▗▄▄▖▗▄▄▄▖▗▄▄▖   
▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌▐▌   ▐▌   ▐▌ ▐▌  
▐▛▀▘ ▐▛▀▜▌▐▛▀▚▖ ▝▀▚▖▐▛▀▀▘▐▛▀▚▖  
▐▌   ▐▌ ▐▌▐▌ ▐▌▗▄▄▞▘▐▙▄▄▖▐▌ ▐▌  
                                
                                
"""
    print(ascii_banner)

def print_welcome():
    """Display a welcome message along with the ASCII banner."""
    print_ascii_banner()  
    welcome_lines = [
        f"{COLORS['BOLD']}Bienvenue dans Nginx Attack Parser {VERSION}{COLORS['RESET']}",
        f"{COLORS['BOLD']}GitHub: https://github.com/your_username/nginx-attack-parser{COLORS['RESET']}",
        f"{COLORS['BOLD']}Démarrage de Nginx Attack Parser...{COLORS['RESET']}"
    ]
    for line in welcome_lines:
        print(line)
    print()

def print_requirements():
    """Read and print the requirements from requirements.txt with a [*] prefix."""
    req_file = "requirements.txt"
    if os.path.exists(req_file):
        print(f"{COLORS['BOLD']}[*] Loading requirements from {req_file}:{COLORS['RESET']}")
        with open(req_file, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    print(f"[*] {line}")
        print()
    else:
        print(f"{COLORS['YELLOW']}[*] No requirements file found.{COLORS['RESET']}\n")

def get_api_key():
    """Load the AbuseIPDB API key from config.json or prompt the user."""
    config_file = "config.json"
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
                if "ABUSEIPDB_API_KEY" in config:
                    return config["ABUSEIPDB_API_KEY"]
        except Exception as e:
            print("Error reading configuration file:", e)
    api_key = input("Enter your AbuseIPDB API key: ").strip()
    try:
        with open(config_file, "w") as f:
            json.dump({"ABUSEIPDB_API_KEY": api_key}, f)
    except Exception as e:
        print("Error writing configuration file:", e)
    return api_key

def check_ip_reputation(ip, api_key):
    """Check the reputation of an IP address using AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()
        if response.status_code == 200 and "data" in data:
            return data["data"]
        else:
            return None
    except requests.RequestException as e:
        print(f"Connection error for IP {ip}: {e}")
        return None

def list_log_files(log_dir):
    """Return a list of log files in log_dir matching 'access.log*'."""
    files = glob.glob(os.path.join(log_dir, "access.log*"))
    log_files = []
    for file in files:
        try:
            stat = os.stat(file)
            last_modified = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            size = format_size(stat.st_size)
            filename = os.path.basename(file)
            log_files.append((filename, last_modified, size, file))
        except Exception as e:
            print(f"Error accessing file {file}: {e}")
    return log_files

def format_size(num_bytes):
    """Return a human-readable file size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"

def print_single_line_table(header, rows):
    """Print a table with solid single-line borders."""
    num_cols = len(header)
    col_widths = [len(str(h)) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    top = "┌" + "┬".join("─" * (w) for w in col_widths) + "┐"
    header_line = "|" + "|".join(str(header[i]).ljust(col_widths[i]) for i in range(num_cols)) + "|"
    separator = "├" + "┼".join("─" * (w) for w in col_widths) + "┤"
    bottom = "└" + "┴".join("─" * (w) for w in col_widths) + "┘"
    print(top)
    print(header_line)
    print(separator)
    for row in rows:
        row_line = "|" + "|".join(str(row[i]).ljust(col_widths[i]) for i in range(num_cols)) + "|"
        print(row_line)
    print(bottom)

def extract_timestamp(log_line):
    """Extract and return the timestamp from a log line."""
    match = re.search(r"\[(.*?)\]", log_line)
    if match:
        return match.group(1)
    return "Unknown"

def extract_status(log_line):
    """Extract the HTTP status code from a log line."""
    match = re.search(r'"\s*(?:.*?)\s*(\d{3})\s', log_line)
    if not match:
        match = re.search(r'(?:"[^"]*")?\s+(\d{3})\s+\d+', log_line)
    if match:
        return match.group(1)
    return "Unknown"

def get_status_color(status_code):
    """
    Return a color code for the HTTP status code.
    Codes 200-299 and 500-599 are red, 300-399 are yellow, and 400-499 are green.
    """
    try:
        code = int(status_code)
        if 200 <= code < 300:
            return COLORS["RED"]
        elif 300 <= code < 400:
            return COLORS["YELLOW"]
        elif 400 <= code < 500:
            return COLORS["GREEN"]
        elif 500 <= code < 600:
            return COLORS["RED"]
        else:
            return ""
    except:
        return ""

# Refined attack patterns
sql_injection_pattern = r"(?i)(?:\bunion\s+select\b|\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1\b|\bexec\s*\(|\bsleep\s*\(|\bbenchmark\s*\(|/solr/admin/cores)"
hex_encoding_pattern = r"(?:\\x[0-9a-fA-F]{2})+"

attack_patterns = {
    "SQL Injection": sql_injection_pattern,
    "Brute-force (login)": r"(?i)(wp-login\.php|admin|login|passwd|password|auth)",
    "File Inclusion": r"(\.\./|/etc/passwd|/proc/self/environ)",
    "Malicious Bots": r"(?i)(sqlmap|nmap|nikto|w00tw00t|acunetix)",
    "Hex Encoded Attack": hex_encoding_pattern,
    "Solr Exploit": r"(?i)(/solr/admin/cores)",
    "Path Traversal": r"(?i)(/\.\./?|\.\.\\|\.\.\/|%2e%2e%2f)",
    "Command Injection": r"(?i)(;|\||\|\||&&|`|\$\(|\${)",
    "XSS Attack": r"(?i)(<script>|javascript:|onerror=|onload=|eval\()"
}

# Colors assigned to each attack type (used in detailed events)
ATTACK_COLORS = {
    "SQL Injection": COLORS["RED"],
    "Other Injection": COLORS["MAGENTA"],
    "Brute-force (login)": COLORS["YELLOW"],
    "File Inclusion": COLORS["BLUE"],
    "Malicious Bots": COLORS["CYAN"],
    "Hex Encoded Attack": COLORS["GREEN"],
    "Solr Exploit": COLORS["RED"] + COLORS["BOLD"],
    "Path Traversal": COLORS["BLUE"] + COLORS["BOLD"],
    "Command Injection": COLORS["MAGENTA"] + COLORS["BOLD"],
    "XSS Attack": COLORS["YELLOW"] + COLORS["BOLD"],
}

def normalize_log_line(line):
    """Normalize a log line by removing newlines and extra spaces."""
    result = ""
    in_quotes = False
    for char in line:
        if char == '"':
            in_quotes = not in_quotes
        if char.isspace() and not in_quotes and result and result[-1].isspace():
            continue
        result += char
    return result.strip()

def detect_attacks(log_files, days):
    """
    Scan the provided log files for attack attempts within the last 'days' days.
    Each log line is classified only once to prevent duplicate attack types.
    """
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    attack_logs = defaultdict(list)
    for log_file in log_files:
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                raw_lines = f.readlines()
            
            i = 0
            while i < len(raw_lines):
                line = raw_lines[i].rstrip()
                # Check if the line starts with an IP address
                ip_match = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)", line)
                if not ip_match:
                    i += 1
                    continue
                
                ip = ip_match.group(1)
                j = i + 1
                while j < len(raw_lines) and not re.match(r"^\s*\d+\.\d+\.\d+\.\d+", raw_lines[j]):
                    line += " " + raw_lines[j].strip()
                    j += 1
                i = j
                line = normalize_log_line(line)
                
                date_match = re.search(r"\[(.*?)\]", line)
                if not date_match:
                    continue
                date_str = date_match.group(1)
                try:
                    log_date = datetime.datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
                except ValueError:
                    continue
                if log_date < cutoff:
                    continue

                req_match = re.search(r'"(.*?)"', line)
                request = req_match.group(1) if req_match else line

                # Special case: Hex Encoded Attack
                if re.search(hex_encoding_pattern, request):
                    attack_logs[ip].append(("Hex Encoded Attack", line))
                    continue
                # Special case: Solr Exploit
                if re.search(r'(?i)(/solr/admin/cores)', request):
                    attack_logs[ip].append(("Solr Exploit", line))
                    continue

                # Only classify the request once
                detected = False
                for attack, pattern in attack_patterns.items():
                    if detected:
                        break
                    if attack in ["Hex Encoded Attack", "Solr Exploit"]:
                        continue
                    if attack == "SQL Injection":
                        if re.search(r'[^\x20-\x7E]', request):
                            attack_logs[ip].append(("Other Injection", line))
                            detected = True
                        elif re.search(pattern, request):
                            attack_logs[ip].append(("SQL Injection", line))
                            detected = True
                    elif re.search(pattern, request, re.IGNORECASE):
                        attack_logs[ip].append((attack, line))
                        detected = True
        
        except Exception as e:
            print(f"Error reading file {log_file}: {e}")
    
    return attack_logs

def generate_report(attack_logs, api_key):
    """
    Generate and print detailed log events and a consolidated final table report.
    The final table is colored, less wide, and uses continuous vertical borders.
    """
    total_ips = len(attack_logs)
    total_attacks = sum(len(logs) for logs in attack_logs.values())
    if total_ips == 0:
        print("No attacks detected in the specified period.")
        return

    attack_type_summary = {}
    country_summary = {}
    ip_reputation_cache = {}
    detailed_events = []
    api_failure = False  

    # Process detected attacks and retrieve reputation info
    for ip, logs in attack_logs.items():
        if ip in ip_reputation_cache:
            reputation = ip_reputation_cache[ip]
        else:
            reputation = check_ip_reputation(ip, api_key)
            ip_reputation_cache[ip] = reputation

        if reputation:
            abuse_score = reputation.get("abuseConfidenceScore", 0)
            country = reputation.get("countryCode", "Unknown")
            isp = reputation.get("isp", "Unknown")
            reports = reputation.get("totalReports", 0)
            if abuse_score > 50:
                level = "DANGER"
                symbol = "‼"
                color = COLORS["RED"]
            elif abuse_score > 10:
                level = "SUSPICIOUS"
                symbol = "⚠"
                color = COLORS["YELLOW"]
            else:
                level = "Low Risk"
                symbol = "✓"
                color = COLORS["GREEN"]
            level_str = f"{color}{symbol} {level}{COLORS['RESET']}"
            ip_info = f"{color}Country: {country}, ISP: {isp}{COLORS['RESET']}"
        else:
            api_failure = True
            level_str = "? Unknown"
            reports = "N/A"
            ip_info = "No info"
            country = "Unknown"

        # Build summary by country using 'country'
        if country in country_summary:
            country_summary[country]["ips"].add(ip)
            country_summary[country]["attacks"] += len(logs)
        else:
            country_summary[country] = {"ips": {ip}, "attacks": len(logs)}

        for attack, log_line in logs:
            timestamp = extract_timestamp(log_line)
            status_code = extract_status(log_line)
            attack_type_summary[attack] = attack_type_summary.get(attack, 0) + 1
            event = {
                "Level": level_str,
                "IP": ip,
                "IP Info": ip_info,
                "Reports": reports,
                "Timestamp": timestamp,
                "Attack": attack,
                "Log": log_line,
                "Status": status_code,
                "Country": country
            }
            detailed_events.append(event)

    if api_failure:
        print(f"\n{COLORS['YELLOW']}Attention: L'API d'AbuseIPDB ne répond plus (quota atteint ou indisponible). Les informations de réputation sont incomplètes.{COLORS['RESET']}\n")

    # Print detailed log events
    print(f"\n{COLORS['BOLD']}=== Detailed Log Events ==={COLORS['RESET']}")
    for event in detailed_events:
        print("─" * 80)
        print(f"Level     : {event['Level']}")
        print(f"IP        : {event['IP']}")
        print(f"IP Info   : {event['IP Info']}")
        print(f"Reports   : {event['Reports']}")
        print(f"Timestamp : {event['Timestamp']}")
        status_color = get_status_color(event["Status"])
        print(f"Status    : {status_color}{event['Status']}{COLORS['RESET']}")
        attack_color = ATTACK_COLORS.get(event["Attack"], "")
        print(f"Attack    : {attack_color}{event['Attack']}{COLORS['RESET']}")
        log_display = textwrap.fill(event["Log"], width=80)
        print(f"Log       : {log_display}")
    print("─" * 80)

    # Build consolidated table by country
    # Columns: Country | Susp. IPs | Tot. Att | Hex | Brute | File | Path | Solr | Cmd/Bots
    col_names = ["Country", "Susp.IPs", "Tot.Att", "Hex", "Brute", "File", "Path", "Solr", "Cmd/Bots"]
    # Reduced column widths
    col_widths = [8, 10, 10, 8, 8, 8, 8, 8, 9]

    # Create a summary table per country with counts for selected attack types:
    # "Hex Encoded Attack", "Brute-force (login)", "File Inclusion", "Path Traversal", "Solr Exploit"
    # and a combination of "Command Injection" and "Malicious Bots" under "Cmd/Bots"
    country_table = {}
    for event in detailed_events:
        c = event["Country"]
        if c not in country_table:
            country_table[c] = {
                "ips": set(),
                "total": 0,
                "Hex": 0,
                "Brute": 0,
                "File": 0,
                "Path": 0,
                "Solr": 0,
                "Cmd/Bots": 0
            }
        country_table[c]["ips"].add(event["IP"])
        country_table[c]["total"] += 1
        att = event["Attack"]
        if att == "Hex Encoded Attack":
            country_table[c]["Hex"] += 1
        elif att == "Brute-force (login)":
            country_table[c]["Brute"] += 1
        elif att == "File Inclusion":
            country_table[c]["File"] += 1
        elif att == "Path Traversal":
            country_table[c]["Path"] += 1
        elif att == "Solr Exploit":
            country_table[c]["Solr"] += 1
        elif att in ("Command Injection", "Malicious Bots"):
            country_table[c]["Cmd/Bots"] += 1

    # Calculate global totals
    global_ips = sum(len(country_table[c]["ips"]) for c in country_table)
    global_total = sum(country_table[c]["total"] for c in country_table)
    global_hex = sum(country_table[c]["Hex"] for c in country_table)
    global_brute = sum(country_table[c]["Brute"] for c in country_table)
    global_file = sum(country_table[c]["File"] for c in country_table)
    global_path = sum(country_table[c]["Path"] for c in country_table)
    global_solr = sum(country_table[c]["Solr"] for c in country_table)
    global_cmd = sum(country_table[c]["Cmd/Bots"] for c in country_table)

    # Function to print a table line with given alignments without extra spaces between borders
    def print_table_line(values, col_widths, alignments, color=""):
        line = "|"
        for i, val in enumerate(values):
            if alignments[i] == "left":
                cell = str(val).ljust(col_widths[i])
            else:
                cell = str(val).rjust(col_widths[i])
            line += color + cell + COLORS["RESET"] + "|"
        print(line)

    # Print table border with continuous vertical lines
    def print_border(col_widths):
        border = "+"
        for w in col_widths:
            border += "─" * w + "+"
        print(border)

    # Prepare rows per country (sorted by country code)
    country_rows = []
    for c in sorted(country_table.keys()):
        data = country_table[c]
        row = [
            c,
            len(data["ips"]),
            data["total"],
            data["Hex"],
            data["Brute"],
            data["File"],
            data["Path"],
            data["Solr"],
            data["Cmd/Bots"]
        ]
        country_rows.append(row)

    # Global total row
    total_row = ["TOTAL", global_ips, global_total, global_hex, global_brute, global_file, global_path, global_solr, global_cmd]

    # Percentage row (calculated with respect to global_total)
    def format_percentage(val):
        perc = (val * 100 / global_total) if global_total else 0
        if abs(perc - round(perc)) < 0.05:
            return f"{int(round(perc))}%"
        else:
            return f"{perc:.1f}%"

    percent_row = ["%", "---", "100%",
                   format_percentage(global_hex),
                   format_percentage(global_brute),
                   format_percentage(global_file),
                   format_percentage(global_path),
                   format_percentage(global_solr),
                   format_percentage(global_cmd)]

    # Print the consolidated report table with header and colors
    header_color = "\033[1;33m"  # Bold yellow
    total_color = "\033[1;32m"   # Bold green

    print(f"\n\033[1;37;44m=================== CONSOLIDATED SECURITY ATTACK REPORT ===================\033[0m")
    print("")
    print(header_color + "UNIFIED TABLE - COMPLETE SECURITY ATTACK SUMMARY" + COLORS["RESET"])
    print_border(col_widths)
    print_table_line(col_names, col_widths, ["left", "right", "right", "right", "right", "right", "right", "right", "right"], header_color)
    print_border(col_widths)
    for row in country_rows:
        print_table_line(row, col_widths, ["left", "right", "right", "right", "right", "right", "right", "right", "right"])
    print_border(col_widths)
    print_table_line(total_row, col_widths, ["left", "right", "right", "right", "right", "right", "right", "right", "right"], total_color)
    print_table_line(percent_row, col_widths, ["left", "right", "right", "right", "right", "right", "right", "right", "right"], total_color)
    print_border(col_widths)
    print("")
    print(header_color + "Legend:" + COLORS["RESET"])
    print("- Cmd/Bots: Combination of Command Injection and Malicious Bots")
    print(f"\033[1;37;44m{'=' * 83}\033[0m\n")

def main():
    print_welcome()
    print_requirements()

    api_key = get_api_key()
    cache = load_cache()

    days = int(input("[?] Enter the number of days to analyze logs (default: 7): ") or 7)

    log_dir = "/var/log/nginx"
    log_files_info = list_log_files(log_dir)
    if not log_files_info:
        print(f"No log files found in {log_dir}")
        return

    table_rows = [[info[0], info[1], info[2]] for info in log_files_info]
    print("\nAvailable log files:")
    print_single_line_table(["File", "Modified", "Size"], table_rows)

    default_log = os.path.join(log_dir, "access.log")
    log_file_input = input(f"[?] Enter the log file to analyze (default: access.log): ") or "access.log"
    log_file = os.path.join(log_dir, log_file_input)

    if not os.path.isfile(log_file):
        print(f"Selected log file '{log_file}' does not exist. Exiting.")
        return

    print(f"Analyzing logs from: {log_file}")
    attack_logs = detect_attacks([log_file], days)

    detailed_events = []
    for ip in attack_logs:
        reputation = check_ip_reputation_cached(ip, api_key, cache)
        if reputation:
            detailed_events.append((ip, reputation))

    save_cache(cache)

    generate_report(attack_logs, api_key)

if __name__ == "__main__":
    main()
