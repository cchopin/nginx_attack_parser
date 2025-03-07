#!/bin/bash
# This script sets up the virtual environment, installs the required dependencies,
# and runs the Nginx attack parser.

set -e

echo "[*] Checking for virtual environment..."
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment..."
source venv/bin/activate

echo "[*] Upgrading pip..."
pip install --upgrade pip | sed 's/^/[*] /'

echo "[*] Installing requirements..."
pip install -r requirements.txt | sed 's/^/[*] /'

echo "[*] Running Nginx attack parser..."
python nginx_attack_parser.py "$@"
