#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "[+] Installing Python dependencies (user can use venv manually if preferred)..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

echo "[+] Done."

