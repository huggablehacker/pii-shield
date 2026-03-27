#!/usr/bin/env bash
# PII Shield – One-time setup script (Mac / Linux)
# Run: chmod +x setup.sh && ./setup.sh

set -e

echo ""
echo "🛡️  PII Shield Setup"
echo "════════════════════════════════════════"

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "❌  Python 3 is required. Install from https://python.org"
    exit 1
fi

PY=$(python3 --version 2>&1)
echo "✅  Found $PY"

# Virtual environment
if [ ! -d ".venv" ]; then
    echo "📦  Creating virtual environment …"
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "✅  Virtual environment active"

# Install dependencies
echo "📥  Installing Python packages …"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

# Download spaCy model (try large, fall back to small)
echo "🧠  Downloading spaCy language model …"
if python -m spacy download en_core_web_lg 2>/dev/null; then
    echo "✅  Downloaded en_core_web_lg (best accuracy)"
else
    echo "⚠️   Large model unavailable, downloading small model …"
    python -m spacy download en_core_web_sm
    echo "✅  Downloaded en_core_web_sm"
fi

echo ""
echo "════════════════════════════════════════"
echo "✅  Setup complete!"
echo ""
echo "Usage (activate venv first):"
echo "  source .venv/bin/activate"
echo "  python pii_shield.py anonymize your_document.pdf"
echo "  python pii_shield.py anonymize data.xlsx --output clean.txt"
echo "  python pii_shield.py sessions"
echo "  python pii_shield.py restore clean.txt --session <ID>"
echo ""
