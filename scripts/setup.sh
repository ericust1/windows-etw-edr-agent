#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== ETW EDR Agent Setup ==="
echo ""

if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "This script targets Linux. On Windows, follow docs/setup-guide.md"
    exit 1
fi

echo "[1/4] Installing Python dependencies..."
cd "$PROJECT_ROOT"
python3 -m pip install --upgrade pip 2>/dev/null || pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "[2/4] Checking for .NET SDK..."
if command -v dotnet &>/dev/null; then
    echo "  .NET SDK found: $(dotnet --version)"
    cd "$PROJECT_ROOT/src/agent"
    dotnet build --configuration Release
    echo "  C# agent built successfully"
else
    echo "  .NET SDK not found - skipping C# build"
    echo "  Install .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0"
fi

echo ""
echo "[3/4] Generating Sysmon configuration..."
cd "$PROJECT_ROOT"
python -m src.modules.sysmon_config_generator --rules 1 3 7 8 10 11 --output sysmonconfig.xml
echo "  Configuration written to sysmonconfig.xml"

echo ""
echo "[4/4] Running tests..."
cd "$PROJECT_ROOT"
python -m pytest tests/ -v --tb=short

echo ""
echo "=== Setup Complete ==="
echo "Next steps:"
echo "  - Deploy agent to Windows endpoint (see docs/setup-guide.md)"
echo "  - Start ELK stack: cd lab && docker compose up -d"
echo "  - Run detection engine: python -m src.core.detection_engine"
