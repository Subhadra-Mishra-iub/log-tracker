#!/bin/bash

# AI-Based Log Anomaly Checker - Setup Script
# This script sets up the environment and generates test data

echo "🚀 Setting up AI-Based Log Anomaly Checker"
echo "=========================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "📚 Installing dependencies..."
pip install -r requirements.txt

# Generate test log files
echo "📝 Generating test log files..."
python generate_logs.py

# Run demo
echo "🎬 Running demo..."
python demo.py

echo ""
echo "✅ Setup complete!"
echo ""
echo "📁 Project structure:"
echo "  • log_analyzer.py     - Main analyzer"
echo "  • demo.py             - Demo script"
echo "  • logs/               - Test log files"
echo "  • requirements.txt    - Dependencies"
echo "  • README.md           - Documentation"
echo ""
echo "🚀 Quick start:"
echo "  source venv/bin/activate"
echo "  python log_analyzer.py --log-file logs/security.log"
echo ""
echo "📊 View results:"
echo "  • anomaly_report.csv           - Detailed anomalies"
echo "  • log_analysis_dashboard.png   - Visualizations"
echo "  • alerts.txt                   - Alert summary"
