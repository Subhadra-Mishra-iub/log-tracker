#!/usr/bin/env python3
"""
Demo Script for AI-Based Log Anomaly Checker
Demonstrates the key features and capabilities of the log analyzer.
"""

import os
import time
from log_analyzer import LogAnalyzer

def run_demo():
    """Run a comprehensive demo of the log analyzer"""
    print("🎬 AI-Based Log Anomaly Checker - Demo")
    print("=" * 50)
    
    # Available log files
    log_files = [
        ("logs/application.log", "Application Logs", "50K entries, 3% anomaly rate"),
        ("logs/database.log", "Database Logs", "30K entries, 8% anomaly rate"),
        ("logs/security.log", "Security Logs", "15K entries, 12% anomaly rate"),
        ("logs/error.log", "Error Logs", "20K entries, 15% anomaly rate"),
        ("logs/combined.log", "Combined Logs", "200K entries, 6% anomaly rate")
    ]
    
    print("\n📁 Available Test Log Files:")
    for i, (file_path, description, details) in enumerate(log_files, 1):
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            print(f"  {i}. {description}")
            print(f"     File: {file_path}")
            print(f"     Details: {details}")
            print(f"     Size: {file_size:.1f} MB")
            print()
    
    # Demo with security logs (high anomaly rate)
    print("🔍 Running Demo Analysis on Security Logs...")
    print("This will demonstrate both ML and pattern-based detection.")
    print()
    
    start_time = time.time()
    
    # Initialize analyzer
    analyzer = LogAnalyzer("logs/security.log")
    
    # Run complete analysis
    analyzer.run_analysis()
    
    end_time = time.time()
    processing_time = end_time - start_time
    
    print(f"\n⏱️  Processing Time: {processing_time:.2f} seconds")
    print(f"📊 Processing Rate: {analyzer.stats.get('total_entries', 0) / processing_time:.0f} entries/second")
    
    # Show file outputs
    print("\n📄 Generated Files:")
    output_files = [
        "anomaly_report.csv",
        "log_analysis_dashboard.png", 
        "alerts.txt"
    ]
    
    for file in output_files:
        if os.path.exists(file):
            file_size = os.path.getsize(file) / 1024
            print(f"  ✅ {file} ({file_size:.1f} KB)")
        else:
            print(f"  ❌ {file} (not found)")
    
    print("\n🎯 Demo Complete!")
    print("Check the generated files to see detailed results and visualizations.")

def show_anomaly_sample():
    """Show a sample of detected anomalies"""
    print("\n🔍 Sample Anomalies Detected:")
    print("-" * 40)
    
    if os.path.exists("anomaly_report.csv"):
        import pandas as pd
        df = pd.read_csv("anomaly_report.csv")
        
        # Show first 5 anomalies
        print("Top 5 Anomalies:")
        for i, row in df.head().iterrows():
            print(f"\n{i+1}. Line {row['line_number']}")
            print(f"   Type: {row['anomaly_type']}")
            print(f"   Service: {row['service']}")
            print(f"   Message: {row['message'][:80]}...")
    else:
        print("No anomaly report found. Run the analyzer first.")

if __name__ == "__main__":
    run_demo()
    show_anomaly_sample()
