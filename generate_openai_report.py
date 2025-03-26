#!/usr/bin/env python3
"""
Script to generate an enhanced vulnerability report using OpenAI's gpt-4o model.
This script loads environment variables from .env and properly passes the API key
to the report generator.
"""

import os
import sys
import subprocess
from dotenv import load_dotenv

def generate_report():
    """Generate an enhanced report using OpenAI's gpt-4o model."""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get the OpenAI API key
    api_key = os.getenv("LLM_OPENAI_API_KEY")
    
    if not api_key:
        print("❌ Error: LLM_OPENAI_API_KEY not found in .env file")
        return False
    
    # Input and output file paths
    input_file = "results/20250317185805.json"
    output_file = "results/enhanced_openai_4o.json"
    report_output = "reports/enhanced_report_openai_4o.html"
    
    # Build the command
    cmd = [
        "python3", "report_generator.py", "enhance-with-llm",
        "--input", input_file,
        "--output", output_file,
        "--provider", "openai",
        "--model", "gpt-4o",
        "--api-key", api_key,
        "--generate-report",
        "--report-format", "html",
        "--report-output", report_output
    ]
    
    print(f"🔄 Generating enhanced report with OpenAI gpt-4o model...")
    print(f"📄 Input file: {input_file}")
    print(f"📄 Output file: {output_file}")
    print(f"📊 Report output: {report_output}")
    
    try:
        # Run the command
        process = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ Report generation successful!")
        print(f"📊 Report saved to: {report_output}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error generating report: {e}")
        print(f"Error output: {e.stderr}")
        return False

if __name__ == "__main__":
    print("🔍 OpenAI Enhanced Report Generator")
    print("----------------------------------")
    success = generate_report()
    sys.exit(0 if success else 1)
