#!/usr/bin/env python3
"""
Generate Missing Report Script

This script generates a report for an existing scan result file.
It's used when a report file is missing but the scan result JSON exists.
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path

def generate_report(scan_id, format='html'):
    """
    Generate a report for an existing scan result
    
    Args:
        scan_id (str): The scan ID to generate a report for
        format (str): The report format (html, json, csv)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get the project root directory
        root_dir = Path(__file__).parent.parent
        results_dir = root_dir / 'results'
        reports_dir = root_dir / 'reports'
        
        # Ensure directories exist
        reports_dir.mkdir(exist_ok=True)
        
        # Check for scan result files
        scan_file = results_dir / f"{scan_id}.json"
        enhanced_scan_file = results_dir / f"{scan_id}_enhanced.json"
        
        # Use enhanced file if it exists, otherwise use regular file
        if enhanced_scan_file.exists():
            input_file = enhanced_scan_file
            print(f"Using enhanced scan result file: {enhanced_scan_file}")
        elif scan_file.exists():
            input_file = scan_file
            print(f"Using regular scan result file: {scan_file}")
        else:
            print(f"Error: No scan result file found for scan ID: {scan_id}")
            return False
        
        # Define the output report file
        report_file = reports_dir / f"report_{scan_id}.{format}"
        
        # Extract scan ID from the filename
        scan_id_from_file = input_file.stem.split('_')[0]
        
        # Run the report generator script using quick-report command
        cmd = [
            sys.executable,
            str(root_dir / "report_generator.py"),
            "quick-report",
            scan_id_from_file,
            "--format", format,
            "--output", str(report_file)
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"Successfully generated report: {report_file}")
            return True
        else:
            print(f"Error generating report: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Generate a report for an existing scan result')
    parser.add_argument('scan_id', help='Scan ID to generate a report for')
    parser.add_argument('--format', choices=['html', 'json', 'csv'], default='html',
                        help='Report format (default: html)')
    
    args = parser.parse_args()
    
    success = generate_report(args.scan_id, args.format)
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
