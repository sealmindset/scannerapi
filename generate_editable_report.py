#!/usr/bin/env python3
"""
Script to generate an editable report using LLM enhancement and launch the web interface.
This script:
1. Enhances scan results using the specified LLM provider and model
2. Stores the enhanced content in Redis
3. Launches the Express.js web interface for editing and generating reports
"""

import os
import sys
import json
import subprocess
import time
import argparse
from dotenv import load_dotenv
import redis

def check_redis_connection():
    """Check if Redis is running and accessible."""
    try:
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis connection successful")
        return True
    except redis.exceptions.ConnectionError:
        print("❌ Redis connection failed. Make sure Redis is running.")
        return False

def generate_enhanced_content(scan_id, provider='openai', model='gpt-4o'):
    """Generate enhanced content using the specified LLM provider and model."""
    # Load environment variables from .env file
    load_dotenv()
    
    # Get the OpenAI API key
    api_key = os.getenv("LLM_OPENAI_API_KEY")
    
    if not api_key and provider == 'openai':
        print("❌ Error: LLM_OPENAI_API_KEY not found in .env file")
        return False
    
    # Input and output file paths with absolute paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_file = os.path.join(script_dir, "results", f"{scan_id}.json")
    output_file = os.path.join(script_dir, "results", f"{scan_id}_enhanced.json")
    
    if not os.path.exists(input_file):
        print(f"❌ Error: Input file not found: {input_file}")
        return False
    
    # Build the command
    cmd = [
        "python3", "report_generator.py", "enhance-with-llm",
        "--input", input_file,
        "--output", output_file,
        "--provider", provider,
        "--model", model
    ]
    
    if provider == 'openai':
        cmd.extend(["--api-key", api_key])
    
    print(f"🔄 Generating enhanced content with {provider}/{model} model...")
    print(f"📄 Input file: {input_file}")
    print(f"📄 Output file: {output_file}")
    
    try:
        # Run the command
        process = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ Content enhancement successful!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error generating enhanced content: {e}")
        print(f"Error output: {e.stderr}")
        return False

def store_in_redis(scan_id):
    """Store the enhanced content in Redis for the web interface."""
    try:
        # Load the enhanced content with absolute path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        input_file = os.path.join(script_dir, "results", f"{scan_id}_enhanced.json")
        
        if not os.path.exists(input_file):
            print(f"❌ Error: Enhanced file not found: {input_file}")
            return False
        
        with open(input_file, 'r') as f:
            enhanced_content = json.load(f)
        
        # Connect to Redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        
        # Store metadata
        r.set(f"report:{scan_id}:metadata", json.dumps({
            "scanId": scan_id,
            "timestamp": enhanced_content.get("start_time", ""),
            "target": enhanced_content.get("target", ""),
            "summary": "Vulnerability scan report"
        }))
        
        # Store vulnerabilities
        vuln_list = []
        for scanner_data in enhanced_content.get("scanners", []):
            scanner_name = scanner_data.get("name", "unknown")
            for finding in scanner_data.get("findings", []):
                # Generate a unique ID for the vulnerability
                vuln_id = finding.get("finding_id", "") or f"{scanner_name}:{finding.get('vulnerability', '').replace(' ', '_').lower()}"
                
                # Store each field separately
                r.set(f"report:{scan_id}:vuln:{vuln_id}:title", finding.get("vulnerability", ""))
                r.set(f"report:{scan_id}:vuln:{vuln_id}:severity", finding.get("severity", ""))
                r.set(f"report:{scan_id}:vuln:{vuln_id}:description", finding.get("risk_assessment", ""))
                r.set(f"report:{scan_id}:vuln:{vuln_id}:remediation", finding.get("remediation", ""))
                
                # Store details
                details = {
                    "endpoint": finding.get("endpoint", ""),
                    "details": finding.get("details", "")
                }
                r.set(f"report:{scan_id}:vuln:{vuln_id}:details", json.dumps(details))
                
                # Store evidence if available
                if finding.get("evidence"):
                    r.set(f"report:{scan_id}:vuln:{vuln_id}:evidence", json.dumps(finding.get("evidence", {})))
                
                # Add to vulnerability list
                vuln_list.append({
                    "id": vuln_id,
                    "title": finding.get("vulnerability", ""),
                    "severity": finding.get("severity", ""),
                    "scanner": scanner_name
                })
        
        # Store vulnerability list
        r.set(f"report:{scan_id}:vulnList", json.dumps(vuln_list))
        
        print(f"✅ Enhanced content stored in Redis for scan ID: {scan_id}")
        return True
    except Exception as e:
        print(f"❌ Error storing content in Redis: {str(e)}")
        return False

def launch_web_interface(scan_id=None):
    """Launch the Express.js web interface.
    
    Args:
        scan_id (str, optional): The scan ID to display in the URL. Defaults to None.
    """
    try:
        # Check if the web interface is already running
        result = subprocess.run(
            ["lsof", "-i", ":3000"],
            capture_output=True, text=True
        )
        
        if "node" in result.stdout:
            print("✅ Web interface is already running on port 3000")
            return True
        
        print("🚀 Launching web interface...")
        
        # Start the web interface in a new process
        process = subprocess.Popen(
            ["node", "app.js"],
            cwd="web-interface",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for the server to start
        time.sleep(2)
        
        # Check if the server started successfully
        if process.poll() is None:
            print("✅ Web interface launched successfully!")
            if scan_id:
                print(f"📊 Access the report editor at: http://localhost:3000/report-editor/editor/{scan_id}")
            else:
                print("📊 Access the web interface at: http://localhost:3000")
            return True
        else:
            stdout, stderr = process.communicate()
            print(f"❌ Error launching web interface: {stderr}")
            return False
    except Exception as e:
        print(f"❌ Error launching web interface: {str(e)}")
        return False

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Generate an editable report from scan results')
    
    parser.add_argument('--scan-id', required=True, help='Scan ID to process')
    parser.add_argument('--provider', default='openai', choices=['openai', 'ollama'], 
                        help='LLM provider (openai or ollama)')
    parser.add_argument('--model', default='gpt-4o', 
                        help='LLM model to use (e.g., gpt-4o for OpenAI, llama3.3 for Ollama)')
    parser.add_argument('--no-launch-web', action='store_true', 
                        help='Do not launch the web interface (useful when called from the web interface)')
    parser.add_argument('--skip-enhance', action='store_true',
                        help='Skip the enhancement step (use if already enhanced)')
    
    return parser.parse_args()

def main():
    """Main function to run the script."""
    print("🔍 Editable Report Generator")
    print("---------------------------")
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Check Redis connection
    if not check_redis_connection():
        return False
    
    # Generate enhanced content if not skipped
    if not args.skip_enhance:
        if not generate_enhanced_content(args.scan_id, args.provider, args.model):
            return False
    else:
        print("🔍 Enhancement step skipped (--skip-enhance option)")
        # Copy the original results file to the enhanced file path
        import shutil
        script_dir = os.path.dirname(os.path.abspath(__file__))
        input_file = os.path.join(script_dir, "results", f"{args.scan_id}.json")
        output_file = os.path.join(script_dir, "results", f"{args.scan_id}_enhanced.json")
        
        if not os.path.exists(input_file):
            print(f"❌ Error: Input file not found: {input_file}")
            return False
            
        try:
            shutil.copy(input_file, output_file)
            print(f"✅ Created enhanced file from original results: {output_file}")
        except Exception as e:
            print(f"❌ Error creating enhanced file: {str(e)}")
            return False
    
    # Store in Redis
    if not store_in_redis(args.scan_id):
        return False
    
    # Launch web interface if not disabled
    if not args.no_launch_web:
        if not launch_web_interface(args.scan_id):
            return False
    else:
        print("🔍 Web interface launch skipped (--no-launch-web option)")
    
    print("\n✨ Success! You can now edit and generate reports with the correct layout.")
    print(f"📝 Access the report editor at: http://localhost:3000/report-editor/editor/{args.scan_id}")
    print("🔄 After editing, you can generate and download reports in various formats.")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
