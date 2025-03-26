#!/usr/bin/env python3
"""
Vulnerability Report Generator for Scanner API

This script generates detailed reports from Scanner API scan results in various formats
(JSON, CSV, HTML). It also supports integration with LLM-based middleware for enhancing
vulnerability remediation details and descriptions.
"""

import argparse
import json
import csv
import os
import sys
import datetime
import glob
import importlib.util
from typing import Dict, List, Any, Optional, Tuple
import sqlite3
from pathlib import Path
import logging
import subprocess

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("report_generator")

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_results.db")
# Results directory path
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

def load_scan_results_from_file(scan_id: str) -> Optional[Dict[str, Any]]:
    """
    Load scan results directly from a JSON file based on scan ID.
    
    Args:
        scan_id: The ID of the scan to load
        
    Returns:
        The scan results as a dictionary, or None if not found
    """
    try:
        # Look for the scan results file in the results directory
        result_file = os.path.join(RESULTS_DIR, f"{scan_id}.json")
        
        if not os.path.exists(result_file):
            # Try to find the file by pattern matching
            files = glob.glob(os.path.join(RESULTS_DIR, f"*{scan_id}*.json"))
            if not files:
                logger.error(f"No scan results file found for scan ID: {scan_id}")
                return None
            result_file = files[0]
            logger.info(f"Found scan results file: {result_file}")
        
        with open(result_file, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Error loading scan results file: {e}")
        return None

class ReportGenerator:
    """Generate detailed vulnerability reports from scan results."""

    def __init__(self, scan_id: str, output_format: str, output_path: str, use_direct_file: bool = False, input_file: Optional[str] = None):
        """
        Initialize the report generator.
        
        Args:
            scan_id: The ID of the scan to generate a report for
            output_format: The format of the report (json, csv, html)
            output_path: The path to save the report to
            use_direct_file: Whether to load data directly from JSON file instead of database
            input_file: Optional specific input file path to use instead of deriving from scan_id
        """
        self.scan_id = scan_id
        self.format = output_format.lower()
        self.output_path = output_path
        self.db_conn = None
        self.scan_data = None
        self.vulnerabilities = None
        self.use_direct_file = use_direct_file
        self.raw_scan_results = None
        self.input_file = input_file
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def connect_to_db(self) -> None:
        """Connect to the SQLite database."""
        try:
            # Create the database if it doesn't exist
            if not os.path.exists(DB_PATH):
                self._create_database()
                
            self.db_conn = sqlite3.connect(DB_PATH)
            self.db_conn.row_factory = sqlite3.Row
            logger.info(f"Connected to database at {DB_PATH}")
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            sys.exit(1)
    
    def _create_database(self) -> None:
        """Create the database schema if it doesn't exist."""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                target_url TEXT,
                config_path TEXT,
                summary TEXT
            )
            ''')
            
            # Create vulnerabilities table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                scanner TEXT,
                title TEXT,
                severity TEXT,
                endpoint TEXT,
                details TEXT,
                request_headers TEXT,
                request_body TEXT,
                response_headers TEXT,
                response_body TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"Created database at {DB_PATH}")
        except sqlite3.Error as e:
            logger.error(f"Database creation error: {e}")
            sys.exit(1)
    
    def fetch_scan_data(self) -> None:
        """Fetch scan data from the database or directly from JSON file."""
        if self.use_direct_file:
            self._fetch_from_file()
        else:
            self._fetch_from_database()
    
    def _fetch_from_database(self) -> None:
        """Fetch scan data from the database."""
        if not self.db_conn:
            self.connect_to_db()
            
        try:
            cursor = self.db_conn.cursor()
            
            # Fetch scan data
            cursor.execute(
                "SELECT * FROM scans WHERE id = ?", 
                (self.scan_id,)
            )
            scan_row = cursor.fetchone()
            
            if not scan_row:
                logger.error(f"No scan found with ID: {self.scan_id}")
                sys.exit(1)
                
            self.scan_data = dict(scan_row)
            
            # Fetch vulnerabilities
            cursor.execute(
                "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC", 
                (self.scan_id,)
            )
            vuln_rows = cursor.fetchall()
            
            self.vulnerabilities = [dict(row) for row in vuln_rows]
            
            logger.info(f"Fetched data for scan ID: {self.scan_id} from database")
            logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
            
        except sqlite3.Error as e:
            logger.error(f"Error fetching scan data from database: {e}")
            sys.exit(1)
            
    def _fetch_from_file(self) -> None:
        """Fetch scan data directly from JSON file."""
        if self.input_file and os.path.exists(self.input_file):
            # Load directly from the specified input file
            logger.info(f"Loading scan data from specified input file: {self.input_file}")
            try:
                with open(self.input_file, 'r') as f:
                    self.raw_scan_results = json.load(f)
            except Exception as e:
                logger.error(f"Error loading scan data from input file {self.input_file}: {e}")
                sys.exit(1)
        else:
            # Load using the scan_id to find the file
            self.raw_scan_results = load_scan_results_from_file(self.scan_id)
            
        if not self.raw_scan_results:
            logger.error(f"No scan results found for scan ID: {self.scan_id}")
            sys.exit(1)
        
        # Extract scan data
        self.scan_data = {
            "id": self.raw_scan_results.get("scan_id", self.scan_id),
            "timestamp": self.raw_scan_results.get("start_time", ""),
            "target_url": self.raw_scan_results.get("target", ""),
            "config_path": self.raw_scan_results.get("metadata", {}).get("config_file", ""),
            "summary": f"Scan completed in {self.raw_scan_results.get('duration', 0):.2f} seconds"
        }
        
        # Extract vulnerabilities from scanner findings
        self.vulnerabilities = []
        for scanner in self.raw_scan_results.get("scanners", []):
            for finding in scanner.get("findings", []):
                # Extract evidence based on vulnerability type
                evidence = finding.get("evidence", {})
                
                # Special handling for Rate-Limited Account Creation evidence
                if finding.get("vulnerability") == "Rate-Limited Account Creation":
                    # Format the specialized evidence structure for rate limiting
                    request_body = {}
                    response_body = {}
                    
                    # Include normal test data
                    if "normal_test" in evidence:
                        request_body["normal_test"] = evidence["normal_test"]
                    
                    # Include aggressive test data
                    if "aggressive_test" in evidence:
                        request_body["aggressive_test"] = evidence["aggressive_test"]
                    
                    # Include optimal rate data
                    if "optimal_rate" in evidence:
                        response_body["optimal_rate"] = evidence["optimal_rate"]
                    
                    # Include example request/response
                    if "example_request_response" in evidence:
                        example = evidence["example_request_response"]
                        if isinstance(example, dict):
                            if "request" in example:
                                request_body["example"] = example["request"]
                            if "response" in example:
                                response_body["example"] = example["response"]
                    
                    vuln = {
                        "scan_id": self.scan_id,
                        "scanner": scanner.get("name", ""),
                        "title": finding.get("vulnerability", ""),
                        "severity": finding.get("severity", ""),
                        "endpoint": finding.get("endpoint", ""),
                        "details": finding.get("details", ""),
                        "request_headers": json.dumps({}),
                        "request_body": json.dumps(request_body),
                        "response_headers": json.dumps({}),
                        "response_body": json.dumps(response_body),
                        "remediation": finding.get("remediation", ""),
                        "risk_assessment": finding.get("risk_assessment", ""),
                        "impact_analysis": finding.get("impact_analysis", ""),
                        "real_world_examples": finding.get("real_world_examples", "")
                    }
                else:
                    # Standard evidence processing for other vulnerabilities
                    vuln = {
                        "scan_id": self.scan_id,
                        "scanner": scanner.get("name", ""),
                        "title": finding.get("vulnerability", ""),
                        "severity": finding.get("severity", ""),
                        "endpoint": finding.get("endpoint", ""),
                        "details": finding.get("details", ""),
                        "request_headers": json.dumps(evidence.get("request", {}).get("headers", {})),
                        "request_body": json.dumps(evidence.get("request", {}).get("json_data", {})),
                        "response_headers": json.dumps(evidence.get("response", {}).get("headers", {})),
                        "response_body": json.dumps(evidence.get("response", {}).get("body", {})),
                        "remediation": finding.get("remediation", ""),
                        "risk_assessment": finding.get("risk_assessment", ""),
                        "impact_analysis": finding.get("impact_analysis", ""),
                        "real_world_examples": finding.get("real_world_examples", "")
                    }
                # Normalize severity to uppercase for consistent sorting
                if "severity" in vuln:
                    vuln["severity"] = vuln["severity"].upper()
                self.vulnerabilities.append(vuln)
        
        # Sort vulnerabilities by severity
        # This sorting is used for internal data structures and will be applied to all report formats
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.vulnerabilities.sort(key=lambda x: severity_order.get(x.get("severity", ""), 999))
        
        logger.info(f"Fetched data for scan ID: {self.scan_id} from file")
        logger.info(f"Found {len(self.vulnerabilities)} vulnerabilities")
    
    def generate_report(self) -> None:
        """Generate the report in the specified format."""
        if not self.scan_data or not self.vulnerabilities:
            self.fetch_scan_data()
            
        if self.format == "json":
            self._generate_json_report()
        elif self.format == "csv":
            self._generate_csv_report()
        elif self.format == "html":
            self._generate_html_report()
        else:
            logger.error(f"Unsupported format: {self.format}")
            sys.exit(1)
    
    def _generate_json_report(self) -> None:
        """Generate a JSON report."""
        report = {
            "scan_id": self.scan_id,
            "timestamp": self.scan_data["timestamp"],
            "target_url": self.scan_data["target_url"],
            "summary": self.scan_data["summary"],
            "vulnerabilities": self.vulnerabilities
        }
        
        try:
            with open(self.output_path, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"JSON report saved to {self.output_path}")
        except IOError as e:
            logger.error(f"Error writing JSON report: {e}")
            sys.exit(1)
    
    def _generate_csv_report(self) -> None:
        """Generate a CSV report."""
        try:
            with open(self.output_path, "w", newline="") as f:
                # Write summary
                writer = csv.writer(f)
                writer.writerow(["Scan ID", "Timestamp", "Target URL"])
                writer.writerow([
                    self.scan_id, 
                    self.scan_data["timestamp"], 
                    self.scan_data["target_url"]
                ])
                writer.writerow([])
                
                # Write vulnerabilities
                writer.writerow([
                    "Scanner", "Title", "Severity", "Endpoint", 
                    "Details", "Request Headers", "Request Body", 
                    "Response Headers", "Response Body", "Remediation"
                ])
                
                for vuln in self.vulnerabilities:
                    writer.writerow([
                        vuln["scanner"],
                        vuln["title"],
                        vuln["severity"],
                        vuln["endpoint"],
                        vuln["details"],
                        vuln["request_headers"],
                        vuln["request_body"],
                        vuln["response_headers"],
                        vuln["response_body"],
                        vuln["remediation"]
                    ])
                    
            logger.info(f"CSV report saved to {self.output_path}")
        except IOError as e:
            logger.error(f"Error writing CSV report: {e}")
            sys.exit(1)
    
    def _generate_evidence_html(self, vuln: Dict[str, Any]) -> str:
        """Generate HTML for vulnerability evidence based on vulnerability type.
        
        Args:
            vuln: Vulnerability data dictionary
            
        Returns:
            HTML string for the evidence section
        """
        # Check if this is a Rate-Limited Account Creation vulnerability
        if "Rate-Limited Account Creation" in vuln.get("title", ""):
            try:
                # Parse the JSON data from the request and response body fields
                request_data = json.loads(vuln.get("request_body", "{}"))
                response_data = json.loads(vuln.get("response_body", "{}"))
                
                html = ""
                
                # Normal test section
                if "normal_test" in request_data:
                    normal_test = request_data["normal_test"]
                    html += f"""
                    <div class="section-title">Normal Test Results:</div>
                    <div class="code-block">
                        <p>Successful Creations: {normal_test.get('successful_creations', 'N/A')}</p>
                        <p>Test Count: {normal_test.get('test_count', 'N/A')}</p>
                        <p>Delay Between Requests: {normal_test.get('delay_between_requests', 'N/A')}</p>
                        <p>Requests Per Second: {normal_test.get('requests_per_second', 'N/A')}</p>
                    </div>
                    """
                
                # Aggressive test section
                if "aggressive_test" in request_data:
                    aggressive_test = request_data["aggressive_test"]
                    html += f"""
                    <div class="section-title">Aggressive Test Results:</div>
                    <div class="code-block">
                        <p>Successful Creations: {aggressive_test.get('successful_creations', 'N/A')}</p>
                        <p>Test Count: {aggressive_test.get('test_count', 'N/A')}</p>
                        <p>Delay Between Requests: {aggressive_test.get('delay_between_requests', 'N/A')}</p>
                        <p>Requests Per Second: {aggressive_test.get('requests_per_second', 'N/A')}</p>
                    </div>
                    """
                
                # Optimal rate section
                if "optimal_rate" in response_data:
                    optimal_rate = response_data["optimal_rate"]
                    html += f"""
                    <div class="section-title">Optimal Rate Information:</div>
                    <div class="code-block">
                        <p>Delay Between Requests: {optimal_rate.get('delay_between_requests', 'N/A')}</p>
                        <p>Requests Per Second: {optimal_rate.get('requests_per_second', 'N/A')}</p>
                    </div>
                    """
                
                # Display successful account creations from test details
                if "optimal_rate" in response_data and "test_details" in response_data["optimal_rate"]:
                    test_details = response_data["optimal_rate"]["test_details"]
                    successful_requests = []
                    failed_requests = []
                    
                    # Separate successful and failed requests
                    for detail in test_details:
                        if detail.get("status_code") == 200:
                            successful_requests.append(detail)
                        else:
                            failed_requests.append(detail)
                    
                    # Show successful account creations
                    if successful_requests:
                        html += f"""
                        <div class="section-title">Successful Account Creations ({len(successful_requests)}):</div>
                        <div class="code-block">
                        """
                        
                        for i, request in enumerate(successful_requests[:3]):  # Show up to 3 examples
                            html += f"""
                            <p><strong>Example {i+1}:</strong></p>
                            <p>Username: {request.get('username', 'N/A')}</p>
                            <p>Status Code: <span style="color: green;">{request.get('status_code', 'N/A')}</span></p>
                            <p>Response Time: {request.get('response_time', 'N/A')} seconds</p>
                            <hr>
                            """
                        
                        if len(successful_requests) > 3:
                            html += f"<p>...and {len(successful_requests) - 3} more successful requests</p>"
                        
                        html += "</div>"
                    
                    # Show failed account creations
                    if failed_requests:
                        html += f"""
                        <div class="section-title">Failed Account Creation Attempts ({len(failed_requests)}):</div>
                        <div class="code-block">
                        """
                        
                        for i, request in enumerate(failed_requests[:2]):  # Show up to 2 examples
                            html += f"""
                            <p><strong>Example {i+1}:</strong></p>
                            <p>Username: {request.get('username', 'N/A')}</p>
                            <p>Status Code: <span style="color: red;">{request.get('status_code', 'N/A')}</span></p>
                            <p>Response Time: {request.get('response_time', 'N/A')} seconds</p>
                            <hr>
                            """
                        
                        if len(failed_requests) > 2:
                            html += f"<p>...and {len(failed_requests) - 2} more failed requests</p>"
                        
                        html += "</div>"
                
                # Example request/response
                if "example" in request_data or "example" in response_data:
                    html += f"""
                    <div class="section-title">Example Request/Response:</div>
                    <div class="code-block">
                    """
                    
                    if "example" in request_data:
                        html += f"<p><strong>Request:</strong></p><pre>{json.dumps(request_data['example'], indent=2)}</pre>"
                    
                    if "example" in response_data:
                        html += f"<p><strong>Response:</strong></p><pre>{json.dumps(response_data['example'], indent=2)}</pre>"
                    
                    html += "</div>"
                
                return html
            except Exception as e:
                logger.error(f"Error formatting Rate-Limited Account Creation evidence: {e}")
                # Fall back to standard evidence display
                pass
        
        # Standard evidence display for other vulnerabilities
        return f"""
        <div class="section-title">Request Headers:</div>
        <div class="code-block">{vuln["request_headers"] or "N/A"}</div>
        
        <div class="section-title">Request Body:</div>
        <div class="code-block">{vuln["request_body"] or "N/A"}</div>
        
        <div class="section-title">Response Headers:</div>
        <div class="code-block">{vuln["response_headers"] or "N/A"}</div>
        
        <div class="section-title">Response Body:</div>
        <div class="code-block">{vuln["response_body"] or "N/A"}</div>
        """
    
    def _generate_html_report(self) -> None:
        """Generate an HTML report."""
        try:
            with open(self.output_path, "w") as f:
                # HTML header
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        .summary-table th, .summary-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .summary-table th {
            background-color: #f2f2f2;
        }
        .vulnerability {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            padding: 15px;
            border-radius: 5px;
        }
        .critical {
            border-left: 5px solid #e74c3c;
        }
        .high {
            border-left: 5px solid #e67e22;
        }
        .medium {
            border-left: 5px solid #f1c40f;
        }
        .low {
            border-left: 5px solid #3498db;
        }
        .info {
            border-left: 5px solid #2ecc71;
        }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .severity {
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
        }
        .severity.critical {
            background-color: #e74c3c;
        }
        .severity.high {
            background-color: #e67e22;
        }
        .severity.medium {
            background-color: #f1c40f;
            color: #333;
        }
        .severity.low {
            background-color: #3498db;
        }
        .severity.info {
            background-color: #2ecc71;
        }
        .code-block {
            background-color: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 10px;
            overflow-x: auto;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .section {
            margin-bottom: 15px;
        }
        .section-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .enhanced-content {
            background-color: #f0f7ff;
            border-left: 3px solid #3498db;
            padding: 10px 15px;
            margin: 10px 0;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Report</h1>
""")

                # Scan summary
                f.write(f"""
        <h2>Scan Summary</h2>
        <table class="summary-table">
            <tr>
                <th>Scan ID</th>
                <td>{self.scan_id}</td>
            </tr>
            <tr>
                <th>Timestamp</th>
                <td>{self.scan_data["timestamp"]}</td>
            </tr>
            <tr>
                <th>Target URL</th>
                <td>{self.scan_data["target_url"]}</td>
            </tr>
        </table>
        
        <h2>Vulnerability Summary</h2>
        <table class="summary-table">
            <tr>
                <th>Scanner</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Endpoint</th>
            </tr>
""")

                # Vulnerability summary table
                for vuln in self.vulnerabilities:
                    # Ensure severity class is lowercase for CSS styling
                    severity_class = vuln["severity"].lower()
                    f.write(f"""
            <tr>
                <td>{vuln["scanner"]}</td>
                <td>{vuln["title"]}</td>
                <td class="severity {severity_class}">{vuln["severity"]}</td>
                <td>{vuln["endpoint"]}</td>
            </tr>""")

                f.write("""
        </table>
        
        <h2>Detailed Findings</h2>
""")

                # Detailed vulnerability findings
                for i, vuln in enumerate(self.vulnerabilities):
                    # Ensure severity class is lowercase for CSS styling
                    severity_class = vuln["severity"].lower()
                    f.write(f"""
        <div class="vulnerability {severity_class}">
            <div class="vuln-header">
                <h3>{i+1}. {vuln["title"]}</h3>
                <span class="severity {severity_class}">{vuln["severity"]}</span>
            </div>
            
            <div class="section">
                <div class="section-title">URL:</div>
                <div>{self.scan_data["target_url"]}/{vuln["endpoint"]}</div>
            </div>
            
            <div class="section">
                <div class="section-title">Description:</div>
                <div>{vuln["details"]}</div>
            </div>
            
            {"" if not vuln.get("risk_assessment") else f'''
            <div class="section">
                <div class="section-title">Risk Assessment:</div>
                <div class="enhanced-content">{vuln["risk_assessment"]}</div>
            </div>
            '''}
            
            {"" if not vuln.get("impact_analysis") else f'''
            <div class="section">
                <div class="section-title">Impact Analysis:</div>
                <div class="enhanced-content">{vuln["impact_analysis"]}</div>
            </div>
            '''}
            
            {"" if not vuln.get("real_world_examples") else f'''
            <div class="section">
                <div class="section-title">Real-World Examples:</div>
                <div class="enhanced-content">{vuln["real_world_examples"]}</div>
            </div>
            '''}
            
            <div class="section">
                <div class="section-title">Results:</div>
                
                {self._generate_evidence_html(vuln)}
            </div>
            
            <div class="section">
                <div class="section-title">Remediation:</div>
                <div>{vuln["remediation"] or "No specific remediation provided."}</div>
            </div>
        </div>
""")

                
                # HTML footer
                f.write("""
    </div>
    <footer style="text-align: center; margin-top: 30px; color: #777;">
        <p>Generated by Scanner API Report Generator on """ + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </footer>
</body>
</html>
""")
                
            logger.info(f"HTML report saved to {self.output_path}")
        except IOError as e:
            logger.error(f"Error writing HTML report: {e}")
            sys.exit(1)

def import_scan_results(results_file: str, config_path: str) -> str:
    """
    Import scan results from a JSON file into the database.
    
    Args:
        results_file: Path to the JSON results file
        config_path: Path to the configuration file used for the scan
        
    Returns:
        The scan ID
    """
    try:
        with open(results_file, 'r') as f:
            results = json.load(f)
            
        # Create database connection
        if not os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                target_url TEXT,
                config_path TEXT,
                summary TEXT
            )
            ''')
            
            # Create vulnerabilities table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                scanner TEXT,
                title TEXT,
                severity TEXT,
                endpoint TEXT,
                details TEXT,
                request_headers TEXT,
                request_body TEXT,
                response_headers TEXT,
                response_body TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
            ''')
            
            conn.commit()
        else:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
        
        # Generate scan ID
        scan_id = f"scan_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Extract target URL from results
        target_url = None
        if "target_url" in results:
            target_url = results["target_url"]
        elif "config" in results and "target" in results["config"] and "base_url" in results["config"]["target"]:
            target_url = results["config"]["target"]["base_url"]
        else:
            # Try to extract from config file
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yml') or config_path.endswith('.yaml'):
                        import yaml
                        config = yaml.safe_load(f)
                        if "target" in config and "base_url" in config["target"]:
                            target_url = config["target"]["base_url"]
                    else:
                        config = json.load(f)
                        if "target" in config and "base_url" in config["target"]:
                            target_url = config["target"]["base_url"]
            except Exception as e:
                logger.warning(f"Could not extract target URL from config file: {e}")
                
        if not target_url:
            target_url = "Unknown"
            
        # Create summary
        summary = f"Found {len(results.get('vulnerabilities', []))} vulnerabilities"
        
        # Insert scan data
        cursor.execute(
            "INSERT INTO scans (id, timestamp, target_url, config_path, summary) VALUES (?, ?, ?, ?, ?)",
            (
                scan_id,
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                target_url,
                config_path,
                summary
            )
        )
        
        # Insert vulnerabilities
        for vuln in results.get("vulnerabilities", []):
            # Extract evidence if available
            request_headers = ""
            request_body = ""
            response_headers = ""
            response_body = ""
            
            if "evidence" in vuln:
                evidence = vuln["evidence"]
                if isinstance(evidence, dict):
                    if "request" in evidence:
                        request = evidence["request"]
                        if isinstance(request, dict):
                            if "headers" in request:
                                request_headers = json.dumps(request["headers"], indent=2)
                            if "body" in request:
                                request_body = request["body"]
                    
                    if "response" in evidence:
                        response = evidence["response"]
                        if isinstance(response, dict):
                            if "headers" in response:
                                response_headers = json.dumps(response["headers"], indent=2)
                            if "body" in response:
                                response_body = response["body"]
            
            # Extract remediation if available
            remediation = ""
            if "remediation" in vuln:
                remediation = vuln["remediation"]
            elif "mitigation" in vuln:
                remediation = vuln["mitigation"]
                
            cursor.execute(
                """INSERT INTO vulnerabilities 
                   (scan_id, scanner, title, severity, endpoint, details, 
                    request_headers, request_body, response_headers, response_body, remediation) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    vuln.get("scanner", "Unknown"),
                    vuln.get("title", "Unknown"),
                    vuln.get("severity", "Unknown"),
                    vuln.get("endpoint", ""),
                    vuln.get("details", ""),
                    request_headers,
                    request_body,
                    response_headers,
                    response_body,
                    remediation
                )
            )
        
        conn.commit()
        conn.close()
        
        logger.info(f"Imported scan results with ID: {scan_id}")
        return scan_id
        
    except Exception as e:
        logger.error(f"Error importing scan results: {e}")
        sys.exit(1)

def list_scans() -> None:
    """List all scans in the database."""
    try:
        if not os.path.exists(DB_PATH):
            logger.error("No scans database found.")
            return
            
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, timestamp, target_url, summary FROM scans ORDER BY timestamp DESC")
        scans = cursor.fetchall()
        
        if not scans:
            logger.info("No scans found in the database.")
            return
            
        print("\nAvailable Scans:")
        print("-" * 80)
        print(f"{'Scan ID':<25} {'Timestamp':<20} {'Target URL':<30} {'Summary'}")
        print("-" * 80)
        
        for scan in scans:
            print(f"{scan['id']:<25} {scan['timestamp']:<20} {scan['target_url']:<30} {scan['summary']}")
            
        print("-" * 80)
        print(f"Total: {len(scans)} scans\n")
        
        conn.close()
        
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        sys.exit(1)

def add_jwt_vulnerability_remediations(scan_id: str) -> None:
    """
    Add specific remediations for JWT vulnerabilities.
    
    Args:
        scan_id: The ID of the scan to update
    """
    try:
        if not os.path.exists(DB_PATH):
            logger.error("No scans database found.")
            return
            
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # JWT 'none' Algorithm Vulnerability
        cursor.execute(
            """UPDATE vulnerabilities 
               SET remediation = ? 
               WHERE scan_id = ? AND title LIKE '%none%Algorithm%'""",
            (
                """1. Explicitly validate the algorithm used in JWT tokens.
2. Reject tokens that use the 'none' algorithm.
3. Implement a whitelist of allowed algorithms (e.g., HS256, RS256).
4. Use a library that properly validates JWT tokens and doesn't allow the 'none' algorithm.
5. Example code:
   ```
   // Node.js example with jsonwebtoken library
   const jwt = require('jsonwebtoken');
   
   try {
     const decoded = jwt.verify(token, secretKey, {
       algorithms: ['HS256', 'RS256'] // Whitelist of allowed algorithms
     });
     // Process the decoded token
   } catch (err) {
     // Handle invalid token
   }
   ```""",
                scan_id
            )
        )
        
        # JWT Weak Signing Key
        cursor.execute(
            """UPDATE vulnerabilities 
               SET remediation = ? 
               WHERE scan_id = ? AND title LIKE '%Weak Signing Key%'""",
            (
                """1. Use a strong, randomly generated key for JWT token signing.
2. The key should be at least 256 bits (32 bytes) for HS256.
3. Consider using asymmetric algorithms (RS256) for better security.
4. Rotate keys periodically.
5. Store keys securely, never hardcode them.
6. Example:
   ```
   // Generate a strong key
   const crypto = require('crypto');
   const strongKey = crypto.randomBytes(64).toString('hex');
   
   // Use environment variables to store the key
   process.env.JWT_SECRET = strongKey;
   ```""",
                scan_id
            )
        )
        
        # Missing JWT Signature Validation
        cursor.execute(
            """UPDATE vulnerabilities 
               SET remediation = ? 
               WHERE scan_id = ? AND title LIKE '%Missing JWT Signature%'""",
            (
                """1. Always validate JWT signatures before processing requests.
2. Use a reputable JWT library that properly validates signatures.
3. Implement proper exception handling for invalid signatures.
4. Never accept tokens with invalid signatures.
5. Example code:
   ```
   // Node.js example
   const jwt = require('jsonwebtoken');
   
   function verifyToken(req, res, next) {
     const token = req.headers.authorization?.split(' ')[1];
     
     if (!token) {
       return res.status(401).json({ message: 'No token provided' });
     }
     
     try {
       const decoded = jwt.verify(token, process.env.JWT_SECRET);
       req.user = decoded;
       next();
     } catch (err) {
       return res.status(401).json({ message: 'Invalid token' });
     }
   }
   ```""",
                scan_id
            )
        )
        
        # JWT Expiration Manipulation
        cursor.execute(
            """UPDATE vulnerabilities 
               SET remediation = ? 
               WHERE scan_id = ? AND title LIKE '%Expiration%'""",
            (
                """1. Always validate the 'exp' claim in JWT tokens.
2. Use short-lived access tokens (15-60 minutes).
3. Implement refresh tokens for obtaining new access tokens.
4. Add server-side validation of token expiration.
5. Consider using a token blacklist for revoked tokens.
6. Example code:
   ```
   // Node.js example
   const jwt = require('jsonwebtoken');
   
   // Create token with expiration
   const token = jwt.sign(
     { userId: user.id },
     process.env.JWT_SECRET,
     { expiresIn: '15m' } // Token expires in 15 minutes
   );
   
   // Verify token with expiration check
   try {
     const decoded = jwt.verify(token, process.env.JWT_SECRET);
     // Additional server-side validation
     const currentTime = Math.floor(Date.now() / 1000);
     if (decoded.exp < currentTime) {
       throw new Error('Token expired');
     }
     // Process request
   } catch (err) {
     // Handle invalid or expired token
   }
   ```""",
                scan_id
            )
        )
        
        # JWT Token Tampering
        cursor.execute(
            """UPDATE vulnerabilities 
               SET remediation = ? 
               WHERE scan_id = ? AND title LIKE '%Token Tampering%'""",
            (
                """1. Implement proper JWT signature validation.
2. Use a strong secret key or asymmetric keys (public/private key pair).
3. Validate all claims in the token, including 'sub', 'iss', and 'aud'.
4. Consider using a token revocation mechanism.
5. Implement proper error handling for invalid tokens.
6. Example code:
   ```
   // Node.js example
   const jwt = require('jsonwebtoken');
   
   function verifyToken(req, res, next) {
     const token = req.headers.authorization?.split(' ')[1];
     
     if (!token) {
       return res.status(401).json({ message: 'No token provided' });
     }
     
     try {
       const decoded = jwt.verify(token, process.env.JWT_SECRET, {
         algorithms: ['HS256', 'RS256'], // Whitelist of allowed algorithms
         issuer: 'your-api-issuer',      // Validate issuer
         audience: 'your-api-audience'   // Validate audience
       });
       
       // Additional validation
       if (!decoded.sub) {
         throw new Error('Invalid subject claim');
       }
       
       req.user = decoded;
       next();
     } catch (err) {
       return res.status(401).json({ message: 'Invalid token' });
     }
   }
   ```""",
                scan_id
            )
        )
        
        conn.commit()
        conn.close()
        
        logger.info(f"Added JWT vulnerability remediations for scan ID: {scan_id}")
        
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        sys.exit(1)

def import_llm_module(module_path, module_name):
    """Dynamically import a module from a file path.
    
    Args:
        module_path: Path to the module file
        module_name: Name to give the imported module
        
    Returns:
        The imported module, or None if import failed
    """
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if not spec or not spec.loader:
            logger.error(f"Could not load spec for {module_path}")
            return None
            
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except (ImportError, AttributeError) as e:
        logger.error(f"Error importing {module_path}: {e}")
        return None

def run_llm_enhancement_pipeline(input_file, output_file, use_remediation=True, use_description=True, 
                                llm_provider="openai", llm_model=None, api_key=None, ollama_url="http://localhost:11434",
                                batch_size=5, max_workers=3):
    """Run the LLM enhancement pipeline on scan results.
    
    Args:
        input_file: Path to the input scan results file
        output_file: Path to save the enhanced results
        use_remediation: Whether to enhance remediation details
        use_description: Whether to enhance vulnerability descriptions
        llm_provider: LLM provider to use ('openai' or 'ollama')
        llm_model: Model to use (provider-specific)
        batch_size: Batch size for processing
        max_workers: Maximum number of worker threads
        
    Returns:
        Path to the enhanced results file
    """
    logger.info(f"Pipeline parameters: input={input_file}, output={output_file}, remediation={use_remediation}, description={use_description}")
    logger.info(f"LLM config: provider={llm_provider}, model={llm_model}, api_key={'set' if api_key else 'not set'}, ollama_url={ollama_url}, batch_size={batch_size}, max_workers={max_workers}")
    
    current_file = input_file
    temp_files = []
    
    try:
        # Step 1: Enhance remediation if requested
        if use_remediation:
            logger.info("Enhancing remediation details with LLM...")
            remediation_output = f"{os.path.splitext(output_file)[0]}_remediation_enhanced.json"
            temp_files.append(remediation_output)
            
            # Try to import the module
            llm_remediation_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llm_remediation_middleware.py")
            logger.info(f"Looking for remediation middleware at: {llm_remediation_path}")
            
            if not os.path.exists(llm_remediation_path):
                logger.error(f"Remediation middleware file not found: {llm_remediation_path}")
                print(f"Error: Remediation middleware file not found. Skipping remediation enhancement.")
                use_remediation = False
            else:
                llm_remediation = import_llm_module(llm_remediation_path, "llm_remediation_middleware")
            
            if llm_remediation:
                # Use the imported module
                logger.info("Using imported llm_remediation_middleware module")
                
                # Direct integration without using command-line parsing
                try:
                    # Load the configuration
                    if hasattr(llm_remediation, 'RemediationConfig'):
                        # Create config directly
                        config_class = getattr(llm_remediation, 'RemediationConfig')
                        config_params = {
                            'llm_provider': llm_provider,
                            'batch_size': batch_size,
                            'max_workers': max_workers
                        }
                        
                        # Add provider-specific configuration
                        if llm_provider == 'openai':
                            if api_key:
                                config_params['openai_api_key'] = api_key
                            if llm_model:
                                config_params['openai_model'] = llm_model
                        else:  # ollama
                            if ollama_url:
                                config_params['ollama_base_url'] = ollama_url
                            if llm_model:
                                config_params['ollama_model'] = llm_model
                                
                        config = config_class(**config_params)
                    else:
                        # Fall back to the module's load_config function
                        config = llm_remediation.load_config()
                    
                    # Create middleware instance
                    middleware = llm_remediation.LLMRemediationMiddleware(config)
                    
                    # Process the scan results
                    logger.info(f"Loading scan results from {current_file}")
                    scan_results = llm_remediation.load_scan_results(current_file)
                    logger.info(f"Processing scan results with remediation middleware")
                    enhanced_results = middleware.process_scan_results(scan_results)
                    logger.info(f"Saving enhanced results to {remediation_output}")
                    llm_remediation.save_scan_results(enhanced_results, remediation_output)
                    logger.info("Remediation enhancement completed successfully")
                except Exception as e:
                    logger.error(f"Error using remediation middleware: {e}", exc_info=True)
                    print(f"Error enhancing remediation: {e}")
                    # Continue with the original file
                    remediation_output = current_file
            else:
                # Fall back to subprocess
                logger.info("Falling back to subprocess for llm_remediation_middleware")
                cmd = [
                    "python3", llm_remediation_path,
                    "--input", current_file,
                    "--output", remediation_output,
                    "--provider", llm_provider,
                    "--batch-size", str(batch_size),
                    "--max-workers", str(max_workers)
                ]
                if llm_model:
                    cmd.extend(["--model", llm_model])
                    
                subprocess.run(cmd, check=True)
                
            current_file = remediation_output
            logger.info(f"Remediation enhancement complete. Output saved to {remediation_output}")
        
        # Step 2: Enhance descriptions if requested
        if use_description:
            logger.info("Enhancing vulnerability descriptions with LLM...")
            description_output = f"{os.path.splitext(output_file)[0]}_description_enhanced.json"
            temp_files.append(description_output)
            
            # Try to import the module
            llm_description_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llm_description.py")
            logger.info(f"Looking for description middleware at: {llm_description_path}")
            
            if not os.path.exists(llm_description_path):
                logger.error(f"Description middleware file not found: {llm_description_path}")
                print(f"Error: Description middleware file not found. Skipping description enhancement.")
                use_description = False
            else:
                llm_description = import_llm_module(llm_description_path, "llm_description")
            
            if llm_description:
                # Use the imported module
                logger.info("Using imported llm_description module")
                
                # Direct integration without using command-line parsing
                try:
                    # Create configuration
                    if hasattr(llm_description, 'DescriptionConfig'):
                        config_class = getattr(llm_description, 'DescriptionConfig')
                        config_params = {
                            'llm_provider': llm_provider,
                            'batch_size': batch_size,
                            'max_workers': max_workers
                        }
                        
                        # Set the appropriate model and credentials based on provider
                        if llm_provider == 'openai':
                            if api_key:
                                config_params['openai_api_key'] = api_key
                            config_params['openai_model'] = llm_model if llm_model else "gpt-4o"
                        else:  # ollama
                            if ollama_url:
                                config_params['ollama_base_url'] = ollama_url
                            config_params['ollama_model'] = llm_model if llm_model else "llama3"
                            
                        config = config_class(**config_params)
                    else:
                        # If no config class is found, try to create a generic dict config
                        config = {
                            'llm_provider': llm_provider,
                            'model': llm_model,
                            'batch_size': batch_size,
                            'max_workers': max_workers
                        }
                    
                    # Create middleware instance
                    logger.info(f"Creating LLMDescriptionMiddleware with config: {config}")
                    middleware = llm_description.LLMDescriptionMiddleware(config)
                    
                    # Process the scan results
                    logger.info(f"Loading scan results from {current_file}")
                    scan_results = llm_description.load_scan_results(current_file)
                    logger.info(f"Processing scan results with description middleware")
                    enhanced_results = middleware.process_scan_results(scan_results)
                    logger.info(f"Saving enhanced results to {description_output}")
                    llm_description.save_scan_results(enhanced_results, description_output)
                    logger.info("Description enhancement completed successfully")
                except Exception as e:
                    logger.error(f"Error using description middleware: {e}", exc_info=True)
                    print(f"Error enhancing descriptions: {e}")
                    # Continue with the original file
                    description_output = current_file
            else:
                # Fall back to subprocess
                logger.info("Falling back to subprocess for llm_description")
                cmd = [
                    "python3", llm_description_path,
                    "--input", current_file,
                    "--output", description_output,
                    "--provider", llm_provider,
                    "--batch-size", str(batch_size),
                    "--max-workers", str(max_workers)
                ]
                if llm_model:
                    cmd.extend(["--model", llm_model])
                    
                subprocess.run(cmd, check=True)
                
            current_file = description_output
            logger.info(f"Description enhancement complete. Output saved to {description_output}")
        
        # Step 3: Copy the final result to the output file
        if current_file != output_file:
            try:
                with open(current_file, 'r') as src, open(output_file, 'w') as dst:
                    content = src.read()
                    dst.write(content)
                logger.info(f"Final enhanced results saved to {output_file}")
                
                # Verify the output file was created and has content
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    logger.info(f"Successfully created output file: {output_file} with size {os.path.getsize(output_file)} bytes")
                else:
                    logger.error(f"Output file issue: exists={os.path.exists(output_file)}, size={os.path.getsize(output_file) if os.path.exists(output_file) else 'N/A'}")
            except Exception as e:
                logger.error(f"Error copying to final output file: {e}", exc_info=True)
                print(f"Error saving final results: {e}")
            
        return output_file
    except Exception as e:
        logger.error(f"Error in LLM enhancement pipeline: {e}", exc_info=True)
        print(f"Error in LLM enhancement pipeline: {e}")
        return input_file

def main():
    """Main function to parse arguments and run the report generator."""
    parser = argparse.ArgumentParser(description="Generate vulnerability reports from scan results")
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Import command
    import_parser = subparsers.add_parser("import", help="Import scan results into the database")
    import_parser.add_argument("--results", required=True, help="Path to the JSON results file")
    import_parser.add_argument("--config", required=True, help="Path to the configuration file used for the scan")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List all scans in the database")
    
    # Generate command
    generate_parser = subparsers.add_parser("generate", help="Generate a report from scan results")
    generate_parser.add_argument("--scanid", required=True, help="ID of the scan to generate a report for")
    generate_parser.add_argument("--format", choices=["json", "csv", "html"], default="html", help="Format of the report")
    generate_parser.add_argument("--output", required=True, help="Path to save the report to")
    generate_parser.add_argument("--direct", action="store_true", help="Load scan data directly from file instead of database")
    
    # Quick report command (simplified version of generate)
    quick_parser = subparsers.add_parser("quick-report", help="Quickly generate a report from scan ID without database import")
    quick_parser.add_argument("scanid", help="ID of the scan to generate a report for")
    quick_parser.add_argument("--format", choices=["json", "csv", "html"], default="html", help="Format of the report")
    quick_parser.add_argument("--output", help="Path to save the report to (defaults to ./reports/<scanid>.<format>)")
    
    # JWT remediation command
    jwt_parser = subparsers.add_parser("add-jwt-remediations", help="Add JWT vulnerability remediations")
    jwt_parser.add_argument("--scanid", required=True, help="ID of the scan to update")
    
    # NEW: LLM enhancement command
    llm_parser = subparsers.add_parser("enhance-with-llm", help="Enhance scan results with LLM-generated content")
    llm_parser.add_argument("--input", required=True, help="Path to the input scan results file")
    llm_parser.add_argument("--output", required=True, help="Path to save the enhanced results")
    llm_parser.add_argument("--no-remediation", action="store_false", dest="remediation", help="Skip remediation enhancement")
    llm_parser.add_argument("--no-description", action="store_false", dest="description", help="Skip description enhancement")
    llm_parser.add_argument("--provider", choices=["openai", "ollama"], default="openai", help="LLM provider to use")
    llm_parser.add_argument("--model", help="Model to use (provider-specific)")
    llm_parser.add_argument("--api-key", help="API key for the LLM provider (required for OpenAI)")
    llm_parser.add_argument("--ollama-url", default="http://localhost:11434", help="URL for Ollama server")
    llm_parser.add_argument("--batch-size", type=int, default=5, help="Batch size for processing")
    llm_parser.add_argument("--max-workers", type=int, default=3, help="Maximum number of worker threads")
    llm_parser.add_argument("--generate-report", action="store_true", help="Generate a report after enhancement")
    llm_parser.add_argument("--report-format", choices=["json", "csv", "html"], default="html", 
                           help="Format of the report (if --generate-report is specified)")
    llm_parser.add_argument("--report-output", help="Path to save the report (if --generate-report is specified)")
    
    args = parser.parse_args()
    
    if args.command == "import":
        scan_id = import_scan_results(args.results, args.config)
        print(f"Imported scan results with ID: {scan_id}")
        
    elif args.command == "list":
        list_scans()
        
    elif args.command == "generate":
        generator = ReportGenerator(args.scanid, args.format, args.output, use_direct_file=args.direct)
        generator.generate_report()
        print(f"Generated {args.format.upper()} report at {args.output}")
    
    elif args.command == "quick-report":
        # Set default output path if not provided
        output_path = args.output
        if not output_path:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir)
            output_path = os.path.join(reports_dir, f"{args.scanid}.{args.format}")
        
        # Generate report directly from file
        generator = ReportGenerator(args.scanid, args.format, output_path, use_direct_file=True)
        generator.generate_report()
        print(f"Generated {args.format.upper()} report at {output_path}")
        
    elif args.command == "add-jwt-remediations":
        add_jwt_vulnerability_remediations(args.scanid)
        print(f"Added JWT vulnerability remediations for scan ID: {args.scanid}")
        
    elif args.command == "enhance-with-llm":
        # Run the LLM enhancement pipeline
        logger.info(f"Starting LLM enhancement pipeline for {args.input}")
        logger.info(f"Debug - Command arguments: {vars(args)}")
        
        # Check if the input file exists
        if not os.path.exists(args.input):
            logger.error(f"Input file not found: {args.input}")
            print(f"Error: Input file not found: {args.input}")
            sys.exit(1)
            
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(args.output)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            logger.info(f"Created output directory: {output_dir}")
        
        enhanced_file = run_llm_enhancement_pipeline(
            args.input, args.output,
            use_remediation=args.remediation,
            use_description=args.description,
            llm_provider=args.provider,
            llm_model=args.model,
            api_key=args.api_key,
            ollama_url=args.ollama_url,
            batch_size=args.batch_size,
            max_workers=args.max_workers
        )
        
        logger.info(f"Enhancement pipeline completed. Result: {enhanced_file}")
        print(f"Enhanced scan results saved to {enhanced_file}")
        
        # Generate a report if requested
        if args.generate_report:
            # Set default report output path if not provided
            report_output = args.report_output
            if not report_output:
                # Create reports directory if it doesn't exist
                reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
                if not os.path.exists(reports_dir):
                    os.makedirs(reports_dir)
            
            # Extract scan ID from the enhanced file
            scan_id = None
            try:
                with open(enhanced_file, 'r') as f:
                    enhanced_data = json.load(f)
                    scan_id = enhanced_data.get('scan_id')
            except Exception as e:
                logger.warning(f"Could not extract scan_id from enhanced file: {e}")
            
            # If we couldn't get scan_id from the file content, try to extract from filename
            if not scan_id:
                filename = os.path.basename(args.input)
                scan_id = os.path.splitext(filename)[0]
                logger.info(f"Using scan_id from input filename: {scan_id}")
            
            if not report_output:
                report_output = os.path.join(reports_dir, f"report_{scan_id}_enhanced.{args.report_format}")
            
            # Generate the report using the enhanced file
            logger.info(f"Generating {args.report_format} report from enhanced results for scan ID: {scan_id}")
            generator = ReportGenerator(
                scan_id=scan_id, 
                output_format=args.report_format, 
                output_path=report_output, 
                use_direct_file=True,
                input_file=enhanced_file  # Use the enhanced file directly
            )
            generator.generate_report()
            print(f"Generated {args.report_format.upper()} report at {report_output}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
