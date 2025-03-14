#!/usr/bin/env python3
"""
Vulnerability Report Generator for Scanner API

This script generates detailed reports from Scanner API scan results in various formats
(JSON, CSV, HTML).
"""

import argparse
import json
import csv
import os
import sys
import datetime
import glob
from typing import Dict, List, Any, Optional, Tuple
import sqlite3
from pathlib import Path
import logging

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

    def __init__(self, scan_id: str, output_format: str, output_path: str, use_direct_file: bool = False):
        """
        Initialize the report generator.
        
        Args:
            scan_id: The ID of the scan to generate a report for
            output_format: The format of the report (json, csv, html)
            output_path: The path to save the report to
            use_direct_file: Whether to load data directly from JSON file instead of database
        """
        self.scan_id = scan_id
        self.format = output_format.lower()
        self.output_path = output_path
        self.db_conn = None
        self.scan_data = None
        self.vulnerabilities = None
        self.use_direct_file = use_direct_file
        self.raw_scan_results = None
        
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
        self.raw_scan_results = load_scan_results_from_file(self.scan_id)
        
        if not self.raw_scan_results:
            logger.error(f"No scan results file found for scan ID: {self.scan_id}")
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
                vuln = {
                    "scan_id": self.scan_id,
                    "scanner": scanner.get("name", ""),
                    "title": finding.get("vulnerability", ""),
                    "severity": finding.get("severity", ""),
                    "endpoint": finding.get("endpoint", ""),
                    "details": finding.get("details", ""),
                    "request_headers": json.dumps(finding.get("evidence", {}).get("request", {}).get("headers", {})),
                    "request_body": json.dumps(finding.get("evidence", {}).get("request", {}).get("json_data", {})),
                    "response_headers": json.dumps(finding.get("evidence", {}).get("response", {}).get("headers", {})),
                    "response_body": json.dumps(finding.get("evidence", {}).get("response", {}).get("body", {})),
                    "remediation": finding.get("remediation", "")
                }
                self.vulnerabilities.append(vuln)
        
        # Sort vulnerabilities by severity
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
            
            <div class="section">
                <div class="section-title">Results:</div>
                <div class="section-title">Request Headers:</div>
                <div class="code-block">{vuln["request_headers"] or "N/A"}</div>
                
                <div class="section-title">Request Body:</div>
                <div class="code-block">{vuln["request_body"] or "N/A"}</div>
                
                <div class="section-title">Response Headers:</div>
                <div class="code-block">{vuln["response_headers"] or "N/A"}</div>
                
                <div class="section-title">Response Body:</div>
                <div class="code-block">{vuln["response_body"] or "N/A"}</div>
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
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
