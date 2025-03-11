#!/usr/bin/env python3
"""
Test script for SQL injection scanner with a real OpenAPI specification file.
This script loads an OpenAPI specification file and runs the SQL injection scanner
to test its functionality with real-world OpenAPI endpoint extraction.
"""

import json
import logging
import sys
import argparse
import time
from typing import Dict, Any
import os

from scanners.sql_injection import Scanner
from core.logger import get_logger
from core.openapi import load_openapi_spec, extract_endpoints

# Configure root logger to show all logs
logging.basicConfig(level=logging.INFO, 
                    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Setup logger for this script
logger = get_logger("test_sql_injection_with_spec")

def main():
    """Run the SQL injection scanner test with a real OpenAPI specification file."""
    parser = argparse.ArgumentParser(description="Test SQL injection scanner with OpenAPI spec")
    parser.add_argument("--spec", "-s", required=True, help="Path to OpenAPI specification file")
    parser.add_argument("--url", "-u", default="http://localhost:8080", help="Base URL for the API")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug mode")
    parser.add_argument("--simulate", "-S", action="store_true", help="Simulate vulnerabilities")
    parser.add_argument("--output", "-o", choices=["text", "json"], default="text", help="Output format (text or JSON)")
    parser.add_argument("--fallback-endpoints", "-f", help="Comma-separated list of fallback endpoints to use if none are found in the spec")
    args = parser.parse_args()
    
    logger.info(f"Starting SQL injection scanner test with spec file: {args.spec}")
    
    # Check if the spec file exists
    if not os.path.exists(args.spec):
        logger.error(f"Specification file not found: {args.spec}")
        sys.exit(1)
    
    # Load the OpenAPI specification
    try:
        openapi_spec = load_openapi_spec(args.spec)
        logger.info(f"Successfully loaded OpenAPI specification from {args.spec}")
        
        # Extract endpoints from the OpenAPI specification
        endpoints = extract_endpoints(openapi_spec)
        if endpoints:
            logger.info(f"Successfully extracted {len(endpoints)} endpoints from OpenAPI specification")
            openapi_spec["endpoints"] = endpoints
        else:
            logger.warning("No endpoints extracted from OpenAPI specification")
    except Exception as e:
        logger.error(f"Failed to load OpenAPI specification: {str(e)}")
        sys.exit(1)
    
    # Create a target with the loaded OpenAPI data
    target = {
        "name": "Test API",
        "url": args.url,
        "openapi": openapi_spec
    }
    
    # Log the number of endpoints found in the spec
    if "endpoints" in openapi_spec:
        logger.info(f"Found {len(openapi_spec['endpoints'])} endpoints in OpenAPI specification")
        
        # Log a sample of endpoints (up to 5)
        sample_size = min(5, len(openapi_spec["endpoints"]))
        logger.info(f"Sample of {sample_size} endpoints from OpenAPI specification:")
        for i, endpoint in enumerate(openapi_spec["endpoints"][:sample_size]):
            logger.info(f"  {endpoint.get('method', 'UNKNOWN')} {endpoint.get('path', 'UNKNOWN')} ({endpoint.get('operation_id', 'No operation ID')})")
    else:
        logger.warning("No endpoints found in OpenAPI specification")
    
    # Create scanner configuration
    config = {
        "debug": args.debug,
        "verbose": True,
        "simulate_vulnerabilities": args.simulate
    }
    
    # Add fallback endpoints if provided via command line, otherwise use defaults
    if args.fallback_endpoints:
        fallback_endpoints = [endpoint.strip() for endpoint in args.fallback_endpoints.split(',')]
        logger.info(f"Using custom fallback endpoints: {fallback_endpoints}")
        config["fallback_endpoints"] = fallback_endpoints
    else:
        # Default fallback endpoints
        config["fallback_endpoints"] = [
            "/users/v1/{username}",
            "/api/users/{id}",
            "/api/products/search"
        ]
        logger.info("Using default fallback endpoints")
    
    # Initialize and run the scanner
    scanner = Scanner(target, config)
    findings = scanner.run()
    
    # Process and output findings
    if findings:
        # Map fields from the scanner output format to a consistent display format
        findings_display = []
        for finding in findings:
            finding_display = {
                'id': finding.get('finding_id', 'Unknown'),
                'title': finding.get('title', finding.get('vulnerability', finding.get('type', 'Unknown'))),
                'location': finding.get('location', finding.get('endpoint', 'Unknown')),
                'severity': finding.get('severity', 'Unknown'),
                'details': finding.get('description', finding.get('details', 'No details')),
                'remediation': finding.get('remediation', 'No remediation advice available'),
                'evidence': finding.get('evidence', {}),
                'timestamp': finding.get('timestamp', time.time())
            }
            findings_display.append(finding_display)
        
        # Output findings based on format
        if args.output == "json":
            # Output as JSON
            output = {
                "scanner": "SQL Injection",
                "timestamp": time.time(),
                "target": target.get("url", args.url),
                "findings_count": len(findings_display),
                "findings": findings_display
            }
            print(json.dumps(output, indent=2))
        else:
            # Output as text
            logger.info(f"Found {len(findings_display)} SQL injection vulnerabilities:")
            for i, finding in enumerate(findings_display, 1):
                logger.info(f"Finding #{i}: {finding['title']} in {finding['location']}")
                logger.info(f"  Severity: {finding['severity']}")
                logger.info(f"  Details: {finding['details']}")
                logger.info(f"  Remediation: {finding['remediation']}")
                
                # Log additional details if available
                if finding['evidence']:
                    evidence = finding['evidence']
                    if isinstance(evidence, dict):
                        logger.info(f"  Evidence: {json.dumps(evidence, indent=2)}")
                    else:
                        logger.info(f"  Evidence: {evidence}")
                        
                # Log finding ID if available
                logger.info(f"  Finding ID: {finding['id']}")
    else:
        if args.output == "json":
            output = {
                "scanner": "SQL Injection",
                "timestamp": time.time(),
                "target": target.get("url", args.url),
                "findings_count": 0,
                "findings": []
            }
            print(json.dumps(output, indent=2))
        else:
            logger.info("No SQL injection vulnerabilities found")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
