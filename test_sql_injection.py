#!/usr/bin/env python3
"""
Test script for SQL injection scanner.
This script directly instantiates and runs the SQL injection scanner
to test its functionality with OpenAPI endpoint extraction.
"""

import json
import logging
import sys
from typing import Dict, Any

from scanners.sql_injection import Scanner
from core.logger import get_logger

# Configure root logger to show all logs
logging.basicConfig(level=logging.INFO, 
                    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Setup logger for this script
logger = get_logger("test_sql_injection")

def main():
    """Run the SQL injection scanner test."""
    logger.info("Starting SQL injection scanner test")
    
    # Create a mock target with OpenAPI data that matches what we saw in the logs
    target = {
        "name": "Test API",
        "url": "http://localhost:8080",
        "openapi": {
            "endpoints": [
                {
                    "path": "/users/me",
                    "method": "GET",
                    "operation_id": "getCurrentUser",
                    "description": "Get the current user's profile"
                },
                {
                    "path": "/users/me/record-purchase",
                    "method": "POST",
                    "operation_id": "recordPurchase",
                    "description": "Record a purchase for the current user"
                },
                {
                    "path": "/users/v1/_debug",
                    "method": "GET",
                    "operation_id": "getDebugInfo",
                    "description": "Get debug information"
                },
                {
                    "path": "/users/v1/register",
                    "method": "POST",
                    "operation_id": "registerUser",
                    "description": "Register a new user"
                },
                {
                    "path": "/users/v1/login",
                    "method": "POST",
                    "operation_id": "loginUser",
                    "description": "Login a user"
                },
                {
                    "path": "/users/v1/{username}/password",
                    "method": "PUT",
                    "operation_id": "changePassword",
                    "description": "Change a user's password"
                },
                {
                    "path": "/users/{id}",
                    "method": "GET",
                    "operation_id": "getUserById",
                    "description": "Get a user by ID"
                },
                {
                    "path": "/users/search",
                    "method": "GET",
                    "operation_id": "searchUsers",
                    "description": "Search for users"
                },
                {
                    "path": "/products/{id}",
                    "method": "GET",
                    "operation_id": "getProductById",
                    "description": "Get a product by ID"
                },
                {
                    "path": "/products/search",
                    "method": "GET",
                    "operation_id": "searchProducts",
                    "description": "Search for products"
                }
            ]
        }
    }
    
    # Create scanner configuration
    config = {
        "debug": True,
        "verbose": True,
        "simulate_vulnerabilities": True,  # For testing purposes
        "fallback_endpoints": [
            "/users/v1/{username}",
            "/api/users/{id}",
            "/api/products/search"
        ]
    }
    
    logger.info("Using the following endpoints from OpenAPI specification:")
    for endpoint in target["openapi"]["endpoints"]:
        logger.info(f"  {endpoint['method']} {endpoint['path']} ({endpoint['operation_id']})")
    
    # Initialize and run the scanner
    scanner = Scanner(target, config)
    findings = scanner.run()
    
    # Print findings
    if findings:
        logger.info(f"Found {len(findings)} SQL injection vulnerabilities:")
        for i, finding in enumerate(findings, 1):
            logger.info(f"Finding #{i}: {finding['vulnerability']} in {finding['endpoint']}")
            logger.info(f"  Severity: {finding['severity']}")
            logger.info(f"  Details: {finding['details']}")
    else:
        logger.info("No SQL injection vulnerabilities found")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
