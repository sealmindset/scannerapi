#!/usr/bin/env python3
"""
Test script for OpenAPI endpoint extraction functionality.

This script tests the dynamic extraction of API endpoints from an OpenAPI specification file.
"""

import os
import sys
import json
import argparse
import logging
from typing import Dict, Any, List

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.openapi import load_openapi_spec, extract_endpoints, find_endpoint_by_purpose
from core.logger import setup_logger, get_logger

def setup_logging():
    """Set up logging for the test script."""
    log_config = {
        "level": "DEBUG",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "datefmt": "%Y-%m-%d %H:%M:%S"
    }
    setup_logger(log_config)
    return get_logger("test_openapi")

def test_endpoint_extraction(swagger_path: str) -> None:
    """
    Test the extraction of endpoints from an OpenAPI specification file.
    
    Args:
        swagger_path: Path to the OpenAPI specification file
    """
    logger = setup_logging()
    
    logger.info(f"Testing OpenAPI endpoint extraction with file: {swagger_path}")
    
    try:
        # Load the OpenAPI specification
        openapi_spec = load_openapi_spec(swagger_path)
        logger.info(f"Successfully loaded OpenAPI specification")
        
        # Extract endpoints
        endpoints = extract_endpoints(openapi_spec)
        logger.info(f"Extracted {len(endpoints)} endpoints from OpenAPI specification")
        
        # Print all extracted endpoints
        logger.info("Extracted endpoints:")
        for i, endpoint in enumerate(endpoints):
            logger.info(f"  {i+1}. {endpoint['method']} {endpoint['path']} - {endpoint.get('operation_id', 'No operation ID')}")
        
        # Test finding endpoints by purpose
        purposes = [
            "register", "login", "debug", "create_user", "update_user", 
            "get_user", "password_change"
        ]
        
        logger.info("\nTesting endpoint purpose mapping:")
        for purpose in purposes:
            default_path = f"/default/{purpose}"
            found_path = find_endpoint_by_purpose(endpoints, purpose, default_path)
            
            if found_path != default_path:
                logger.info(f"  Found {purpose} endpoint: {found_path}")
            else:
                logger.warning(f"  No matching endpoint found for purpose: {purpose}, using default: {default_path}")
        
        return True
    
    except Exception as e:
        logger.error(f"Error testing OpenAPI endpoint extraction: {str(e)}")
        return False

def main():
    """Main entry point for the test script."""
    parser = argparse.ArgumentParser(description="Test OpenAPI endpoint extraction")
    parser.add_argument("--swagger", "-s", required=True, help="Path to OpenAPI/Swagger specification file")
    args = parser.parse_args()
    
    if not os.path.exists(args.swagger):
        print(f"Error: OpenAPI specification file not found: {args.swagger}")
        sys.exit(1)
    
    success = test_endpoint_extraction(args.swagger)
    
    if success:
        print("OpenAPI endpoint extraction test completed successfully")
        sys.exit(0)
    else:
        print("OpenAPI endpoint extraction test failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
