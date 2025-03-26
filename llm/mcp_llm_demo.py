#!/usr/bin/env python3
"""
MCP LLM Demo Script

This script demonstrates how to use the Model Context Protocol (MCP) with an actual LLM
to enhance vulnerability data with LLM-generated content using prompt templates.
"""

import json
import os
import sys
import argparse
import requests
from typing import Dict, Any, List, Optional

# Import MCP client
from mcp_integration import MCPClient, MCPEnhancedLLM

def load_vulnerability(file_path: str) -> Dict[str, Any]:
    """
    Load vulnerability data from a JSON file
    
    Args:
        file_path: Path to the vulnerability JSON file
        
    Returns:
        The vulnerability data as a dictionary
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading vulnerability file: {str(e)}")
        sys.exit(1)

def enhance_vulnerability(vulnerability: Dict[str, Any], mcp_endpoint: str, llm_provider: str = "openai") -> Dict[str, Any]:
    """
    Enhance vulnerability data using MCP and LLM
    
    Args:
        vulnerability: The vulnerability data
        mcp_endpoint: The MCP server endpoint
        llm_provider: The LLM provider to use
        
    Returns:
        The enhanced vulnerability data
    """
    # Create MCP-enhanced LLM
    llm = MCPEnhancedLLM(mcp_endpoint, llm_provider)
    
    # Create context from vulnerability data
    context = {
        "vulnerability": vulnerability["type"],
        "severity": vulnerability["severity"],
        "endpoint": vulnerability["endpoint"],
        "details": vulnerability["description"],
        "api_structure": vulnerability.get("api_structure", "REST API"),
        "evidence": vulnerability.get("evidence", "")
    }
    
    # Generate enhanced description
    print(f"Enhancing vulnerability: {vulnerability['type']}")
    enhanced_description = llm.generate("Enhance this vulnerability description", context)
    
    # Create enhanced vulnerability object
    enhanced_vulnerability = vulnerability.copy()
    enhanced_vulnerability["enhanced_description"] = enhanced_description
    
    return enhanced_vulnerability

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="MCP LLM Demo")
    parser.add_argument("--endpoint", default="http://localhost:3001/api/mcp/mcp",
                      help="MCP server endpoint URL")
    parser.add_argument("--vulnerability-file", required=True,
                      help="JSON file with vulnerability data")
    parser.add_argument("--llm-provider", default="openai",
                      choices=["openai", "ollama"],
                      help="LLM provider to use")
    parser.add_argument("--output-file",
                      help="Output file for enhanced vulnerability data")
    
    args = parser.parse_args()
    
    # Load vulnerability data
    vulnerability = load_vulnerability(args.vulnerability_file)
    
    # Enhance vulnerability
    enhanced_vulnerability = enhance_vulnerability(
        vulnerability, 
        args.endpoint,
        args.llm_provider
    )
    
    # Output enhanced vulnerability
    if args.output_file:
        with open(args.output_file, 'w') as f:
            json.dump(enhanced_vulnerability, f, indent=2)
        print(f"Enhanced vulnerability saved to: {args.output_file}")
    else:
        print("\nEnhanced Vulnerability:")
        print(json.dumps(enhanced_vulnerability, indent=2))

if __name__ == "__main__":
    main()
