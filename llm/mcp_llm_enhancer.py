#!/usr/bin/env python3
"""
MCP-Enhanced LLM Vulnerability Enhancer

This module integrates the Model Context Protocol (MCP) with the existing
vulnerability enhancement process to provide more accurate and context-aware
enhancements to scan results.
"""

import json
import os
import sys
import argparse
from typing import Dict, List, Any, Optional

# Import MCP client
from mcp_integration import MCPClient

class MCPEnhancedVulnerabilityProcessor:
    """
    Enhances vulnerability data using MCP to access prompt templates and other data sources
    """
    def __init__(self, mcp_endpoint: str, input_file: str, output_file: str):
        """
        Initialize the MCP-enhanced vulnerability processor
        
        Args:
            mcp_endpoint: The MCP server endpoint URL
            input_file: Path to the input JSON file containing vulnerability data
            output_file: Path to the output JSON file for enhanced vulnerability data
        """
        self.mcp_client = MCPClient(mcp_endpoint)
        self.input_file = input_file
        self.output_file = output_file
        
        # Initialize MCP connection
        self.mcp_client.initialize()
        print(f"MCP connection initialized successfully")
    
    def load_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Load vulnerabilities from the input file
        
        Returns:
            List of vulnerability objects
        """
        try:
            with open(self.input_file, 'r') as f:
                data = json.load(f)
                
            # Handle different formats of vulnerability data
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'vulnerabilities' in data:
                return data['vulnerabilities']
            elif isinstance(data, dict) and 'results' in data:
                return data['results']
            else:
                print(f"Warning: Unexpected data format in {self.input_file}")
                return []
        except Exception as e:
            print(f"Error loading vulnerabilities: {str(e)}")
            return []
    
    def get_enhancement_template(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get the appropriate enhancement template for a vulnerability
        
        Args:
            vulnerability: The vulnerability object
            
        Returns:
            The enhancement template
        """
        # Determine the appropriate template based on vulnerability type
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', '').lower()
        
        # Try to find a template specific to this vulnerability type
        search_terms = [vuln_type]
        
        # Add severity if available
        if severity:
            search_terms.append(severity)
        
        # Search for templates matching the vulnerability type
        for term in search_terms:
            if not term:
                continue
                
            search_results = self.mcp_client.search_prompt_templates(term)
            if "results" in search_results and search_results["results"]:
                return search_results["results"][0]
        
        # Fall back to a general vulnerability template
        templates = self.mcp_client.list_prompt_templates("vulnerability")
        if "templates" in templates and templates["templates"]:
            return templates["templates"][0]
        
        # If no templates found, return a default template structure
        return {
            "name": "Default Vulnerability Enhancement",
            "description": "Default template for enhancing vulnerability information",
            "template": "Analyze the following vulnerability:\n\nType: {{type}}\nSeverity: {{severity}}\nEndpoint: {{endpoint}}\nDescription: {{description}}\n\nProvide a detailed explanation of this vulnerability, its potential impact, and remediation steps."
        }
    
    def fill_template(self, template: Dict[str, Any], vulnerability: Dict[str, Any]) -> str:
        """
        Fill a template with vulnerability data
        
        Args:
            template: The template object
            vulnerability: The vulnerability object
            
        Returns:
            The filled template
        """
        template_text = template.get("template", "")
        
        # Map vulnerability fields to template variables
        context = {
            "type": vulnerability.get("type", "Unknown"),
            "severity": vulnerability.get("severity", "Unknown"),
            "endpoint": vulnerability.get("endpoint", vulnerability.get("url", "Unknown")),
            "description": vulnerability.get("description", "No description available"),
            "method": vulnerability.get("method", "Unknown"),
            "parameters": json.dumps(vulnerability.get("parameters", {})),
            "headers": json.dumps(vulnerability.get("headers", {}))
        }
        
        # Simple template variable replacement
        for key, value in context.items():
            placeholder = f"{{{{{key}}}}}"
            if placeholder in template_text:
                template_text = template_text.replace(placeholder, str(value))
        
        return template_text
    
    def enhance_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance a vulnerability using MCP templates
        
        Args:
            vulnerability: The vulnerability object
            
        Returns:
            The enhanced vulnerability object
        """
        # Get the appropriate template
        template = self.get_enhancement_template(vulnerability)
        print(f"Using template: {template.get('name', 'Unknown')} for vulnerability: {vulnerability.get('name', 'Unknown')}")
        
        # Fill the template with vulnerability data
        filled_template = self.fill_template(template, vulnerability)
        
        # In a real implementation, you would now send this to your LLM
        # and process the response to enhance the vulnerability
        
        # For this demo, we'll just add a note about the enhancement
        enhanced_vulnerability = vulnerability.copy()
        enhanced_vulnerability["enhanced"] = True
        enhanced_vulnerability["enhancement_template"] = template.get("name", "Unknown")
        enhanced_vulnerability["enhancement_note"] = "This vulnerability was enhanced using MCP templates"
        
        # In a real implementation, you would update these fields based on LLM output
        if "remediation" not in enhanced_vulnerability:
            enhanced_vulnerability["remediation"] = "Implement proper input validation and sanitization"
        
        if "impact" not in enhanced_vulnerability:
            enhanced_vulnerability["impact"] = "This vulnerability could potentially lead to unauthorized access or data exposure"
        
        return enhanced_vulnerability
    
    def process_vulnerabilities(self):
        """
        Process all vulnerabilities in the input file and save to output file
        """
        # Load vulnerabilities
        vulnerabilities = self.load_vulnerabilities()
        print(f"Loaded {len(vulnerabilities)} vulnerabilities from {self.input_file}")
        
        # Enhance each vulnerability
        enhanced_vulnerabilities = []
        for vulnerability in vulnerabilities:
            enhanced_vulnerability = self.enhance_vulnerability(vulnerability)
            enhanced_vulnerabilities.append(enhanced_vulnerability)
        
        # Save enhanced vulnerabilities
        output_data = {
            "vulnerabilities": enhanced_vulnerabilities,
            "enhanced": True,
            "enhancement_method": "MCP-Enhanced LLM"
        }
        
        try:
            with open(self.output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"Enhanced vulnerabilities saved to {self.output_file}")
        except Exception as e:
            print(f"Error saving enhanced vulnerabilities: {str(e)}")


def main():
    """Main function to demonstrate MCP-enhanced vulnerability processing"""
    parser = argparse.ArgumentParser(description="Enhance vulnerability data using MCP")
    parser.add_argument("--input", "-i", required=True, help="Input JSON file with vulnerability data")
    parser.add_argument("--output", "-o", required=True, help="Output JSON file for enhanced vulnerability data")
    parser.add_argument("--mcp-endpoint", default="http://localhost:3000/api/mcp/mcp", 
                        help="MCP server endpoint URL")
    
    args = parser.parse_args()
    
    # Create processor and process vulnerabilities
    processor = MCPEnhancedVulnerabilityProcessor(
        args.mcp_endpoint,
        args.input,
        args.output
    )
    
    processor.process_vulnerabilities()


if __name__ == "__main__":
    main()
