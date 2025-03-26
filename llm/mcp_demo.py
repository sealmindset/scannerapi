#!/usr/bin/env python3
"""
MCP Demo Script

This script demonstrates how to use the Model Context Protocol (MCP) to enhance
vulnerability data with LLM-generated content using prompt templates.
"""

import json
import os
import sys
import argparse
from typing import Dict, Any, List, Optional
import requests

# Import MCP client and enhanced LLM
from mcp_integration import MCPClient, MCPEnhancedLLM

class MCPDemo:
    """
    Demonstrates MCP functionality for LLM enhancement
    """
    def __init__(self, mcp_endpoint: str):
        """
        Initialize the MCP demo
        
        Args:
            mcp_endpoint: The MCP server endpoint URL
        """
        self.mcp_client = MCPClient(mcp_endpoint)
        print(f"Initializing MCP client with endpoint: {mcp_endpoint}")
    
    def initialize(self):
        """Initialize the MCP connection"""
        print("Initializing MCP connection...")
        result = self.mcp_client.initialize()
        print(f"MCP initialization result: {result}")
        return result
    
    def list_tools(self):
        """List available MCP tools"""
        print("Listing available MCP tools...")
        tools = self.mcp_client.list_tools()
        print(f"Found {len(tools['tools'])} tools:")
        for tool in tools['tools']:
            print(f"  - {tool['name']}: {tool['description']}")
        return tools
    
    def list_templates(self, category: str = 'all'):
        """
        List prompt templates by category
        
        Args:
            category: Category of templates to list
        """
        print(f"Listing prompt templates for category: {category}")
        templates = self.mcp_client.list_prompt_templates(category)
        
        if 'error' in templates:
            print(f"Error: {templates['error']}")
            return templates
        
        print(f"Found {templates['total']} templates:")
        for template in templates['templates']:
            print(f"  - {template['name']} (ID: {template['id']})")
            print(f"    Description: {template.get('description', 'No description')}")
            print(f"    Category: {template.get('category', 'No category')}")
            print()
        
        return templates
    
    def search_templates(self, query: str):
        """
        Search for prompt templates
        
        Args:
            query: Search query
        """
        print(f"Searching for prompt templates with query: {query}")
        results = self.mcp_client.search_prompt_templates(query)
        
        if 'error' in results:
            print(f"Error: {results['error']}")
            return results
        
        print(f"Found {results['count']} results:")
        for template in results['results']:
            print(f"  - {template['name']} (ID: {template['id']})")
            print(f"    Description: {template.get('description', 'No description')}")
            print(f"    Category: {template.get('category', 'No category')}")
            print()
        
        return results
    
    def get_template(self, template_id: str):
        """
        Get a prompt template by ID
        
        Args:
            template_id: ID of the template to get
        """
        print(f"Getting prompt template with ID: {template_id}")
        result = self.mcp_client.get_prompt_template(template_id)
        
        if 'error' in result:
            print(f"Error: {result['error']}")
            return result
        
        template = result['template']
        print(f"Template: {template['name']}")
        print(f"Description: {template.get('description', 'No description')}")
        print(f"Category: {template.get('category', 'No category')}")
        print("\nTemplate content:")
        print("-------------------")
        print(template['template'])
        print("-------------------")
        
        return result
    
    def enhance_vulnerability(self, vulnerability: Dict[str, Any], template_id: Optional[str] = None):
        """
        Enhance a vulnerability using a prompt template
        
        Args:
            vulnerability: Vulnerability data to enhance
            template_id: ID of the template to use (optional)
        """
        # If no template ID is provided, search for an appropriate template
        if not template_id:
            # Try to find a template based on vulnerability type
            vuln_type = vulnerability.get('type', '').lower()
            search_results = self.mcp_client.search_prompt_templates(vuln_type)
            
            if 'results' in search_results and search_results['results']:
                template_id = search_results['results'][0]['id']
                print(f"Found template for vulnerability type '{vuln_type}': {template_id}")
            else:
                # Fall back to the default description template
                template_id = 'description_template'
                print(f"Using default template: {template_id}")
        
        # Get the template
        template_result = self.mcp_client.get_prompt_template(template_id)
        
        if 'error' in template_result:
            print(f"Error getting template: {template_result['error']}")
            return None
        
        template = template_result['template']
        
        # Fill the template with vulnerability data
        filled_template = self._fill_template(template, vulnerability)
        
        print("\nFilled template:")
        print("-------------------")
        print(filled_template)
        print("-------------------")
        
        # In a real implementation, you would now send this to your LLM
        # and process the response to enhance the vulnerability
        
        print("\nIn a real implementation, this would be sent to an LLM for processing.")
        print("The LLM would generate enhanced content based on the template.")
        
        return {
            "template_id": template_id,
            "template_name": template['name'],
            "filled_template": filled_template,
            "vulnerability": vulnerability
        }
    
    def _fill_template(self, template: Dict[str, Any], vulnerability: Dict[str, Any]) -> str:
        """
        Fill a template with vulnerability data
        
        Args:
            template: The template object
            vulnerability: The vulnerability data
            
        Returns:
            The filled template
        """
        template_text = template.get("template", "")
        
        # Map vulnerability fields to template variables
        context = {
            "vulnerability": vulnerability.get("type", "Unknown vulnerability"),
            "vulnerability_name": vulnerability.get("type", "Unknown vulnerability"),
            "severity": vulnerability.get("severity", "Unknown"),
            "endpoint": vulnerability.get("endpoint", vulnerability.get("url", "Unknown")),
            "details": vulnerability.get("description", "No description available"),
            "evidence": json.dumps(vulnerability, indent=2),
            "api_structure": vulnerability.get("api_structure", "Unknown API structure")
        }
        
        # Simple template variable replacement
        for key, value in context.items():
            placeholder = f"{{{key}}}"
            if placeholder in template_text:
                template_text = template_text.replace(placeholder, str(value))
        
        return template_text


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="MCP Demo")
    parser.add_argument("--endpoint", default="http://localhost:3002/api/mcp/mcp",
                      help="MCP server endpoint URL")
    parser.add_argument("--action", choices=["list", "search", "get", "enhance", "enhance-llm"],
                      default="list", help="Action to perform")
    parser.add_argument("--category", default="all",
                      help="Category for listing templates")
    parser.add_argument("--query", help="Search query for templates")
    parser.add_argument("--template-id", help="Template ID for get action")
    parser.add_argument("--vulnerability-file", help="JSON file with vulnerability data for enhance action")
    parser.add_argument("--llm-provider", choices=["openai", "ollama", "simulation"],
                      default="simulation", help="LLM provider to use")
    parser.add_argument("--output-file", help="Output file for enhanced data")
    
    args = parser.parse_args()
    
    # Create demo instance
    demo = MCPDemo(args.endpoint)
    
    # Initialize MCP connection
    demo.initialize()
    
    # Perform action
    if args.action == "list":
        if args.category:
            demo.list_templates(args.category)
        else:
            demo.list_tools()
    
    elif args.action == "search":
        if not args.query:
            print("Error: --query is required for search action")
            sys.exit(1)
        
        demo.search_templates(args.query)
    
    elif args.action == "get":
        if not args.template_id:
            print("Error: --template-id is required for get action")
            sys.exit(1)
        
        demo.get_template(args.template_id)
    
    elif args.action == "enhance":
        if not args.vulnerability_file:
            print("Error: --vulnerability-file is required for enhance action")
            sys.exit(1)
        
        try:
            with open(args.vulnerability_file, 'r') as f:
                vulnerability = json.load(f)
            
            result = demo.enhance_vulnerability(vulnerability, args.template_id)
            
            # Save to output file if specified
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Enhanced vulnerability saved to {args.output_file}")
                
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)
            
    elif args.action == "enhance-llm":
        if not args.query and not args.vulnerability_file:
            print("Error: Either --query or --vulnerability-file is required for enhance-llm action")
            sys.exit(1)
        
        try:
            # Create MCP-enhanced LLM
            print(f"\nInitializing MCP-enhanced LLM with provider: {args.llm_provider}")
            llm = MCPEnhancedLLM(args.endpoint, args.llm_provider)
            
            context = {}
            
            # If vulnerability file is provided, use it as context
            if args.vulnerability_file:
                with open(args.vulnerability_file, 'r') as f:
                    vulnerability = json.load(f)
                context = vulnerability
                
                # If no query is provided, generate one based on vulnerability type
                if not args.query:
                    vuln_type = vulnerability.get('type', 'Unknown')
                    args.query = f"Analyze and describe the {vuln_type} vulnerability"
            
            print(f"\nGenerating response for query: {args.query}")
            print(f"Using context: {json.dumps(context, indent=2)}\n")
            
            # Generate response
            response = llm.generate(args.query, context)
            
            print("\nLLM Response:")
            print("-------------------")
            print(response)
            print("-------------------\n")
            
            # Save to output file if specified
            if args.output_file:
                result = {
                    "query": args.query,
                    "context": context,
                    "response": response
                }
                with open(args.output_file, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Enhanced response saved to {args.output_file}")
                
        except Exception as e:
            print(f"Error: {str(e)}")
            sys.exit(1)


if __name__ == "__main__":
    main()
