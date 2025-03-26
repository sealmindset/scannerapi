#!/usr/bin/env python3
"""
Test script for the section enhancement functionality.
This script simulates a section enhancement request and processes it locally.
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

# Import the enhancement function from enhance_section.py
sys.path.append(str(Path(__file__).parent))
from enhance_section import get_llm_response

def main():
    parser = argparse.ArgumentParser(description='Test section enhancement')
    parser.add_argument('--provider', default='ollama', help='LLM provider (ollama or openai)')
    parser.add_argument('--model', default='llama3.3', help='LLM model name')
    parser.add_argument('--section', default='description', help='Section to enhance (description, risk, impact, examples, remediation)')
    parser.add_argument('--api-key', help='API key for OpenAI (if provider is openai)')
    
    args = parser.parse_args()
    
    # Sample vulnerability details
    vuln_details = {
        "name": "SQL Injection",
        "severity": "High",
        "url": "https://example.com/api/users?id=1",
        "evidence": "Response contains database error messages when submitting ' OR 1=1 --"
    }
    
    # Create the prompt based on the section type
    prompt = ""
    
    section = args.section
    if section == 'description':
        prompt = f"Generate a detailed description for the vulnerability: {vuln_details['name']}. "
        prompt += "This should explain what the vulnerability is, how it works, and why it's a security concern. "
    elif section == 'risk':
        prompt = f"Generate a comprehensive risk assessment for the vulnerability: {vuln_details['name']}. "
        prompt += "Explain the potential risks to the organization if this vulnerability is exploited. "
    elif section == 'impact':
        prompt = f"Generate an impact analysis for the vulnerability: {vuln_details['name']}. "
        prompt += "Describe the potential impact on the organization, users, and data if this vulnerability is exploited. "
    elif section == 'examples':
        prompt = f"Provide real-world examples of how the vulnerability: {vuln_details['name']} has been exploited in the past. "
        prompt += "Include notable security incidents, breaches, or attacks that utilized this type of vulnerability. "
    elif section == 'remediation':
        prompt = f"Provide detailed remediation steps for the vulnerability: {vuln_details['name']}. "
        prompt += "Include specific code examples, configuration changes, or best practices to fix this issue. "
    else:
        prompt = f"Generate enhanced content for the {section} section of the vulnerability: {vuln_details['name']}. "
    
    # Add severity context
    prompt += f"The severity of this vulnerability is {vuln_details['severity']}. "
    
    # Add URL context
    prompt += f"The affected endpoint is: {vuln_details['url']}. "
    
    # Add evidence context
    prompt += f"Here is the evidence of the vulnerability: {vuln_details['evidence']}. "
    
    print(f"Testing section enhancement for {section} with {args.provider} {args.model}")
    print(f"Prompt: {prompt}")
    print(f"Progress: 1/3 33.3%")
    
    # Get the LLM response
    enhanced_content = get_llm_response(prompt, args.provider, args.model, args.api_key)
    
    if enhanced_content:
        print("\nEnhanced content:")
        print("=" * 80)
        print(enhanced_content)
        print("=" * 80)
        
        # Save to a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.html') as f:
            f.write(enhanced_content)
            print(f"\nEnhanced content saved to: {f.name}")
    else:
        print("Error: Failed to get response from LLM")
        sys.exit(1)

if __name__ == '__main__':
    main()
