#!/usr/bin/env python3
"""
Test script for the prompt manager utility.
"""

import json
from utils.prompt_manager import (
    load_prompts,
    get_prompt_template,
    list_available_prompts
)

def main():
    """Main function to test the prompt manager."""
    print("Testing prompt manager...")
    
    # Load all prompts
    prompts = load_prompts()
    print(f"Loaded {len(prompts)} top-level prompts")
    
    # Get description template
    description_template = get_prompt_template("description_template")
    if description_template:
        print("\nDescription Template:")
        print(f"Length: {len(description_template)} characters")
        print(f"First 100 chars: {description_template[:100]}...")
    else:
        print("Failed to load description template")
    
    # Get remediation template
    remediation_template = get_prompt_template("remediation_template")
    if remediation_template:
        print("\nRemediation Template:")
        print(f"Length: {len(remediation_template)} characters")
        print(f"First 100 chars: {remediation_template[:100]}...")
    else:
        print("Failed to load remediation template")
    
    # Get a section template
    section_template = get_prompt_template("section_templates.description")
    if section_template:
        print("\nSection Template (Description):")
        print(f"Length: {len(section_template)} characters")
        print(f"First 100 chars: {section_template[:100]}...")
    else:
        print("Failed to load section template")
    
    # List all available prompts
    print("\nAvailable Prompts:")
    available_prompts = list_available_prompts()
    for i, prompt in enumerate(available_prompts, 1):
        print(f"{i}. {prompt['id']} - {prompt['name']}")
        print(f"   Description: {prompt['description']}")
        print(f"   Preview: {prompt['template_preview']}")

if __name__ == "__main__":
    main()
