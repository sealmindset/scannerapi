#!/usr/bin/env python3
"""
Update LLM Modules Script

This script updates the LLM description and remediation modules to use the configurable prompts
from the prompt manager instead of hardcoded templates.
"""

import os
import sys
import re
import importlib.util
import logging
from pathlib import Path

# Add parent directory to path to import prompt_manager
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.prompt_manager import get_prompt_template, load_prompts
except ImportError:
    print("Error: Could not import prompt_manager. Make sure the utils directory is in your Python path.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("update_llm_modules")

def update_llm_description_module():
    """
    Update the llm_description.py module to use the prompt manager.
    """
    file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'llm_description.py')
    
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return False
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check if the file has already been updated
    if "from utils.prompt_manager import get_prompt_template" in content:
        logger.info(f"File already updated: {file_path}")
        return True
    
    # Add import for prompt_manager
    import_pattern = r"from langchain.prompts import PromptTemplate"
    import_replacement = "from langchain.prompts import PromptTemplate\nfrom utils.prompt_manager import get_prompt_template"
    content = re.sub(import_pattern, import_replacement, content)
    
    # Update the _setup_prompt_template method
    setup_pattern = r"def _setup_prompt_template\(self\) -> None:(\s+)template = \"\"\"(.*?)\"\"\""
    
    def setup_replacement(match):
        indent = match.group(1)
        return f"def _setup_prompt_template(self) -> None:{indent}# Get template from prompt manager{indent}template_str = get_prompt_template('description_template'){indent}if not template_str:{indent}    logger.warning('Could not load description template from prompt manager, using default template'){indent}    template_str = \"\"\"{match.group(2)}\"\"\""
    
    content = re.sub(setup_pattern, setup_replacement, content, flags=re.DOTALL)
    
    # Update the prompt template creation
    template_pattern = r"self.prompt_template = PromptTemplate\(template=template, input_variables=\[.*?\]\)"
    template_replacement = "self.prompt_template = PromptTemplate(template=template_str, input_variables=['vulnerability', 'severity', 'endpoint', 'details', 'api_structure'])"
    content = re.sub(template_pattern, template_replacement, content)
    
    # Write the updated content back to the file
    with open(file_path, 'w') as f:
        f.write(content)
    
    logger.info(f"Updated file: {file_path}")
    return True

def update_llm_remediation_module():
    """
    Update the llm_remediation_middleware.py module to use the prompt manager.
    """
    file_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'llm_remediation_middleware.py')
    
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return False
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check if the file has already been updated
    if "from utils.prompt_manager import get_prompt_template" in content:
        logger.info(f"File already updated: {file_path}")
        return True
    
    # Add import for prompt_manager
    import_pattern = r"from langchain.prompts import PromptTemplate"
    import_replacement = "from langchain.prompts import PromptTemplate\nfrom utils.prompt_manager import get_prompt_template"
    content = re.sub(import_pattern, import_replacement, content)
    
    # Update the _setup_prompt_template method
    setup_pattern = r"def _setup_prompt_template\(self\):(\s+)template = \"\"\"(.*?)\"\"\""
    
    def setup_replacement(match):
        indent = match.group(1)
        return f"def _setup_prompt_template(self):{indent}# Get template from prompt manager{indent}template_str = get_prompt_template('remediation_template'){indent}if not template_str:{indent}    logger.warning('Could not load remediation template from prompt manager, using default template'){indent}    template_str = \"\"\"{match.group(2)}\"\"\""
    
    content = re.sub(setup_pattern, setup_replacement, content, flags=re.DOTALL)
    
    # Update the prompt template creation
    template_pattern = r"self.prompt_template = PromptTemplate\(template=template, input_variables=\[.*?\]\)"
    template_replacement = "self.prompt_template = PromptTemplate(template=template_str, input_variables=['vulnerability', 'severity', 'endpoint', 'details', 'api_structure'])"
    content = re.sub(template_pattern, template_replacement, content)
    
    # Write the updated content back to the file
    with open(file_path, 'w') as f:
        f.write(content)
    
    logger.info(f"Updated file: {file_path}")
    return True

def main():
    """
    Main function to update the LLM modules.
    """
    logger.info("Starting update of LLM modules")
    
    # Make sure the prompt manager is working
    try:
        prompts = load_prompts()
        if not prompts:
            logger.error("Could not load prompts from prompt manager")
            return 1
        
        logger.info(f"Loaded {len(prompts)} prompts from prompt manager")
    except Exception as e:
        logger.error(f"Error loading prompts: {str(e)}")
        return 1
    
    # Update the modules
    success_description = update_llm_description_module()
    success_remediation = update_llm_remediation_module()
    
    if success_description and success_remediation:
        logger.info("Successfully updated all LLM modules")
        return 0
    else:
        logger.error("Failed to update some LLM modules")
        return 1

if __name__ == "__main__":
    sys.exit(main())
