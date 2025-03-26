#!/usr/bin/env python3
"""
Test script for creating a backup of the LLM prompts file
"""

import os
import sys
import json
from pathlib import Path

# Add parent directory to path so we can import utils
sys.path.append(str(Path(__file__).parent.parent))
from utils.prompt_manager import create_backup, DEFAULT_PROMPTS_PATH

def main():
    """Create a backup of the prompts file and verify it exists"""
    print(f"Default prompts path: {DEFAULT_PROMPTS_PATH}")
    
    # Check if the prompts file exists
    if not os.path.exists(DEFAULT_PROMPTS_PATH):
        print(f"Error: Prompts file {DEFAULT_PROMPTS_PATH} does not exist")
        return False
        
    # Check if the backup directory exists, create if not
    backup_dir = os.path.join(os.path.dirname(DEFAULT_PROMPTS_PATH), "backups")
    if not os.path.exists(backup_dir):
        print(f"Creating backup directory: {backup_dir}")
        os.makedirs(backup_dir, exist_ok=True)
    
    # Create the backup
    print("Creating backup...")
    backup_path = create_backup()
    
    if backup_path and os.path.exists(backup_path):
        print(f"Backup created successfully at: {backup_path}")
        
        # Verify the backup file contains the same data
        try:
            with open(DEFAULT_PROMPTS_PATH, 'r') as f:
                original_data = json.load(f)
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)
                
            if original_data == backup_data:
                print("Backup verification successful - content matches original")
            else:
                print("Warning: Backup content does not match original")
        except Exception as e:
            print(f"Error verifying backup: {e}")
        
        return True
    else:
        print("Error: Backup creation failed or backup file not found")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
