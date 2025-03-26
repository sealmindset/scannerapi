#!/usr/bin/env python3
"""
Fix script for LLM prompt backups functionality
"""

import os
import sys
import json
from pathlib import Path

# Add parent directory to path so we can import utils
sys.path.append(str(Path(__file__).parent.parent))
from utils.prompt_manager import create_backup, DEFAULT_PROMPTS_PATH

def main():
    """Create the backups directory and update permissions"""
    print(f"Default prompts path: {DEFAULT_PROMPTS_PATH}")
    
    # Check if the prompts file exists
    if not os.path.exists(DEFAULT_PROMPTS_PATH):
        print(f"Error: Prompts file {DEFAULT_PROMPTS_PATH} does not exist")
        return False
        
    # Create the backups directory in configs
    configs_dir = os.path.dirname(DEFAULT_PROMPTS_PATH)
    backups_dir = os.path.join(configs_dir, "backups")
    
    if not os.path.exists(backups_dir):
        print(f"Creating backups directory: {backups_dir}")
        os.makedirs(backups_dir, exist_ok=True)
    else:
        print(f"Backups directory already exists: {backups_dir}")
    
    # Set permissions to ensure web server can write to it
    try:
        print(f"Setting permissions on backups directory: {backups_dir}")
        os.chmod(backups_dir, 0o755)  # rwxr-xr-x
        print("Permissions set successfully")
    except Exception as e:
        print(f"Error setting permissions: {e}")
    
    # Create a test backup in the backups directory
    print("Creating test backup...")
    
    # Create a symlink to the backups directory for the web interface
    web_backups_dir = os.path.join(configs_dir, "web_backups")
    if not os.path.exists(web_backups_dir):
        try:
            print(f"Creating symlink from {backups_dir} to {web_backups_dir}")
            os.symlink(backups_dir, web_backups_dir)
            print("Symlink created successfully")
        except Exception as e:
            print(f"Error creating symlink: {e}")
    
    # Create a test backup
    backup_path = create_backup()
    
    if backup_path and os.path.exists(backup_path):
        print(f"Backup created successfully at: {backup_path}")
        
        # Copy the backup to the backups directory
        backup_filename = os.path.basename(backup_path)
        backup_copy_path = os.path.join(backups_dir, backup_filename)
        
        try:
            import shutil
            shutil.copy2(backup_path, backup_copy_path)
            print(f"Backup copied to: {backup_copy_path}")
        except Exception as e:
            print(f"Error copying backup: {e}")
        
        return True
    else:
        print("Error: Backup creation failed or backup file not found")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
