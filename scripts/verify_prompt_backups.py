#!/usr/bin/env python3
"""
Comprehensive verification script for LLM prompt backups functionality.
This script tests both direct Python API and web interface functionality.
"""

import os
import sys
import json
import time
import shutil
import datetime
import requests
from pathlib import Path

# Add parent directory to path so we can import utils
sys.path.append(str(Path(__file__).parent.parent))
from utils.prompt_manager import create_backup, DEFAULT_PROMPTS_PATH

# Configuration
WEB_SERVER_URL = "http://localhost:3000"  # Scanner web interface port
BACKUP_TEST_COUNT = 3  # Number of test backups to create
CONFIGS_DIR = os.path.dirname(DEFAULT_PROMPTS_PATH)
BACKUPS_DIR = os.path.join(CONFIGS_DIR, "backups")


def test_direct_backup():
    """Test backup creation directly through the Python API"""
    print("\n=== Testing Direct Backup Creation ===")
    print(f"Default prompts path: {DEFAULT_PROMPTS_PATH}")
    
    # Check if the prompts file exists
    if not os.path.exists(DEFAULT_PROMPTS_PATH):
        print(f"Error: Prompts file {DEFAULT_PROMPTS_PATH} does not exist")
        return False
        
    # Ensure backups directory exists
    if not os.path.exists(BACKUPS_DIR):
        print(f"Creating backups directory: {BACKUPS_DIR}")
        os.makedirs(BACKUPS_DIR, exist_ok=True)
    else:
        print(f"Backups directory exists: {BACKUPS_DIR}")
    
    # Create a test backup
    print("Creating backup...")
    backup_path = create_backup()
    
    if backup_path and os.path.exists(backup_path):
        print(f"Backup created successfully at: {backup_path}")
        
        # Verify backup content
        try:
            with open(DEFAULT_PROMPTS_PATH, 'r') as f:
                original_content = json.load(f)
            
            with open(backup_path, 'r') as f:
                backup_content = json.load(f)
                
            if original_content == backup_content:
                print("Backup verification successful - content matches original")
                return True
            else:
                print("Error: Backup content does not match original")
                return False
        except Exception as e:
            print(f"Error verifying backup content: {e}")
            return False
    else:
        print("Error: Backup creation failed or backup file not found")
        return False


def test_web_interface_backup():
    """Test backup creation through the web interface"""
    print("\n=== Testing Web Interface Backup Creation ===")
    
    try:
        # Check if web server is running
        try:
            response = requests.get(f"{WEB_SERVER_URL}/admin/prompts")
            if response.status_code != 200:
                print(f"Web server returned status code {response.status_code}")
                return False
            print("Web server is running")
        except requests.exceptions.ConnectionError:
            print(f"Error: Could not connect to web server at {WEB_SERVER_URL}")
            print("Make sure the web server is running before running this test")
            return False
        
        # Create backup through web interface
        print("Creating backup through web interface...")
        response = requests.post(f"{WEB_SERVER_URL}/admin/prompts/backup/create")
        
        if response.status_code != 200:
            print(f"Error: Web server returned status code {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
        data = response.json()
        if not data.get('success'):
            print(f"Error: Backup creation failed - {data.get('error', 'Unknown error')}")
            return False
            
        backup_path = data.get('backupPath')
        print(f"Backup created successfully at: {backup_path}")
        
        # Get list of backups
        print("Getting list of backups...")
        response = requests.get(f"{WEB_SERVER_URL}/admin/prompts/backups")
        
        if response.status_code != 200:
            print(f"Error: Failed to get backups list - status code {response.status_code}")
            return False
            
        backups_data = response.json()
        backups = backups_data.get('backups', [])
        print(f"Found {len(backups)} backups")
        
        if len(backups) == 0:
            print("Error: No backups found")
            return False
            
        # Check if our backup is in the list
        backup_found = False
        backup_filename = os.path.basename(backup_path) if backup_path else ''
        print(f"Looking for backup with filename: {backup_filename}")
        
        for backup in backups:
            backup_path_from_list = backup.get('path', '')
            if backup_filename and backup_filename in backup_path_from_list:
                backup_found = True
                print(f"Found backup in list: {backup_path_from_list}")
                break
                
        if not backup_found:
            print(f"Error: Created backup not found in backups list")
            return False
            
        print("Web interface backup test successful")
        return True
        
    except Exception as e:
        print(f"Error testing web interface backup: {e}")
        return False


def test_multiple_backups():
    """Test creating multiple backups and verify they're all accessible"""
    print("\n=== Testing Multiple Backups ===")
    
    backup_paths = []
    for i in range(BACKUP_TEST_COUNT):
        print(f"Creating backup {i+1}/{BACKUP_TEST_COUNT}...")
        backup_path = create_backup()
        
        if backup_path and os.path.exists(backup_path):
            print(f"Backup {i+1} created at: {backup_path}")
            backup_paths.append(backup_path)
        else:
            print(f"Error creating backup {i+1}")
            
        # Wait a second to ensure different timestamps
        time.sleep(1)
    
    # Verify all backups were created
    if len(backup_paths) != BACKUP_TEST_COUNT:
        print(f"Error: Expected {BACKUP_TEST_COUNT} backups, but created {len(backup_paths)}")
        return False
        
    # Get list of backups from web interface
    try:
        print("Getting backups list from web interface...")
        response = requests.get(f"{WEB_SERVER_URL}/admin/prompts/backups")
        
        if response.status_code != 200:
            print(f"Error: Failed to get backups list - status code {response.status_code}")
            return False
            
        backups_data = response.json()
        backups = backups_data.get('backups', [])
        print(f"Found {len(backups)} backups in web interface")
        
        # Check if all our backups are in the list
        found_count = 0
        for backup_path in backup_paths:
            for backup in backups:
                if backup_path in backup.get('path', '') or os.path.basename(backup_path) in backup.get('name', ''):
                    found_count += 1
                    break
                    
        if found_count != len(backup_paths):
            print(f"Error: Only {found_count}/{len(backup_paths)} backups found in web interface")
            return False
            
        print("Multiple backups test successful")
        return True
        
    except Exception as e:
        print(f"Error testing multiple backups: {e}")
        return False


def main():
    """Run all tests"""
    print("=== LLM Prompt Backups Verification ===")
    print(f"Current time: {datetime.datetime.now()}")
    print(f"Default prompts path: {DEFAULT_PROMPTS_PATH}")
    print(f"Backups directory: {BACKUPS_DIR}")
    
    # Run tests
    direct_backup_success = test_direct_backup()
    web_backup_success = test_web_interface_backup()
    multiple_backups_success = test_multiple_backups()
    
    # Print summary
    print("\n=== Test Summary ===")
    print(f"Direct backup test: {'PASSED' if direct_backup_success else 'FAILED'}")
    print(f"Web interface backup test: {'PASSED' if web_backup_success else 'FAILED'}")
    print(f"Multiple backups test: {'PASSED' if multiple_backups_success else 'FAILED'}")
    
    # Overall result
    if direct_backup_success and web_backup_success and multiple_backups_success:
        print("\n✅ All tests PASSED - Backup functionality is working correctly")
        return True
    else:
        print("\n❌ Some tests FAILED - Backup functionality needs attention")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
