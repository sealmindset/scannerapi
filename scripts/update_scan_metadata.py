#!/usr/bin/env python3
"""
Update scan metadata after enhancing individual sections.
This ensures that the enhanced version replaces the original in the UI.
"""

import argparse
import json
import os
import sys
import datetime
import subprocess
from pathlib import Path

def update_scan_metadata(scan_id, section, enhanced_content, metadata_file=None):
    """
    Update the scan metadata with enhanced section content.
    
    Args:
        scan_id (str): The ID of the scan to update
        section (str): The section that was enhanced (description, risk, impact, examples, remediation)
        enhanced_content (str): The enhanced content for the section
        metadata_file (str, optional): Path to the metadata file. If None, will use default location.
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Determine metadata file path if not provided
        if not metadata_file:
            # Default location is in the results directory
            results_dir = Path(__file__).parent.parent / 'results'
            metadata_file = results_dir / f"{scan_id}_metadata.json"
        else:
            metadata_file = Path(metadata_file)
            
        # Check if metadata file exists
        if not metadata_file.exists():
            print(f"Error: Metadata file not found: {metadata_file}", file=sys.stderr)
            return False
            
        # Load existing metadata
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
            
        # Update the appropriate section in the metadata
        vulnerabilities = metadata.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if section == 'description':
                vuln['description'] = enhanced_content
            elif section == 'risk':
                vuln['risk_assessment'] = enhanced_content
            elif section == 'impact':
                vuln['impact_analysis'] = enhanced_content
            elif section == 'examples':
                vuln['real_world_examples'] = enhanced_content
            elif section == 'remediation':
                vuln['remediation'] = enhanced_content
                
        # Add flag to indicate this scan has been enhanced with LLM
        metadata['enhanced_with_llm'] = True
        metadata['last_enhanced_section'] = section
        metadata['last_enhanced_timestamp'] = datetime.datetime.now().isoformat()
        
        # Save updated metadata
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
            
        # Trigger Redis cache update by running the sync script
        try:
            web_interface_dir = Path(__file__).parent.parent / 'web-interface'
            sync_script = web_interface_dir / 'utils' / 'sync-redis.js'
            
            if sync_script.exists():
                print(f"Updating Redis cache for scan {scan_id}...")
                result = subprocess.run(
                    ['node', str(sync_script)],
                    cwd=str(web_interface_dir),
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    print("Redis cache updated successfully")
                else:
                    print(f"Warning: Redis cache update failed: {result.stderr}", file=sys.stderr)
            else:
                print(f"Warning: Redis sync script not found at {sync_script}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Failed to update Redis cache: {str(e)}", file=sys.stderr)
            
        print(f"Successfully updated metadata for scan {scan_id}, section {section}")
        return True
        
    except Exception as e:
        print(f"Error updating scan metadata: {str(e)}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description='Update scan metadata after enhancing sections')
    parser.add_argument('--scan-id', required=True, help='ID of the scan to update')
    parser.add_argument('--section', required=True, 
                       choices=['description', 'risk', 'impact', 'examples', 'remediation'],
                       help='Section that was enhanced')
    parser.add_argument('--content-file', required=True, help='File containing the enhanced content')
    parser.add_argument('--metadata-file', help='Path to the metadata file (optional)')
    
    args = parser.parse_args()
    
    try:
        # Read the enhanced content
        with open(args.content_file, 'r') as f:
            enhanced_content = f.read()
            
        # Update the metadata
        success = update_scan_metadata(
            args.scan_id,
            args.section,
            enhanced_content,
            args.metadata_file
        )
        
        if success:
            print("Metadata updated successfully")
            sys.exit(0)
        else:
            print("Failed to update metadata", file=sys.stderr)
            sys.exit(1)
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    # Fix import for datetime
    from importlib import import_module
    main()
