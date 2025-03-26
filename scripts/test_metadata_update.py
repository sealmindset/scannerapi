#!/usr/bin/env python3
"""
Test script for the metadata update functionality.
This script simulates updating scan metadata after enhancing a section.
"""

import argparse
import json
import os
import sys
from pathlib import Path

def create_test_metadata(scan_id, output_dir=None):
    """Create a test metadata file for testing the update functionality"""
    if not output_dir:
        output_dir = Path(__file__).parent.parent / 'results'
    
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True, parents=True)
    
    metadata_file = output_dir / f"{scan_id}_metadata.json"
    
    # Create a simple metadata structure
    metadata = {
        "scan_id": scan_id,
        "scan_date": "2025-03-21T19:42:02-05:00",
        "target": "https://example.com",
        "scan_type": "web",
        "vulnerabilities": [
            {
                "id": "vuln-001",
                "name": "SQL Injection",
                "severity": "High",
                "description": "Original description content",
                "risk_assessment": "Original risk content",
                "impact_analysis": "Original impact content",
                "real_world_examples": "Original examples content",
                "remediation": "Original remediation content"
            }
        ]
    }
    
    # Write the metadata file
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
        
    print(f"Created test metadata file: {metadata_file}")
    return metadata_file

def test_update_metadata(scan_id, section, content, metadata_file=None):
    """Test the update_scan_metadata.py script with the given parameters"""
    # Import the update_scan_metadata module
    sys.path.insert(0, str(Path(__file__).parent))
    from update_scan_metadata import update_scan_metadata
    
    # Create a temporary file with the enhanced content
    temp_dir = Path('/tmp')
    content_file = temp_dir / f"test_content_{scan_id}_{section}.html"
    
    with open(content_file, 'w') as f:
        f.write(content)
    
    print(f"Created test content file: {content_file}")
    
    # Update the metadata
    result = update_scan_metadata(scan_id, section, content, metadata_file)
    
    if result:
        print(f"Successfully updated metadata for scan {scan_id}, section {section}")
        
        # Read the updated metadata
        with open(metadata_file, 'r') as f:
            updated_metadata = json.load(f)
            
        # Check if the section was updated
        vuln = updated_metadata.get('vulnerabilities', [])[0]
        if section == 'description':
            updated_content = vuln.get('description', '')
        elif section == 'risk':
            updated_content = vuln.get('risk_assessment', '')
        elif section == 'impact':
            updated_content = vuln.get('impact_analysis', '')
        elif section == 'examples':
            updated_content = vuln.get('real_world_examples', '')
        elif section == 'remediation':
            updated_content = vuln.get('remediation', '')
        
        print(f"\nUpdated {section} content:")
        print("="*80)
        print(updated_content)
        print("="*80)
        
        # Check if the enhanced_with_llm flag was set
        if updated_metadata.get('enhanced_with_llm'):
            print("\nMetadata flag 'enhanced_with_llm' was set correctly")
        else:
            print("\nWARNING: Metadata flag 'enhanced_with_llm' was not set")
            
        # Check if the last_enhanced_section was set
        if updated_metadata.get('last_enhanced_section') == section:
            print(f"Metadata field 'last_enhanced_section' was set correctly to '{section}'")
        else:
            print(f"WARNING: Metadata field 'last_enhanced_section' was not set correctly")
            
        # Check if the last_enhanced_timestamp was set
        if updated_metadata.get('last_enhanced_timestamp'):
            print(f"Metadata field 'last_enhanced_timestamp' was set to: {updated_metadata.get('last_enhanced_timestamp')}")
        else:
            print(f"WARNING: Metadata field 'last_enhanced_timestamp' was not set")
    else:
        print(f"Failed to update metadata for scan {scan_id}, section {section}")
    
    # Clean up
    os.unlink(content_file)
    
    return result

def main():
    parser = argparse.ArgumentParser(description='Test the metadata update functionality')
    parser.add_argument('--scan-id', default='test-scan-001', help='ID of the scan to update')
    parser.add_argument('--section', default='description', 
                       choices=['description', 'risk', 'impact', 'examples', 'remediation'],
                       help='Section to enhance')
    parser.add_argument('--content', default='This is enhanced content for testing purposes.',
                       help='Enhanced content to use for the test')
    
    args = parser.parse_args()
    
    # Create a test metadata file
    metadata_file = create_test_metadata(args.scan_id)
    
    # Test updating the metadata
    test_update_metadata(args.scan_id, args.section, args.content, metadata_file)

if __name__ == '__main__':
    main()
