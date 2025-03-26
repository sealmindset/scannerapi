#!/usr/bin/env python3
"""
Prompt Manager Utility

This module provides functions for loading, saving, and managing LLM prompts
used throughout the application. It includes support for template versioning,
caching, and error handling.
"""

import json
import os
import logging
import datetime
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("prompt_manager")

# Default prompts file path
DEFAULT_PROMPTS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "configs",
    "llm_prompts.json"
)

# Default version if not specified in the prompts file
DEFAULT_VERSION = "1.0.0"

# Cache for loaded prompts to avoid repeated file reads
_prompts_cache = {}
_prompts_cache_timestamp = {}
_file_last_modified = {}

def load_prompts(file_path: Optional[str] = None, use_cache: bool = True) -> Dict[str, Any]:
    """
    Load prompts from the JSON file with caching support.
    
    Args:
        file_path: Path to the prompts JSON file. If None, uses the default path.
        use_cache: Whether to use cached prompts if available.
        
    Returns:
        Dictionary containing the prompts with version information
    """
    if file_path is None:
        file_path = DEFAULT_PROMPTS_PATH
    
    # Check if we can use cached prompts
    if use_cache and file_path in _prompts_cache:
        # Check if file has been modified since last cache
        try:
            last_modified = os.path.getmtime(file_path)
            if file_path in _file_last_modified and last_modified <= _file_last_modified[file_path]:
                logger.debug(f"Using cached prompts for {file_path}")
                return _prompts_cache[file_path]
        except OSError:
            # If we can't check modification time, proceed with loading
            pass
    
    try:
        with open(file_path, 'r') as f:
            prompts = json.load(f)
        
        # Validate and ensure version information
        if 'version' not in prompts:
            logger.warning(f"No version information found in {file_path}, adding default version {DEFAULT_VERSION}")
            prompts['version'] = DEFAULT_VERSION
        
        # Update cache
        _prompts_cache[file_path] = prompts
        _prompts_cache_timestamp[file_path] = time.time()
        try:
            _file_last_modified[file_path] = os.path.getmtime(file_path)
        except OSError:
            pass
        
        logger.info(f"Successfully loaded prompts from {file_path} (version {prompts.get('version', 'unknown')})")
        return prompts
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error in prompts file {file_path}: {str(e)}")
        return {'version': DEFAULT_VERSION, 'error': f"JSON parsing error: {str(e)}"}
    except FileNotFoundError:
        logger.error(f"Prompts file not found: {file_path}")
        return {'version': DEFAULT_VERSION, 'error': f"File not found: {file_path}"}
    except Exception as e:
        logger.error(f"Error loading prompts from {file_path}: {str(e)}")
        return {'version': DEFAULT_VERSION, 'error': f"Error loading prompts: {str(e)}"}

def save_prompts(prompts: Dict[str, Any], file_path: Optional[str] = None, update_version: bool = True) -> bool:
    """
    Save prompts to the JSON file with version updating.
    
    Args:
        prompts: Dictionary containing the prompts
        file_path: Path to save the prompts JSON file. If None, uses the default path.
        update_version: Whether to update the version information
        
    Returns:
        True if successful, False otherwise
    """
    if file_path is None:
        file_path = DEFAULT_PROMPTS_PATH
    
    # Create a backup before saving
    try:
        if os.path.exists(file_path):
            create_backup(file_path)
    except Exception as e:
        logger.warning(f"Failed to create backup before saving: {str(e)}")
    
    # Update version if requested
    if update_version:
        current_version = prompts.get('version', DEFAULT_VERSION)
        try:
            # Simple version increment (assuming semantic versioning)
            version_parts = current_version.split('.')
            if len(version_parts) >= 3:
                # Increment patch version
                version_parts[2] = str(int(version_parts[2]) + 1)
                prompts['version'] = '.'.join(version_parts)
                prompts['last_updated'] = datetime.datetime.now().isoformat()
        except Exception as e:
            logger.warning(f"Failed to update version: {str(e)}")
            prompts['version'] = DEFAULT_VERSION
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w') as f:
            json.dump(prompts, f, indent=2)
        
        # Invalidate cache for this file
        if file_path in _prompts_cache:
            del _prompts_cache[file_path]
        if file_path in _prompts_cache_timestamp:
            del _prompts_cache_timestamp[file_path]
        if file_path in _file_last_modified:
            del _file_last_modified[file_path]
        
        logger.info(f"Successfully saved prompts to {file_path} (version {prompts.get('version', 'unknown')})")
        return True
    except Exception as e:
        logger.error(f"Error saving prompts to {file_path}: {str(e)}")
        return False

def get_prompt_template(prompt_key: str, file_path: Optional[str] = None, with_metadata: bool = False) -> Union[Optional[str], Dict[str, Any]]:
    """
    Get a specific prompt template by key with enhanced error handling.
    
    Args:
        prompt_key: Key of the prompt to retrieve (e.g., 'description_template')
        file_path: Path to the prompts JSON file. If None, uses the default path.
        with_metadata: If True, returns the entire template object including metadata
        
    Returns:
        The prompt template string, or None if not found
        If with_metadata is True, returns a dictionary with template and metadata
    """
    prompts = load_prompts(file_path)
    
    # Skip version key when searching for templates
    if prompt_key == 'version' or prompt_key == 'last_updated':
        logger.warning(f"'{prompt_key}' is a reserved metadata key, not a template")
        return None
    
    # Check if prompts loaded successfully
    if 'error' in prompts:
        logger.error(f"Cannot retrieve template due to error in prompts file: {prompts['error']}")
        return None
    
    # Handle nested keys (e.g., 'section_templates.description')
    if '.' in prompt_key:
        parts = prompt_key.split('.')
        current = prompts
        path_so_far = ""
        
        for i, part in enumerate(parts):
            path_so_far = f"{path_so_far}.{part}" if path_so_far else part
            
            if part in current:
                current = current[part]
            else:
                logger.warning(f"Prompt key part '{part}' not found in path '{path_so_far}'")
                return None
        
        if isinstance(current, dict):
            if 'template' in current:
                if with_metadata:
                    # Return the entire template object
                    return current
                return current['template']
            else:
                logger.warning(f"No 'template' field found in '{prompt_key}'")
                return current if with_metadata else None
        return current
    
    # Handle direct keys
    if prompt_key in prompts:
        if isinstance(prompts[prompt_key], dict):
            if 'template' in prompts[prompt_key]:
                if with_metadata:
                    return prompts[prompt_key]
                return prompts[prompt_key]['template']
            else:
                logger.warning(f"No 'template' field found in '{prompt_key}'")
                return prompts[prompt_key] if with_metadata else None
        return prompts[prompt_key]
    
    logger.warning(f"Prompt key '{prompt_key}' not found")
    return None

def update_prompt_template(prompt_key: str, template: str, file_path: Optional[str] = None, 
                        metadata: Optional[Dict[str, Any]] = None) -> bool:
    """
    Update a specific prompt template with version tracking.
    
    Args:
        prompt_key: Key of the prompt to update (e.g., 'description_template')
        template: New template string
        file_path: Path to the prompts JSON file. If None, uses the default path.
        metadata: Optional metadata to update (e.g., name, description, version)
        
    Returns:
        True if successful, False otherwise
    """
    # Skip reserved metadata keys
    if prompt_key in ['version', 'last_updated']:
        logger.error(f"Cannot update reserved metadata key '{prompt_key}'")
        return False
    
    prompts = load_prompts(file_path, use_cache=False)
    
    # Check if prompts loaded successfully
    if 'error' in prompts:
        logger.error(f"Cannot update template due to error in prompts file: {prompts['error']}")
        return False
    
    # Generate a template hash for cache invalidation
    template_hash = hashlib.md5(template.encode()).hexdigest()[:8]
    timestamp = datetime.datetime.now().isoformat()
    
    # Handle nested keys (e.g., 'section_templates.description')
    if '.' in prompt_key:
        parts = prompt_key.split('.')
        current = prompts
        path_so_far = ""
        
        for i, part in enumerate(parts[:-1]):
            path_so_far = f"{path_so_far}.{part}" if path_so_far else part
            
            if part not in current:
                logger.warning(f"Prompt key part '{part}' not found in path '{path_so_far}'")
                return False
            current = current[part]
        
        last_part = parts[-1]
        if last_part in current:
            if isinstance(current[last_part], dict) and 'template' in current[last_part]:
                # Update template and metadata
                current[last_part]['template'] = template
                current[last_part]['last_updated'] = timestamp
                current[last_part]['template_hash'] = template_hash
                
                # Update additional metadata if provided
                if metadata:
                    for key, value in metadata.items():
                        if key not in ['template', 'template_hash', 'last_updated']:
                            current[last_part][key] = value
            else:
                # Convert to a template object with metadata
                current[last_part] = {
                    'template': template,
                    'last_updated': timestamp,
                    'template_hash': template_hash
                }
                # Add metadata if provided
                if metadata:
                    for key, value in metadata.items():
                        if key not in ['template', 'template_hash', 'last_updated']:
                            current[last_part][key] = value
        else:
            logger.warning(f"Prompt key part '{last_part}' not found in {prompt_key}")
            return False
    else:
        # Handle direct keys
        if prompt_key in prompts:
            if isinstance(prompts[prompt_key], dict) and 'template' in prompts[prompt_key]:
                # Update template and metadata
                prompts[prompt_key]['template'] = template
                prompts[prompt_key]['last_updated'] = timestamp
                prompts[prompt_key]['template_hash'] = template_hash
                
                # Update additional metadata if provided
                if metadata:
                    for key, value in metadata.items():
                        if key not in ['template', 'template_hash', 'last_updated']:
                            prompts[prompt_key][key] = value
            else:
                # Convert to a template object with metadata
                prompts[prompt_key] = {
                    'template': template,
                    'last_updated': timestamp,
                    'template_hash': template_hash
                }
                # Add metadata if provided
                if metadata:
                    for key, value in metadata.items():
                        if key not in ['template', 'template_hash', 'last_updated']:
                            prompts[prompt_key][key] = value
        else:
            # Create a new template entry
            logger.info(f"Creating new prompt template '{prompt_key}'")
            prompts[prompt_key] = {
                'template': template,
                'name': metadata.get('name', prompt_key) if metadata else prompt_key,
                'description': metadata.get('description', '') if metadata else '',
                'last_updated': timestamp,
                'template_hash': template_hash
            }
            # Add additional metadata if provided
            if metadata:
                for key, value in metadata.items():
                    if key not in ['template', 'name', 'description', 'template_hash', 'last_updated']:
                        prompts[prompt_key][key] = value
    
    return save_prompts(prompts, file_path)

def list_available_prompts(file_path: Optional[str] = None, include_version: bool = True) -> List[Dict[str, Any]]:
    """
    List all available prompts with their metadata and version information.
    
    Args:
        file_path: Path to the prompts JSON file. If None, uses the default path.
        include_version: Whether to include version information in the result.
        
    Returns:
        List of dictionaries containing prompt information
    """
    prompts = load_prompts(file_path)
    result = []
    
    # Check if prompts loaded successfully
    if 'error' in prompts:
        logger.error(f"Cannot list prompts due to error in prompts file: {prompts['error']}")
        return [{'id': 'error', 'name': 'Error', 'description': prompts['error']}]
    
    # Add file version information if requested
    if include_version and 'version' in prompts:
        result.append({
            'id': 'file_info',
            'name': 'Prompts File Information',
            'description': f"File version: {prompts['version']}",
            'version': prompts['version'],
            'last_updated': prompts.get('last_updated', 'unknown')
        })
    
    # Process top-level templates
    for key, value in prompts.items():
        # Skip metadata keys
        if key in ['version', 'last_updated', 'error']:
            continue
            
        if isinstance(value, dict) and 'template' in value:
            template_info = {
                'id': key,
                'name': value.get('name', key),
                'description': value.get('description', ''),
                'template_preview': value['template'][:100] + '...' if len(value['template']) > 100 else value['template']
            }
            
            # Add version information if available
            if include_version:
                if 'version' in value:
                    template_info['version'] = value['version']
                if 'last_updated' in value:
                    template_info['last_updated'] = value['last_updated']
                if 'template_hash' in value:
                    template_info['template_hash'] = value['template_hash']
                    
            result.append(template_info)
        elif key == 'section_templates':
            # Process section templates
            for section_key, section_value in value.items():
                if isinstance(section_value, dict) and 'template' in section_value:
                    template_info = {
                        'id': f'section_templates.{section_key}',
                        'name': section_value.get('name', f'Section: {section_key}'),
                        'description': section_value.get('description', ''),
                        'template_preview': section_value['template'][:100] + '...' if len(section_value['template']) > 100 else section_value['template']
                    }
                    
                    # Add version information if available
                    if include_version:
                        if 'version' in section_value:
                            template_info['version'] = section_value['version']
                        if 'last_updated' in section_value:
                            template_info['last_updated'] = section_value['last_updated']
                        if 'template_hash' in section_value:
                            template_info['template_hash'] = section_value['template_hash']
                            
                    result.append(template_info)
    
    return result

def create_backup(file_path: Optional[str] = None) -> str:
    """
    Create a backup of the current prompts file.
    
    Args:
        file_path: Path to the prompts JSON file. If None, uses the default path.
        
    Returns:
        Path to the backup file
    """
    if file_path is None:
        file_path = DEFAULT_PROMPTS_PATH
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    
    # Create a dedicated backups directory
    configs_dir = os.path.dirname(file_path)
    backups_dir = os.path.join(configs_dir, "backups")
    os.makedirs(backups_dir, exist_ok=True)
    
    # Use the backups directory for the backup file
    backup_filename = f"llm_prompts.json.{timestamp}.backup"
    backup_path = os.path.join(backups_dir, backup_filename)
    
    try:
        if not os.path.exists(file_path):
            logger.warning(f"Cannot create backup: file {file_path} does not exist")
            return ""
        
        import shutil
        shutil.copy2(file_path, backup_path)
        logger.info(f"Created backup at {backup_path}")
        
        # Also create a backup at the original location for backward compatibility
        legacy_backup_path = f"{file_path}.{timestamp}.backup"
        shutil.copy2(file_path, legacy_backup_path)
        logger.info(f"Created legacy backup at {legacy_backup_path}")
        
        return backup_path
    except Exception as e:
        logger.error(f"Error creating backup: {str(e)}")
        return ""

def restore_from_backup(backup_path: str, file_path: Optional[str] = None) -> bool:
    """
    Restore prompts from a backup file.
    
    Args:
        backup_path: Path to the backup file
        file_path: Path to the target prompts JSON file. If None, uses the default path.
        
    Returns:
        True if successful, False otherwise
    """
    if file_path is None:
        file_path = DEFAULT_PROMPTS_PATH
    
    import shutil
    
    try:
        if not os.path.exists(backup_path):
            logger.error(f"Backup file not found: {backup_path}")
            return False
            
        # Validate backup file is valid JSON
        try:
            with open(backup_path, 'r') as f:
                json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Backup file is not valid JSON: {backup_path}")
            return False
            
        # Create a backup of the current file before restoring
        if os.path.exists(file_path):
            create_backup(file_path)
            
        shutil.copy2(backup_path, file_path)
        
        # Invalidate cache for this file
        if file_path in _prompts_cache:
            del _prompts_cache[file_path]
        if file_path in _prompts_cache_timestamp:
            del _prompts_cache_timestamp[file_path]
        if file_path in _file_last_modified:
            del _file_last_modified[file_path]
            
        logger.info(f"Restored from backup {backup_path} to {file_path}")
        return True
    except Exception as e:
        logger.error(f"Error restoring from backup: {str(e)}")
        return False

def get_template_hash(prompt_key: str, file_path: Optional[str] = None) -> Optional[str]:
    """
    Get the hash of a specific prompt template for cache invalidation.
    
    Args:
        prompt_key: Key of the prompt to retrieve the hash for
        file_path: Path to the prompts JSON file. If None, uses the default path.
        
    Returns:
        The template hash string, or None if not found
    """
    template_data = get_prompt_template(prompt_key, file_path, with_metadata=True)
    if isinstance(template_data, dict) and 'template_hash' in template_data:
        return template_data['template_hash']
    elif isinstance(template_data, dict) and 'template' in template_data:
        # Generate hash on the fly if not stored
        template = template_data['template']
        return hashlib.md5(template.encode()).hexdigest()[:8]
    elif isinstance(template_data, str):
        # For simple string templates
        return hashlib.md5(template_data.encode()).hexdigest()[:8]
    return None

def clear_cache(file_path: Optional[str] = None) -> None:
    """
    Clear the prompts cache for a specific file or all files.
    
    Args:
        file_path: Path to the prompts JSON file to clear cache for. If None, clears all caches.
    """
    global _prompts_cache, _prompts_cache_timestamp, _file_last_modified
    
    if file_path is None:
        # Clear all caches
        _prompts_cache = {}
        _prompts_cache_timestamp = {}
        _file_last_modified = {}
        logger.info("Cleared all prompt caches")
    elif file_path in _prompts_cache:
        # Clear cache for specific file
        del _prompts_cache[file_path]
        if file_path in _prompts_cache_timestamp:
            del _prompts_cache_timestamp[file_path]
        if file_path in _file_last_modified:
            del _file_last_modified[file_path]
        logger.info(f"Cleared cache for {file_path}")
    else:
        logger.debug(f"No cache to clear for {file_path}")

if __name__ == "__main__":
    # Simple CLI for testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage LLM prompts")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # List prompts
    list_parser = subparsers.add_parser("list", help="List available prompts")
    list_parser.add_argument("--with-version", action="store_true", help="Include version information")
    
    # Get prompt
    get_parser = subparsers.add_parser("get", help="Get a prompt template")
    get_parser.add_argument("key", help="Prompt key to retrieve")
    get_parser.add_argument("--with-metadata", action="store_true", help="Include metadata in output")
    
    # Update prompt
    update_parser = subparsers.add_parser("update", help="Update a prompt template")
    update_parser.add_argument("key", help="Prompt key to update")
    update_parser.add_argument("template", help="New template content")
    update_parser.add_argument("--name", help="Name for the template")
    update_parser.add_argument("--description", help="Description for the template")
    
    # Backup prompts
    backup_parser = subparsers.add_parser("backup", help="Create a backup of prompts")
    
    # Restore prompts
    restore_parser = subparsers.add_parser("restore", help="Restore prompts from backup")
    restore_parser.add_argument("backup_path", help="Path to backup file")
    
    # Clear cache
    cache_parser = subparsers.add_parser("clear-cache", help="Clear prompts cache")
    
    # Get version
    version_parser = subparsers.add_parser("version", help="Get prompts file version")
    
    args = parser.parse_args()
    
    if args.command == "list":
        prompts = list_available_prompts(include_version=args.with_version)
        print(f"Found {len(prompts)} prompts:")
        for prompt in prompts:
            print(f"ID: {prompt['id']}")
            print(f"Name: {prompt['name']}")
            print(f"Description: {prompt['description']}")
            if 'version' in prompt:
                print(f"Version: {prompt['version']}")
            if 'last_updated' in prompt:
                print(f"Last Updated: {prompt['last_updated']}")
            if 'template_preview' in prompt:
                print(f"Preview: {prompt['template_preview']}")
            print("-" * 50)
    
    elif args.command == "get":
        template = get_prompt_template(args.key, with_metadata=args.with_metadata)
        if template:
            print(f"Template for '{args.key}':")
            if args.with_metadata and isinstance(template, dict):
                for key, value in template.items():
                    if key == 'template':
                        print(f"\nTemplate Content:\n{value}")
                    else:
                        print(f"{key}: {value}")
            else:
                print(template)
        else:
            print(f"No template found for '{args.key}'")
    
    elif args.command == "update":
        metadata = {}
        if args.name:
            metadata['name'] = args.name
        if args.description:
            metadata['description'] = args.description
            
        success = update_prompt_template(args.key, args.template, metadata=metadata if metadata else None)
        if success:
            print(f"Successfully updated template for '{args.key}'")
        else:
            print(f"Failed to update template for '{args.key}'")
    
    elif args.command == "backup":
        backup_path = create_backup()
        if backup_path:
            print(f"Created backup at {backup_path}")
        else:
            print("Failed to create backup")
    
    elif args.command == "restore":
        success = restore_from_backup(args.backup_path)
        if success:
            print(f"Successfully restored from backup {args.backup_path}")
        else:
            print(f"Failed to restore from backup {args.backup_path}")
    
    elif args.command == "clear-cache":
        clear_cache()
        print("Cache cleared successfully")
    
    elif args.command == "version":
        prompts = load_prompts(use_cache=False)
        if 'version' in prompts:
            print(f"Prompts file version: {prompts['version']}")
            if 'last_updated' in prompts:
                print(f"Last updated: {prompts['last_updated']}")
        else:
            print("No version information found in prompts file")
    
    else:
        parser.print_help()
