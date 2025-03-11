"""
Configuration management for the API Security Scanner.

This module handles loading and validating scanner configurations from YAML/JSON files.
"""

import json
import os
from typing import Dict, Any, List, Optional

import yaml
import jsonschema

from core.logger import get_logger

# Get logger
logger = get_logger("config")

# Configuration schema for validation
CONFIG_SCHEMA = {
    "type": "object",
    "required": ["target", "scanners"],
    "properties": {
        "target": {
            "type": "object",
            "required": ["base_url"],
            "properties": {
                "base_url": {"type": "string", "format": "uri"},
                "auth": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["none", "basic", "bearer", "api_key"]},
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                        "token": {"type": "string"},
                        "header_name": {"type": "string"},
                        "header_value": {"type": "string"}
                    },
                    "required": ["type"]
                },
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                },
                "timeout": {"type": "number", "minimum": 0},
                "verify_ssl": {"type": "boolean"},
                "openapi": {
                    "type": "object",
                    "properties": {
                        "spec_path": {"type": "string"},
                        "endpoints": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "method": {"type": "string"},
                                    "operation_id": {"type": "string"},
                                    "parameters": {"type": "array"}
                                }
                            }
                        },
                        "server_urls": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "openapi_source": {"type": "string"},
                        "url_source": {"type": "string"}
                    }
                }
            }
        },
        "scanners": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "enabled": {"type": "boolean"},
                    "concurrent": {"type": "boolean"},
                    "config": {"type": "object"}
                }
            }
        },
        "logging": {
            "type": "object",
            "properties": {
                "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARN", "ERROR", "FATAL"]},
                "format": {"type": "string", "enum": ["text", "json"]},
                "output": {"type": "string"},
                "max_size": {"type": "integer", "minimum": 1},
                "backup_count": {"type": "integer", "minimum": 0}
            }
        },
        "output": {
            "type": "object",
            "properties": {
                "save_results": {"type": "boolean"},
                "directory": {"type": "string"},
                "format": {"type": "string", "enum": ["json", "yaml", "text"]}
            }
        },
        "execution": {
            "type": "object",
            "properties": {
                "max_concurrent": {"type": "integer", "minimum": 1},
                "request_delay": {"type": "number", "minimum": 0},
                "max_retries": {"type": "integer", "minimum": 0},
                "retry_delay": {"type": "number", "minimum": 0}
            }
        },
        "environment": {"type": "string"}
    }
}


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from a YAML or JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dict containing the configuration
        
    Raises:
        FileNotFoundError: If the configuration file does not exist
        ValueError: If the configuration file format is not supported
    """
    if not os.path.exists(config_path):
        logger.error(f"Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    # Determine file format based on extension
    file_ext = os.path.splitext(config_path)[1].lower()
    
    try:
        with open(config_path, "r") as f:
            if file_ext in [".yaml", ".yml"]:
                config = yaml.safe_load(f)
            elif file_ext == ".json":
                config = json.load(f)
            else:
                logger.error(f"Unsupported configuration file format: {file_ext}")
                raise ValueError(f"Unsupported configuration file format: {file_ext}")
    except Exception as e:
        logger.error(f"Failed to load configuration: {str(e)}")
        raise
    
    # Apply environment-specific overrides if specified
    environment = config.get("environment")
    if environment:
        env_config_path = f"{os.path.splitext(config_path)[0]}.{environment}{file_ext}"
        if os.path.exists(env_config_path):
            logger.info(f"Loading environment-specific configuration: {env_config_path}")
            try:
                with open(env_config_path, "r") as f:
                    if file_ext in [".yaml", ".yml"]:
                        env_config = yaml.safe_load(f)
                    else:
                        env_config = json.load(f)
                
                # Merge environment-specific configuration
                merge_configs(config, env_config)
            except Exception as e:
                logger.error(f"Failed to load environment-specific configuration: {str(e)}")
    
    return config


def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate configuration against the schema.
    
    Args:
        config: Configuration dictionary
        
    Raises:
        jsonschema.exceptions.ValidationError: If the configuration is invalid
    """
    try:
        jsonschema.validate(instance=config, schema=CONFIG_SCHEMA)
    except jsonschema.exceptions.ValidationError as e:
        logger.error(f"Configuration validation failed: {str(e)}")
        raise


def merge_configs(base_config: Dict[str, Any], override_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two configuration dictionaries.
    
    Args:
        base_config: Base configuration
        override_config: Configuration to override base values
        
    Returns:
        Merged configuration dictionary
    """
    for key, value in override_config.items():
        if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
            merge_configs(base_config[key], value)
        else:
            base_config[key] = value
    
    return base_config


def get_scanner_config(config: Dict[str, Any], scanner_name: str) -> Optional[Dict[str, Any]]:
    """
    Get configuration for a specific scanner.
    
    Args:
        config: Full configuration dictionary
        scanner_name: Name of the scanner
        
    Returns:
        Scanner configuration or None if not found
    """
    scanners = config.get("scanners", [])
    for scanner in scanners:
        if scanner.get("name") == scanner_name:
            return scanner
    
    return None


def update_config_with_openapi(config: Dict[str, Any], openapi_spec: Dict[str, Any], 
                           server_urls: List[str], endpoints: List[Dict[str, Any]]) -> None:
    """
    Update configuration with OpenAPI specification data.
    
    Args:
        config: Configuration dictionary to update
        openapi_spec: Parsed OpenAPI specification
        server_urls: List of server URLs extracted from the OpenAPI spec
        endpoints: List of endpoints extracted from the OpenAPI spec
        
    Returns:
        None, updates config in place
    """
    logger.info("Updating configuration with OpenAPI specification data")
    
    # Ensure target section exists
    if "target" not in config:
        config["target"] = {}
    
    # Add OpenAPI data to configuration
    config["target"]["openapi"] = {
        "endpoints": endpoints,
        "server_urls": server_urls,
        "openapi_source": "file",
        "spec_info": {
            "title": openapi_spec.get("info", {}).get("title", "Unknown API"),
            "version": openapi_spec.get("info", {}).get("version", "Unknown"),
            "description": openapi_spec.get("info", {}).get("description", "")
        }
    }
    
    # Update base_url if not overridden and server URLs are available
    if not config["target"].get("url_source") == "override" and server_urls:
        config["target"]["base_url"] = server_urls[0]  # Use first server URL
        config["target"]["openapi_source"] = "openapi"
        logger.info(f"Using server URL from OpenAPI spec: {server_urls[0]}")
    
    logger.info(f"Configuration updated with {len(endpoints)} endpoints from OpenAPI specification")
