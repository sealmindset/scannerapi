#!/usr/bin/env python3
"""
Configuration Generator for API Security Scanner

This script generates a configuration file for the API Security Scanner based on
an OpenAPI/Swagger specification file. It extracts the server URL and endpoints
from the specification and creates a configuration file that can be used with
the scanner.py script.
"""

import argparse
import os
import sys
import yaml
import json
from typing import Dict, Any, List

def load_openapi_spec(spec_path: str) -> Dict[str, Any]:
    """
    Load an OpenAPI specification from a file.
    
    Args:
        spec_path: Path to the OpenAPI specification file
        
    Returns:
        Dict containing the OpenAPI specification
    """
    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"OpenAPI specification file not found: {spec_path}")
    
    file_ext = os.path.splitext(spec_path)[1].lower()
    
    try:
        with open(spec_path, "r") as f:
            if file_ext in [".yaml", ".yml"]:
                return yaml.safe_load(f)
            elif file_ext == ".json":
                return json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
    except Exception as e:
        print(f"Error loading OpenAPI specification: {str(e)}")
        sys.exit(1)

def extract_server_url(openapi_spec: Dict[str, Any]) -> str:
    """
    Extract the server URL from an OpenAPI specification.
    
    Args:
        openapi_spec: OpenAPI specification dictionary
        
    Returns:
        Server URL as a string
    """
    if "servers" in openapi_spec and openapi_spec["servers"]:
        return openapi_spec["servers"][0]["url"]
    return "http://localhost:8080"  # Default fallback

def extract_auth_endpoints(openapi_spec: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract authentication-related endpoints from an OpenAPI specification.
    
    Args:
        openapi_spec: OpenAPI specification dictionary
        
    Returns:
        Dict containing authentication endpoints
    """
    auth_endpoints = {
        "login_endpoint": None,
        "refresh_token_endpoint": None,
        "user_info_endpoint": None,
        "register_endpoint": None
    }
    
    if "paths" not in openapi_spec:
        return auth_endpoints
    
    # Keywords to look for in paths and descriptions
    auth_keywords = {
        "login_endpoint": ["login", "signin", "sign-in", "auth/sign-in", "authenticate"],
        "refresh_token_endpoint": ["refresh", "token/refresh", "refresh-token", "refresh-tokens"],
        "user_info_endpoint": ["me", "userinfo", "user-info", "profile", "users/me"],
        "register_endpoint": ["register", "signup", "sign-up", "auth/sign-up", "create-account"]
    }
    
    # Search for auth endpoints in the paths
    for path, path_item in openapi_spec["paths"].items():
        for endpoint_type, keywords in auth_keywords.items():
            if auth_endpoints[endpoint_type]:
                continue  # Skip if already found
                
            # Check path for keywords
            path_lower = path.lower()
            if any(keyword in path_lower for keyword in keywords):
                auth_endpoints[endpoint_type] = path
                continue
                
            # Check summary and description for keywords
            for method in ["post", "get", "put"]:
                if method not in path_item:
                    continue
                    
                operation = path_item[method]
                summary = operation.get("summary", "").lower()
                description = operation.get("description", "").lower()
                
                if any(keyword in summary or keyword in description for keyword in keywords):
                    auth_endpoints[endpoint_type] = path
                    break
    
    return auth_endpoints

def generate_config(openapi_spec: Dict[str, Any], spec_path: str) -> Dict[str, Any]:
    """
    Generate a configuration dictionary based on an OpenAPI specification.
    
    Args:
        openapi_spec: OpenAPI specification dictionary
        spec_path: Path to the OpenAPI specification file
        
    Returns:
        Dict containing the configuration
    """
    server_url = extract_server_url(openapi_spec)
    auth_endpoints = extract_auth_endpoints(openapi_spec)
    
    # Create base configuration
    config = {
        "target": {
            "base_url": server_url,
            "auth": {
                "type": "none"
            },
            "openapi": {
                "spec_path": spec_path,
                "extract_endpoints": True,
                "use_spec_server_url": True
            },
            "simulate_server": False,  # Default to false as requested
            "disable_fallback_endpoints": True  # Disable fallback endpoints as requested
        },
        "scanners": [
            {"name": "sql_injection", "enabled": True},
            {"name": "broken_authentication", "enabled": True},
            {"name": "broken_access_control", "enabled": True},
            {"name": "excessive_data_exposure", "enabled": True},
            {"name": "mass_assignment", "enabled": True},
            {"name": "unauthorized_password_change", "enabled": True},
            {"name": "unrestricted_account_creation", "enabled": True},
            {"name": "regex_dos", "enabled": False}
        ]
    }
    
    # Add JWT vulnerabilities scanner if authentication endpoints are found
    if any(auth_endpoints.values()):
        jwt_scanner = {
            "name": "jwt_vulnerabilities",
            "enabled": True,
            "config": {
                "simulate_vulnerabilities": False,
                "debug": True
            }
        }
        
        # Add found auth endpoints to the JWT scanner config
        for endpoint_type, endpoint in auth_endpoints.items():
            if endpoint:
                jwt_scanner["config"][endpoint_type] = endpoint
        
        # Add default field names (these can be customized later)
        jwt_scanner["config"]["username_field"] = "email"
        jwt_scanner["config"]["password_field"] = "password"
        jwt_scanner["config"]["access_token_field"] = "accessToken"
        jwt_scanner["config"]["refresh_token_field"] = "refreshToken"
        
        config["scanners"].append(jwt_scanner)
    
    return config

def main():
    """Main function to parse arguments and generate the configuration file."""
    parser = argparse.ArgumentParser(description="Generate a configuration file for the API Security Scanner")
    parser.add_argument("--swagger", required=True, help="Path to the OpenAPI specification file")
    parser.add_argument("--output", required=True, help="Path to the output configuration file")
    
    args = parser.parse_args()
    
    try:
        # Load the OpenAPI specification
        openapi_spec = load_openapi_spec(args.swagger)
        
        # Generate the configuration
        config = generate_config(openapi_spec, args.swagger)
        
        # Write the configuration to the output file
        with open(args.output, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        print(f"Configuration file generated successfully: {args.output}")
        print(f"Server URL: {config['target']['base_url']}")
        print(f"Number of scanners enabled: {sum(1 for scanner in config['scanners'] if scanner.get('enabled', False))}")
        
        # Print auth endpoints if found
        jwt_scanner = next((s for s in config["scanners"] if s["name"] == "jwt_vulnerabilities"), None)
        if jwt_scanner:
            print("\nAuthentication endpoints found:")
            for endpoint_type in ["login_endpoint", "refresh_token_endpoint", "user_info_endpoint", "register_endpoint"]:
                if endpoint_type in jwt_scanner["config"]:
                    print(f"  {endpoint_type}: {jwt_scanner['config'][endpoint_type]}")
        
    except Exception as e:
        print(f"Error generating configuration: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
