"""
OpenAPI specification handling for the API Security Scanner.

This module provides utilities for parsing, validating, and extracting data from
OpenAPI/Swagger specification files.
"""

import json
import os
import re
import urllib.parse
from typing import Dict, List, Any, Optional, Tuple

import yaml
import jsonschema

from core.logger import get_logger
from core.exceptions import ScannerConfigError

# Get logger
logger = get_logger("openapi")

# OpenAPI 3.0.x schema (simplified version for validation)
OPENAPI_3_SCHEMA = {
    "type": "object",
    "required": ["openapi", "info", "paths"],
    "properties": {
        "openapi": {"type": "string", "pattern": "^3\\.0\\.\\d+$"},
        "info": {
            "type": "object",
            "required": ["title", "version"],
            "properties": {
                "title": {"type": "string"},
                "version": {"type": "string"}
            }
        },
        "servers": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"}
                }
            }
        },
        "paths": {"type": "object"}
    }
}

# Swagger 2.0 schema (simplified version for validation)
SWAGGER_2_SCHEMA = {
    "type": "object",
    "required": ["swagger", "info", "paths"],
    "properties": {
        "swagger": {"type": "string", "enum": ["2.0"]},
        "info": {
            "type": "object",
            "required": ["title", "version"],
            "properties": {
                "title": {"type": "string"},
                "version": {"type": "string"}
            }
        },
        "host": {"type": "string"},
        "basePath": {"type": "string"},
        "schemes": {
            "type": "array",
            "items": {"type": "string", "enum": ["http", "https", "ws", "wss"]}
        },
        "paths": {"type": "object"}
    }
}


def load_openapi_spec(spec_path: str) -> Dict[str, Any]:
    """
    Load and validate an OpenAPI/Swagger specification file.
    
    Args:
        spec_path: Path to the specification file (JSON or YAML)
        
    Returns:
        Dict containing the parsed specification
        
    Raises:
        FileNotFoundError: If the specification file does not exist
        ValueError: If the specification file format is not supported
        jsonschema.exceptions.ValidationError: If the specification is invalid
    """
    if not os.path.exists(spec_path):
        logger.error(f"OpenAPI specification file not found: {spec_path}")
        raise FileNotFoundError(f"OpenAPI specification file not found: {spec_path}")
    
    # Determine file format based on extension
    file_ext = os.path.splitext(spec_path)[1].lower()
    
    try:
        with open(spec_path, "r") as f:
            if file_ext in [".yaml", ".yml"]:
                spec = yaml.safe_load(f)
            elif file_ext == ".json":
                spec = json.load(f)
            else:
                logger.error(f"Unsupported OpenAPI specification format: {file_ext}")
                raise ValueError(f"Unsupported OpenAPI specification format: {file_ext}")
    except Exception as e:
        logger.error(f"Failed to load OpenAPI specification: {str(e)}")
        raise
    
    # Validate the specification
    validate_openapi_spec(spec)
    
    return spec


def validate_openapi_spec(spec: Dict[str, Any]) -> None:
    """
    Validate an OpenAPI/Swagger specification against the appropriate schema.
    
    Args:
        spec: The parsed specification dictionary
        
    Raises:
        jsonschema.exceptions.ValidationError: If the specification is invalid
        ValueError: If the specification version is not supported
    """
    # Determine the OpenAPI/Swagger version
    if "openapi" in spec and spec["openapi"].startswith("3.0."):
        # OpenAPI 3.0.x
        schema = OPENAPI_3_SCHEMA
        version = f"OpenAPI {spec['openapi']}"
    elif "swagger" in spec and spec["swagger"] == "2.0":
        # Swagger 2.0
        schema = SWAGGER_2_SCHEMA
        version = "Swagger 2.0"
    else:
        logger.error("Unsupported OpenAPI/Swagger version")
        raise ValueError("Unsupported OpenAPI/Swagger version. Only OpenAPI 3.0.x and Swagger 2.0 are supported.")
    
    try:
        jsonschema.validate(instance=spec, schema=schema)
        logger.info(f"Successfully validated {version} specification")
    except jsonschema.exceptions.ValidationError as e:
        logger.error(f"OpenAPI specification validation failed: {str(e)}")
        raise


def extract_server_urls(spec: Dict[str, Any]) -> List[str]:
    """
    Extract server URLs from an OpenAPI/Swagger specification.
    
    Args:
        spec: The parsed specification dictionary
        
    Returns:
        List of server URLs
    """
    server_urls = []
    
    # Handle OpenAPI 3.0.x format
    if "openapi" in spec and "servers" in spec and isinstance(spec["servers"], list):
        for server in spec["servers"]:
            if "url" in server:
                url = server["url"]
                # Handle relative URLs
                if not url.startswith(("http://", "https://")):
                    url = f"https://{url}" if not url.startswith("/") else f"https://api.example.com{url}"
                server_urls.append(url)
    
    # Handle Swagger 2.0 format
    elif "swagger" in spec and "host" in spec:
        scheme = "https"
        if "schemes" in spec and isinstance(spec["schemes"], list) and spec["schemes"]:
            scheme = spec["schemes"][0]  # Use first scheme
        
        base_path = spec.get("basePath", "")
        host = spec["host"]
        server_urls.append(f"{scheme}://{host}{base_path}")
    
    logger.info(f"Extracted {len(server_urls)} server URLs from OpenAPI specification")
    return server_urls


def extract_endpoints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract endpoints from an OpenAPI/Swagger specification.
    
    Args:
        spec: The parsed specification dictionary
        
    Returns:
        List of endpoint dictionaries with path, method, and other metadata
    """
    endpoints = []
    
    if "paths" not in spec or not isinstance(spec["paths"], dict):
        logger.warning("No paths found in OpenAPI specification")
        return endpoints
    
    for path, path_item in spec["paths"].items():
        # Skip non-object path items
        if not isinstance(path_item, dict):
            continue
        
        for method, operation in path_item.items():
            # Skip non-HTTP methods and non-object operations
            if method.lower() not in ["get", "post", "put", "delete", "patch", "head", "options"] or not isinstance(operation, dict):
                continue
            
            # Handle OpenAPI 3.0.x format
            if "openapi" in spec:
                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "parameters": operation.get("parameters", []),
                    "request_body": operation.get("requestBody", {}),
                    "responses": operation.get("responses", {}),
                    "security": operation.get("security", [])
                }
            
            # Handle Swagger 2.0 format
            else:
                endpoint = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation.get("operationId", ""),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "parameters": operation.get("parameters", []),
                    "responses": operation.get("responses", {}),
                    "security": operation.get("security", [])
                }
                
                # Convert body parameter to request_body for consistency
                body_params = [p for p in endpoint["parameters"] if p.get("in") == "body"]
                if body_params:
                    endpoint["request_body"] = {
                        "content": {
                            "application/json": {
                                "schema": body_params[0].get("schema", {})
                            }
                        }
                    }
            
            endpoints.append(endpoint)
    
    logger.info(f"Extracted {len(endpoints)} endpoints from OpenAPI specification")
    return endpoints


def find_endpoint_by_purpose(endpoints: List[Dict[str, Any]], purpose: str, default_path: str = None) -> str:
    """
    Find an endpoint path that matches a specific purpose.
    
    Args:
        endpoints: List of endpoint dictionaries from extract_endpoints
        purpose: Purpose of the endpoint (e.g., 'register', 'login', 'debug')
        default_path: Default path to return if no matching endpoint is found
        
    Returns:
        Endpoint path that best matches the purpose, or default_path if not found
    """
    # Define mapping of purposes to path patterns and operation IDs
    purpose_mapping = {
        "register": {
            "path_patterns": ["/register", "/signup", "/users/register", "/users/v1/register", "/api/users/register"],
            "operation_ids": ["register", "registerUser", "createUser", "signup", "userRegistration"],
            "methods": ["POST"]
        },
        "login": {
            "path_patterns": ["/login", "/signin", "/users/login", "/users/v1/login", "/api/users/login", "/auth/login"],
            "operation_ids": ["login", "loginUser", "signin", "userLogin", "authenticate"],
            "methods": ["POST"]
        },
        "debug": {
            "path_patterns": ["/_debug", "/debug", "/users/_debug", "/users/v1/_debug", "/api/users/debug"],
            "operation_ids": ["debug", "getDebugInfo", "getUsersDebug"],
            "methods": ["GET"]
        },
        "create_user": {
            "path_patterns": ["/users", "/api/users", "/users/v1"],
            "operation_ids": ["createUser", "addUser", "postUser"],
            "methods": ["POST"]
        },
        "update_user": {
            "path_patterns": ["/users/{id}", "/api/users/{id}", "/users/v1/{id}", "/users/{username}", "/users/v1/{username}"],
            "operation_ids": ["updateUser", "putUser", "patchUser"],
            "methods": ["PUT", "PATCH"]
        },
        "get_user": {
            "path_patterns": ["/users/{id}", "/api/users/{id}", "/users/v1/{id}", "/users/{username}", "/users/v1/{username}"],
            "operation_ids": ["getUser", "getUserById", "getUserByUsername"],
            "methods": ["GET"]
        },
        "password_change": {
            "path_patterns": ["/users/{id}/password", "/users/v1/{id}/password", "/users/{username}/password", "/users/v1/{username}/password", "/password", "/change-password"],
            "operation_ids": ["changePassword", "updatePassword", "resetPassword"],
            "methods": ["PUT", "PATCH", "POST"]
        }
    }
    
    # Check if the purpose is defined in our mapping
    if purpose not in purpose_mapping:
        logger.warning(f"Unknown endpoint purpose: {purpose}, using default path: {default_path}")
        return default_path
    
    purpose_info = purpose_mapping[purpose]
    path_patterns = purpose_info["path_patterns"]
    operation_ids = purpose_info["operation_ids"]
    methods = purpose_info["methods"]
    
    # First, try to match by operation ID (most specific)
    for endpoint in endpoints:
        if endpoint["method"] in methods and any(op_id.lower() in endpoint["operation_id"].lower() for op_id in operation_ids):
            logger.info(f"Found {purpose} endpoint by operation ID: {endpoint['path']}")
            return endpoint["path"]
    
    # Next, try to match by path pattern
    for endpoint in endpoints:
        if endpoint["method"] in methods:
            for pattern in path_patterns:
                if pattern.lower() in endpoint["path"].lower():
                    logger.info(f"Found {purpose} endpoint by path pattern: {endpoint['path']}")
                    return endpoint["path"]
    
    # If no match found, return the default path
    logger.warning(f"No matching endpoint found for purpose: {purpose}, using default path: {default_path}")
    return default_path


def get_endpoint_parameters(endpoint: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Organize endpoint parameters by type (path, query, header, cookie).
    
    Args:
        endpoint: Endpoint dictionary from extract_endpoints
        
    Returns:
        Dictionary with parameters organized by type
    """
    params = {
        "path": [],
        "query": [],
        "header": [],
        "cookie": []
    }
    
    for param in endpoint.get("parameters", []):
        param_in = param.get("in")
        if param_in in params:
            params[param_in].append(param)
    
    return params


def get_request_body_schema(endpoint: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract request body schema from an endpoint.
    
    Args:
        endpoint: Endpoint dictionary from extract_endpoints
        
    Returns:
        Request body schema or None if not present
    """
    request_body = endpoint.get("request_body", {})
    
    # OpenAPI 3.0.x format
    if "content" in request_body:
        for content_type, content in request_body.get("content", {}).items():
            if "schema" in content:
                return content["schema"]
    
    # Swagger 2.0 format (already converted to OpenAPI 3.0.x format in extract_endpoints)
    return None


def resolve_path_template(path_template: str, path_params: Dict[str, Any]) -> str:
    """
    Resolve a path template with parameter values.
    
    Args:
        path_template: Path template with parameters (e.g., /users/{id})
        path_params: Dictionary of parameter values
        
    Returns:
        Resolved path
    """
    resolved_path = path_template
    
    # Replace path parameters with values
    for name, value in path_params.items():
        pattern = f"{{{name}}}"
        resolved_path = resolved_path.replace(pattern, str(value))
    
    # Check if any parameters are still unresolved
    if "{" in resolved_path and "}" in resolved_path:
        logger.warning(f"Unresolved parameters in path: {resolved_path}")
    
    return resolved_path


def build_request_url(base_url: str, path: str, query_params: Dict[str, Any] = None) -> str:
    """
    Build a full request URL from base URL, path, and query parameters.
    
    Args:
        base_url: Base URL (e.g., https://api.example.com)
        path: API path (e.g., /users)
        query_params: Dictionary of query parameters
        
    Returns:
        Full request URL
    """
    # Normalize base URL
    if base_url.endswith("/"):
        base_url = base_url[:-1]
    
    # Normalize path
    if not path.startswith("/"):
        path = f"/{path}"
    
    # Build URL
    url = f"{base_url}{path}"
    
    # Add query parameters
    if query_params:
        query_string = "&".join([f"{k}={urllib.parse.quote(str(v))}" for k, v in query_params.items()])
        url = f"{url}?{query_string}"
    
    return url
