#!/usr/bin/env python3
"""
Swagger to OpenAPI v3 Converter

This script converts Swagger (OpenAPI v2) files to OpenAPI v3 compliant format.
It handles the necessary transformations to ensure compatibility with tools
that require OpenAPI v3 specifications.
"""

import argparse
import json
import os
import sys
from typing import Dict, Any, List, Union, Optional

import yaml


def load_swagger_file(file_path: str) -> Dict[str, Any]:
    """
    Load a Swagger/OpenAPI specification file.
    
    Args:
        file_path: Path to the Swagger/OpenAPI specification file
        
    Returns:
        Dict containing the specification
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Specification file not found: {file_path}")
    
    file_ext = os.path.splitext(file_path)[1].lower()
    
    try:
        with open(file_path, "r") as f:
            if file_ext in [".yaml", ".yml"]:
                return yaml.safe_load(f)
            elif file_ext == ".json":
                return json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
    except Exception as e:
        print(f"Error loading specification file: {str(e)}")
        sys.exit(1)


def save_openapi_file(spec: Dict[str, Any], output_path: str) -> None:
    """
    Save the OpenAPI specification to a file.
    
    Args:
        spec: OpenAPI specification dictionary
        output_path: Path to save the specification
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        with open(output_path, "w") as f:
            json.dump(spec, f, indent=2)
        
        print(f"OpenAPI v3 specification saved to {output_path}")
    except Exception as e:
        print(f"Error saving specification file: {str(e)}")
        sys.exit(1)


def convert_parameter_type(param_type: str) -> Dict[str, Any]:
    """
    Convert Swagger parameter type to OpenAPI v3 schema.
    
    Args:
        param_type: Swagger parameter type
        
    Returns:
        OpenAPI v3 schema object
    """
    type_mapping = {
        "string": {"type": "string"},
        "number": {"type": "number"},
        "integer": {"type": "integer"},
        "boolean": {"type": "boolean"},
        "array": {"type": "array", "items": {}},
        "file": {"type": "string", "format": "binary"},
        "object": {"type": "object"}
    }
    
    return type_mapping.get(param_type, {"type": "string"})


def convert_parameters(parameters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert Swagger parameters to OpenAPI v3 parameters.
    
    Args:
        parameters: List of Swagger parameters
        
    Returns:
        List of OpenAPI v3 parameters
    """
    if not parameters:
        return []
    
    result = []
    for param in parameters:
        # Skip parameters that are already references
        if "$ref" in param:
            result.append(param)
            continue
        
        new_param = {
            "name": param.get("name", ""),
            "in": param.get("in", ""),
            "description": param.get("description", ""),
            "required": param.get("required", False)
        }
        
        # Handle deprecated flag
        if "deprecated" in param:
            new_param["deprecated"] = param["deprecated"]
        
        # Handle style (formerly collectionFormat)
        if "collectionFormat" in param:
            collection_format = param["collectionFormat"]
            if collection_format == "csv":
                new_param["style"] = "form"
                new_param["explode"] = False
            elif collection_format == "ssv":
                new_param["style"] = "spaceDelimited"
            elif collection_format == "pipes":
                new_param["style"] = "pipeDelimited"
            elif collection_format == "multi":
                new_param["style"] = "form"
                new_param["explode"] = True
        
        # Convert body parameters to requestBody in the parent operation
        if param.get("in") == "body":
            continue
        
        # Convert formData parameters to requestBody in the parent operation
        if param.get("in") == "formData":
            continue
        
        # Convert parameter type to schema
        schema = {}
        if "type" in param:
            schema = convert_parameter_type(param["type"])
            
            # Handle array items
            if param["type"] == "array" and "items" in param:
                schema["items"] = param["items"]
            
            # Handle enum
            if "enum" in param:
                schema["enum"] = param["enum"]
            
            # Handle format
            if "format" in param:
                schema["format"] = param["format"]
            
            # Handle default
            if "default" in param:
                schema["default"] = param["default"]
            
            # Handle minimum/maximum
            for prop in ["minimum", "maximum", "minLength", "maxLength", "pattern"]:
                if prop in param:
                    schema[prop] = param[prop]
        
        # Use existing schema if provided
        elif "schema" in param:
            schema = param["schema"]
        
        new_param["schema"] = schema
        
        # Handle allowEmptyValue
        if "allowEmptyValue" in param and param["in"] in ["query", "formData"]:
            new_param["allowEmptyValue"] = param["allowEmptyValue"]
        
        result.append(new_param)
    
    return result


def convert_responses(responses: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Swagger responses to OpenAPI v3 responses.
    
    Args:
        responses: Swagger responses object
        
    Returns:
        OpenAPI v3 responses object
    """
    if not responses:
        return {}
    
    result = {}
    for status_code, response in responses.items():
        # Skip responses that are already references
        if "$ref" in response:
            result[status_code] = response
            continue
        
        new_response = {
            "description": response.get("description", "")
        }
        
        # Convert schema to content
        if "schema" in response:
            new_response["content"] = {
                "application/json": {
                    "schema": response["schema"]
                }
            }
        
        # Handle headers
        if "headers" in response:
            new_response["headers"] = {}
            for header_name, header in response["headers"].items():
                new_header = {
                    "description": header.get("description", ""),
                    "schema": {}
                }
                
                if "type" in header:
                    new_header["schema"] = convert_parameter_type(header["type"])
                    
                    # Handle additional properties
                    for prop in ["format", "enum", "default"]:
                        if prop in header:
                            new_header["schema"][prop] = header[prop]
                
                new_response["headers"][header_name] = new_header
        
        # Handle examples
        if "examples" in response:
            if "content" not in new_response:
                new_response["content"] = {}
            
            for media_type, example in response["examples"].items():
                if media_type not in new_response["content"]:
                    new_response["content"][media_type] = {}
                
                new_response["content"][media_type]["example"] = example
        
        result[status_code] = new_response
    
    return result


def extract_request_body(parameters: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Extract request body from Swagger parameters.
    
    Args:
        parameters: List of Swagger parameters
        
    Returns:
        OpenAPI v3 requestBody object or None if no body parameters
    """
    body_param = None
    form_data_params = []
    
    # Find body and formData parameters
    for param in parameters:
        if param.get("in") == "body":
            body_param = param
        elif param.get("in") == "formData":
            form_data_params.append(param)
    
    # Handle body parameter
    if body_param:
        return {
            "description": body_param.get("description", ""),
            "required": body_param.get("required", False),
            "content": {
                "application/json": {
                    "schema": body_param.get("schema", {})
                }
            }
        }
    
    # Handle formData parameters
    if form_data_params:
        properties = {}
        required_props = []
        
        for param in form_data_params:
            prop_schema = {}
            if "type" in param:
                prop_schema = convert_parameter_type(param["type"])
                
                # Handle array items
                if param["type"] == "array" and "items" in param:
                    prop_schema["items"] = param["items"]
                
                # Handle additional properties
                for prop in ["format", "enum", "default", "minimum", "maximum"]:
                    if prop in param:
                        prop_schema[prop] = param[prop]
            
            properties[param["name"]] = prop_schema
            
            if param.get("required", False):
                required_props.append(param["name"])
        
        schema = {
            "type": "object",
            "properties": properties
        }
        
        if required_props:
            schema["required"] = required_props
        
        # Determine content type
        content_type = "application/x-www-form-urlencoded"
        for param in form_data_params:
            if param.get("type") == "file":
                content_type = "multipart/form-data"
                break
        
        return {
            "required": bool(required_props),
            "content": {
                content_type: {
                    "schema": schema
                }
            }
        }
    
    return None


def convert_security_definitions(security_definitions: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Swagger securityDefinitions to OpenAPI v3 securitySchemes.
    
    Args:
        security_definitions: Swagger securityDefinitions object
        
    Returns:
        OpenAPI v3 securitySchemes object
    """
    if not security_definitions:
        return {}
    
    result = {}
    for name, definition in security_definitions.items():
        security_type = definition.get("type", "")
        
        if security_type == "basic":
            result[name] = {
                "type": "http",
                "scheme": "basic"
            }
        elif security_type == "apiKey":
            result[name] = {
                "type": "apiKey",
                "name": definition.get("name", ""),
                "in": definition.get("in", "")
            }
        elif security_type == "oauth2":
            flow_type = definition.get("flow", "")
            new_def = {
                "type": "oauth2",
                "flows": {}
            }
            
            if flow_type == "implicit":
                new_def["flows"]["implicit"] = {
                    "authorizationUrl": definition.get("authorizationUrl", ""),
                    "scopes": definition.get("scopes", {})
                }
            elif flow_type == "password":
                new_def["flows"]["password"] = {
                    "tokenUrl": definition.get("tokenUrl", ""),
                    "scopes": definition.get("scopes", {})
                }
            elif flow_type == "application":
                new_def["flows"]["clientCredentials"] = {
                    "tokenUrl": definition.get("tokenUrl", ""),
                    "scopes": definition.get("scopes", {})
                }
            elif flow_type == "accessCode":
                new_def["flows"]["authorizationCode"] = {
                    "authorizationUrl": definition.get("authorizationUrl", ""),
                    "tokenUrl": definition.get("tokenUrl", ""),
                    "scopes": definition.get("scopes", {})
                }
            
            result[name] = new_def
        
        # Copy description
        if "description" in definition:
            result[name]["description"] = definition["description"]
    
    return result


def convert_swagger_to_openapi(swagger_spec: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert Swagger (OpenAPI v2) specification to OpenAPI v3.
    
    Args:
        swagger_spec: Swagger specification dictionary
        
    Returns:
        OpenAPI v3 specification dictionary
    """
    # Create base OpenAPI v3 structure
    openapi_spec = {
        "openapi": "3.0.0",
        "info": swagger_spec.get("info", {}),
        "paths": {}
    }
    
    # Convert host, basePath, and schemes to servers
    servers = []
    host = swagger_spec.get("host", "")
    base_path = swagger_spec.get("basePath", "")
    schemes = swagger_spec.get("schemes", ["https"])
    
    if host:
        for scheme in schemes:
            url = f"{scheme}://{host}"
            if base_path:
                url += base_path
            servers.append({"url": url})
    
    if servers:
        openapi_spec["servers"] = servers
    
    # Copy global consumes and produces
    global_consumes = swagger_spec.get("consumes", [])
    global_produces = swagger_spec.get("produces", [])
    
    # Convert paths
    for path, path_item in swagger_spec.get("paths", {}).items():
        openapi_spec["paths"][path] = {}
        
        # Copy path-level parameters
        path_parameters = []
        if "parameters" in path_item:
            path_parameters = convert_parameters(path_item["parameters"])
            if path_parameters:
                openapi_spec["paths"][path]["parameters"] = path_parameters
        
        # Process operations
        for method, operation in path_item.items():
            if method == "parameters":
                continue
            
            new_operation = {
                "responses": {}
            }
            
            # Copy operation properties
            for prop in ["tags", "summary", "description", "operationId", "deprecated"]:
                if prop in operation:
                    new_operation[prop] = operation[prop]
            
            # Convert parameters
            if "parameters" in operation:
                all_parameters = operation["parameters"]
                
                # Add path parameters to operation parameters
                if "parameters" in path_item:
                    # Check for duplicates
                    path_param_names = {(p.get("name"), p.get("in")) for p in path_item["parameters"] if "name" in p and "in" in p}
                    all_parameters = [p for p in all_parameters if ("name" not in p or "in" not in p or (p["name"], p["in"]) not in path_param_names)] + path_item["parameters"]
                
                # Extract request body
                request_body = extract_request_body(all_parameters)
                if request_body:
                    new_operation["requestBody"] = request_body
                
                # Convert remaining parameters
                converted_params = convert_parameters(all_parameters)
                if converted_params:
                    new_operation["parameters"] = converted_params
            
            # Convert responses
            if "responses" in operation:
                new_operation["responses"] = convert_responses(operation["responses"])
            
            # Handle consumes and produces
            operation_consumes = operation.get("consumes", global_consumes)
            operation_produces = operation.get("produces", global_produces)
            
            # Apply content types to requestBody if not already set
            if "requestBody" in new_operation and operation_consumes:
                if "content" not in new_operation["requestBody"]:
                    new_operation["requestBody"]["content"] = {}
                
                # Only add content types that aren't already defined
                existing_content_types = set(new_operation["requestBody"]["content"].keys())
                for content_type in operation_consumes:
                    if content_type not in existing_content_types:
                        new_operation["requestBody"]["content"][content_type] = {
                            "schema": {}
                        }
            
            # Apply content types to responses if not already set
            if operation_produces:
                for status_code, response in new_operation["responses"].items():
                    if "$ref" in response:
                        continue
                    
                    if "content" not in response:
                        response["content"] = {}
                    
                    # Only add content types that aren't already defined
                    existing_content_types = set(response["content"].keys())
                    for content_type in operation_produces:
                        if content_type not in existing_content_types:
                            response["content"][content_type] = {}
            
            # Handle security
            if "security" in operation:
                new_operation["security"] = operation["security"]
            
            openapi_spec["paths"][path][method] = new_operation
    
    # Convert definitions to components/schemas
    if "definitions" in swagger_spec:
        if "components" not in openapi_spec:
            openapi_spec["components"] = {}
        
        openapi_spec["components"]["schemas"] = swagger_spec["definitions"]
    
    # Convert parameters to components/parameters
    if "parameters" in swagger_spec:
        if "components" not in openapi_spec:
            openapi_spec["components"] = {}
        
        openapi_spec["components"]["parameters"] = {}
        for name, param in swagger_spec["parameters"].items():
            converted_params = convert_parameters([param])
            if converted_params:
                openapi_spec["components"]["parameters"][name] = converted_params[0]
    
    # Convert responses to components/responses
    if "responses" in swagger_spec:
        if "components" not in openapi_spec:
            openapi_spec["components"] = {}
        
        openapi_spec["components"]["responses"] = {}
        for name, response in swagger_spec["responses"].items():
            converted_responses = convert_responses({"default": response})
            if "default" in converted_responses:
                openapi_spec["components"]["responses"][name] = converted_responses["default"]
    
    # Convert securityDefinitions to components/securitySchemes
    if "securityDefinitions" in swagger_spec:
        if "components" not in openapi_spec:
            openapi_spec["components"] = {}
        
        openapi_spec["components"]["securitySchemes"] = convert_security_definitions(swagger_spec["securityDefinitions"])
    
    # Copy security
    if "security" in swagger_spec:
        openapi_spec["security"] = swagger_spec["security"]
    
    # Copy tags
    if "tags" in swagger_spec:
        openapi_spec["tags"] = swagger_spec["tags"]
    
    # Copy externalDocs
    if "externalDocs" in swagger_spec:
        openapi_spec["externalDocs"] = swagger_spec["externalDocs"]
    
    return openapi_spec


def main():
    """Main function to parse arguments and convert Swagger to OpenAPI v3."""
    parser = argparse.ArgumentParser(
        description="Convert Swagger (OpenAPI v2) files to OpenAPI v3 compliant format"
    )
    parser.add_argument(
        "--swagger", 
        required=True, 
        help="Path to the Swagger/OpenAPI specification file"
    )
    parser.add_argument(
        "--output", 
        required=True, 
        help="Path to save the converted OpenAPI v3 specification"
    )
    
    args = parser.parse_args()
    
    try:
        # Load the Swagger specification
        swagger_spec = load_swagger_file(args.swagger)
        
        # Check if it's already OpenAPI v3
        if "openapi" in swagger_spec and swagger_spec["openapi"].startswith("3."):
            print(f"The specification is already OpenAPI v3 compliant (version {swagger_spec['openapi']})")
            save_openapi_file(swagger_spec, args.output)
            return
        
        # Convert to OpenAPI v3
        openapi_spec = convert_swagger_to_openapi(swagger_spec)
        
        # Save the converted specification
        save_openapi_file(openapi_spec, args.output)
        
    except Exception as e:
        print(f"Error converting specification: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
