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
    Find an endpoint path that matches a specific purpose using intelligent matching.
    
    This function uses a combination of path patterns, operation IDs, descriptions,
    tags, and summaries to identify endpoints that match a specific purpose.
    It applies a scoring system to rank potential matches and is designed to work
    with various API naming conventions and structures.
    
    Args:
        endpoints: List of endpoint dictionaries from extract_endpoints
        purpose: Purpose of the endpoint (e.g., 'register', 'login', 'debug')
        default_path: Default path to return if no matching endpoint is found
        
    Returns:
        Endpoint path that best matches the purpose, or default_path if not found
    """
    # Define mapping of purposes to patterns, keywords, and related concepts
    purpose_mapping = {
        "register": {
            "path_patterns": ["/register", "/signup", "/sign-up", "/users/register", "/users/v1/register", "/api/users/register", "/auth/register", "/auth/sign-up", "/auth/signup", "/account/create", "/account/new", "/account/register", "/account/signup", "/api/v1/auth/sign-up", "/api/v1/mobile/auth/sign-up", "/api/v1/users/register", "/api/v1/accounts/create"],
            "path_segments": ["register", "signup", "sign-up", "create", "new", "onboarding"],
            "operation_ids": ["register", "registerUser", "createUser", "signup", "signUp", "userRegistration", "createAccount", "newUser", "addUser", "createProfile", "registerAccount", "signUpUser"],
            "methods": ["POST"],
            "tags": ["user", "users", "auth", "authentication", "account", "accounts", "registration", "onboarding", "mobile"],
            "description_keywords": ["register", "signup", "sign up", "sign-up", "create account", "new user", "new account", "registration", "onboarding", "join", "enroll", "create profile"],
            "related_purposes": ["create_user"]
        },
        "login": {
            "path_patterns": ["/login", "/signin", "/sign-in", "/users/login", "/users/v1/login", "/api/users/login", "/auth/login", "/auth/signin", "/auth/sign-in", "/account/login", "/account/signin", "/api/v1/auth/sign-in", "/api/v1/mobile/auth/sign-in", "/api/v1/users/login", "/api/v1/accounts/login"],
            "path_segments": ["login", "signin", "sign-in", "authenticate", "auth"],
            "operation_ids": ["login", "loginUser", "signin", "signIn", "userLogin", "authenticate", "auth", "getToken", "getAccessToken", "authenticateUser", "signInUser"],
            "methods": ["POST"],
            "tags": ["user", "users", "auth", "authentication", "account", "accounts", "login", "mobile"],
            "description_keywords": ["login", "log in", "signin", "sign in", "sign-in", "authenticate", "authentication", "access token", "session", "credentials", "user login", "account login"],
            "related_purposes": ["authenticate"]
        },
        "refresh_token": {
            "path_patterns": ["/refresh", "/token/refresh", "/auth/refresh", "/refresh-token", "/auth/refresh-token", "/token/refresh-token", "/refresh-tokens", "/auth/refresh-tokens", "/api/v1/auth/refresh-tokens", "/api/v1/mobile/auth/refresh-tokens", "/api/v1/token/refresh"],
            "path_segments": ["refresh", "refresh-token", "refresh-tokens", "token", "tokens"],
            "operation_ids": ["refreshToken", "refreshTokens", "tokenRefresh", "renewToken", "renewTokens", "regenerateToken", "getNewToken", "refreshAccessToken", "refreshJwt"],
            "methods": ["POST"],
            "tags": ["auth", "authentication", "token", "refresh", "security", "mobile"],
            "description_keywords": ["refresh", "token", "renew", "regenerate", "access token", "new token", "jwt", "refresh token", "token refresh"],
            "related_purposes": ["token_refresh"]
        },
        "user_info": {
            "path_patterns": ["/me", "/users/me", "/user/me", "/account/me", "/profile", "/my-profile", "/user-info", "/account-info", "/user/profile", "/users/profile", "/api/v1/users/me", "/api/v1/mobile/users/me", "/api/v1/profile"],
            "path_segments": ["me", "profile", "user-info", "account-info", "my-profile"],
            "operation_ids": ["getMe", "getUserInfo", "getMyProfile", "getMyAccount", "getCurrentUser", "getProfile", "getMyInfo", "getUserProfile", "fetchCurrentUser"],
            "methods": ["GET"],
            "tags": ["user", "users", "profile", "account", "me", "mobile"],
            "description_keywords": ["my profile", "my account", "user info", "account info", "profile", "current user", "logged in user", "authenticated user", "user profile", "user details"],
            "related_purposes": ["get_user"]
        },
        "debug": {
            "path_patterns": ["/_debug", "/debug", "/users/_debug", "/users/v1/_debug", "/api/users/debug", "/system/debug", "/dev", "/development", "/test", "/internal", "/api/v1/debug", "/api/v1/system/debug"],
            "path_segments": ["debug", "dev", "test", "internal", "diagnostics"],
            "operation_ids": ["debug", "getDebugInfo", "getUsersDebug", "testEndpoint", "devTools", "systemCheck", "diagnostics", "validate", "systemDiagnostics"],
            "methods": ["GET", "POST"],
            "tags": ["debug", "development", "test", "internal", "system", "diagnostics", "admin"],
            "description_keywords": ["debug", "test", "development", "internal", "diagnostics", "validate", "check", "verification", "system status", "system health"],
            "related_purposes": ["test", "validate"]
        },
        "create_user": {
            "path_patterns": ["/users", "/api/users", "/users/v1", "/accounts", "/api/accounts", "/admin/users", "/admin/accounts", "/api/v1/users", "/api/v1/accounts", "/api/v1/admin/users"],
            "path_segments": ["users", "accounts", "user", "account", "admin"],
            "operation_ids": ["createUser", "addUser", "postUser", "newUser", "createAccount", "addAccount", "createProfile", "addProfile"],
            "methods": ["POST"],
            "tags": ["user", "users", "account", "accounts", "admin", "management"],
            "description_keywords": ["create user", "add user", "new user", "user creation", "account creation", "add account", "create profile", "add profile"],
            "related_purposes": ["register"]
        },
        "update_user": {
            "path_patterns": ["/users/{id}", "/api/users/{id}", "/users/v1/{id}", "/users/{username}", "/users/v1/{username}", "/accounts/{id}", "/users/me", "/accounts/me", "/profile", "/user/profile", "/api/v1/users/{id}", "/api/v1/users/me", "/api/v1/mobile/users/me", "/api/v1/profile"],
            "path_segments": ["users", "accounts", "profile", "me", "user"],
            "operation_ids": ["updateUser", "putUser", "patchUser", "modifyUser", "editUser", "updateAccount", "updateProfile", "editProfile", "updateMe", "updateCurrentUser"],
            "methods": ["PUT", "PATCH"],
            "tags": ["user", "users", "account", "accounts", "profile", "mobile"],
            "description_keywords": ["update user", "edit user", "modify user", "change user", "update account", "edit account", "update profile", "edit profile", "modify profile", "update me"],
            "related_purposes": ["edit_profile"]
        },
        "get_user": {
            "path_patterns": ["/users/{id}", "/api/users/{id}", "/users/v1/{id}", "/users/{username}", "/users/v1/{username}", "/accounts/{id}", "/users/me", "/accounts/me", "/profile", "/user/profile", "/api/v1/users/{id}", "/api/v1/users/me", "/api/v1/mobile/users/me", "/api/v1/profile"],
            "path_segments": ["users", "accounts", "profile", "me", "user"],
            "operation_ids": ["getUser", "getUserById", "getUserByUsername", "fetchUser", "retrieveUser", "getAccount", "getProfile", "fetchProfile", "retrieveProfile", "getMe", "getCurrentUser"],
            "methods": ["GET"],
            "tags": ["user", "users", "account", "accounts", "profile", "mobile"],
            "description_keywords": ["get user", "fetch user", "retrieve user", "user details", "user info", "user information", "get account", "account details", "profile info", "profile details", "current user"],
            "related_purposes": ["view_profile", "user_info"]
        },
        "password_change": {
            "path_patterns": ["/users/{id}/password", "/users/v1/{id}/password", "/users/{username}/password", "/users/v1/{username}/password", "/password", "/change-password", "/reset-password", "/auth/password", "/account/password", "/users/me/password", "/api/v1/users/me/password", "/api/v1/auth/password", "/api/v1/mobile/auth/password"],
            "path_segments": ["password", "change-password", "reset-password"],
            "operation_ids": ["changePassword", "updatePassword", "resetPassword", "modifyPassword", "newPassword", "passwordReset", "passwordUpdate", "setNewPassword", "updateUserPassword"],
            "methods": ["PUT", "PATCH", "POST"],
            "tags": ["user", "users", "auth", "authentication", "account", "accounts", "password", "security", "mobile"],
            "description_keywords": ["change password", "update password", "reset password", "modify password", "new password", "password reset", "password change", "password update", "set password"],
            "related_purposes": ["reset_password"]
        },
        "validate": {
            "path_patterns": ["/validate", "/check", "/verify", "/auth/check", "/auth/validate", "/auth/verify", "/token/validate", "/token/verify", "/session/validate", "/session/check", "/api/v1/auth/check", "/api/v1/mobile/auth/check", "/api/v1/token/validate"],
            "path_segments": ["validate", "check", "verify", "token", "auth"],
            "operation_ids": ["validate", "check", "verify", "validateToken", "checkToken", "verifyToken", "validateSession", "checkSession", "verifySession", "checkUser", "verifyUser", "validateAuth"],
            "methods": ["GET", "POST"],
            "tags": ["auth", "authentication", "token", "session", "validation", "verification", "security", "mobile"],
            "description_keywords": ["validate", "check", "verify", "validation", "verification", "token validation", "session check", "auth check", "authentication verification", "user check", "user verification"],
            "related_purposes": ["check_auth", "verify_token"]
        },
        "device_info": {
            "path_patterns": ["/device", "/device-info", "/users/me/device", "/users/me/device-info", "/account/device", "/profile/device", "/devices", "/api/v1/users/me/device-info", "/api/v1/mobile/users/me/device-info", "/api/v1/device"],
            "path_segments": ["device", "device-info", "devices"],
            "operation_ids": ["getDevice", "getDeviceInfo", "getUserDevice", "fetchDeviceInfo", "retrieveDeviceInfo", "getDevices", "getCurrentDevice", "getMyDevice"],
            "methods": ["GET"],
            "tags": ["device", "devices", "user", "profile", "mobile", "hardware"],
            "description_keywords": ["device", "device info", "user device", "device information", "hardware", "mobile device", "connected device", "my device", "current device"],
            "related_purposes": ["get_device"]
        },
        "health_info": {
            "path_patterns": ["/health", "/health-info", "/users/me/health", "/users/me/health-info", "/users/me/personal-health-info", "/profile/health", "/medical", "/medical-info", "/api/v1/users/me/personal-health-info", "/api/v1/mobile/users/me/personal-health-info", "/api/v1/health"],
            "path_segments": ["health", "health-info", "personal-health-info", "medical", "medical-info"],
            "operation_ids": ["getHealth", "getHealthInfo", "getUserHealth", "fetchHealthInfo", "retrieveHealthInfo", "getMedicalInfo", "getPersonalHealthInfo", "getMyHealth", "getMyMedicalInfo"],
            "methods": ["GET"],
            "tags": ["health", "medical", "user", "profile", "mobile", "personal"],
            "description_keywords": ["health", "health info", "medical", "medical info", "personal health", "health information", "medical information", "personal health information", "my health", "health data"],
            "related_purposes": ["get_health"]
        },
        "subscription": {
            "path_patterns": ["/subscription", "/subscriptions", "/users/me/subscription", "/users/me/subscriptions", "/account/subscription", "/profile/subscription", "/api/v1/users/me/subscription", "/api/v1/mobile/users/me/subscription", "/api/v1/subscription"],
            "path_segments": ["subscription", "subscriptions", "billing", "payment", "plan"],
            "operation_ids": ["getSubscription", "getSubscriptionInfo", "getUserSubscription", "fetchSubscriptionInfo", "retrieveSubscriptionInfo", "getMySubscription", "getCurrentSubscription", "getBillingInfo"],
            "methods": ["GET"],
            "tags": ["subscription", "billing", "payment", "user", "profile", "mobile", "plan"],
            "description_keywords": ["subscription", "subscription info", "user subscription", "subscription information", "billing", "payment", "plan", "my subscription", "current plan", "membership"],
            "related_purposes": ["get_subscription"]
        }
    }
    
    # Check if the purpose is defined in our mapping
    if purpose not in purpose_mapping:
        logger.warning(f"Unknown endpoint purpose: {purpose}, using default path: {default_path}")
        return default_path
    
    purpose_info = purpose_mapping[purpose]
    
    # Initialize scores for each endpoint
    endpoint_scores = {}
    
    # Analyze each endpoint and calculate a matching score
    for endpoint in endpoints:
        score = 0
        reasons = []
        
        # Method matching (high importance)
        if endpoint["method"] in purpose_info["methods"]:
            score += 20
            reasons.append("method_match")
        else:
            # If method doesn't match, this is likely not the right endpoint
            continue
        
        # Operation ID matching (highest importance)
        if endpoint.get("operation_id"):
            for op_id in purpose_info["operation_ids"]:
                if op_id.lower() in endpoint["operation_id"].lower():
                    score += 40
                    reasons.append(f"operation_id_contains_{op_id}")
                    # Exact match gets bonus points
                    if op_id.lower() == endpoint["operation_id"].lower():
                        score += 15
                        reasons.append(f"operation_id_exact_match_{op_id}")
                    break
        
        # Path pattern matching (high importance)
        for pattern in purpose_info["path_patterns"]:
            if pattern.lower() in endpoint["path"].lower():
                score += 30
                reasons.append(f"path_contains_{pattern}")
                # Exact match gets bonus points
                if pattern.lower() == endpoint["path"].lower():
                    score += 15
                    reasons.append(f"path_exact_match_{pattern}")
                break
        
        # Path segment matching (medium-high importance)
        path_segments = [segment.lower() for segment in endpoint["path"].split("/") if segment]
        for segment in purpose_info.get("path_segments", []):
            if segment.lower() in path_segments:
                score += 25
                reasons.append(f"path_segment_{segment}")
                break
        
        # API version pattern detection (e.g., /api/v1/, /v2/)
        if any(re.match(r'/api/v\d+/', part) or re.match(r'/v\d+/', part) for part in endpoint["path"].split('/') if part):
            # This is a versioned API endpoint, which is more likely to be a formal API
            score += 5
            reasons.append("versioned_api")
        
        # Mobile API pattern detection
        if "/mobile/" in endpoint["path"].lower() or "mobile" in path_segments:
            if purpose in ["device_info", "health_info", "subscription", "user_info"]:
                score += 15
                reasons.append("mobile_api_endpoint")
        
        # Tag matching (medium importance)
        if "tags" in endpoint and endpoint["tags"]:
            for tag in endpoint["tags"]:
                if tag.lower() in purpose_info["tags"]:
                    score += 15
                    reasons.append(f"tag_match_{tag}")
                    break
        
        # Description and summary keyword matching (medium importance)
        for field in ["description", "summary"]:
            if field in endpoint and endpoint[field]:
                for keyword in purpose_info["description_keywords"]:
                    if keyword.lower() in endpoint[field].lower():
                        score += 15
                        reasons.append(f"{field}_contains_{keyword}")
                        # Exact phrase match gets bonus points
                        if re.search(r'\b' + re.escape(keyword.lower()) + r'\b', endpoint[field].lower()):
                            score += 5
                            reasons.append(f"{field}_exact_phrase_{keyword}")
                        break
        
        # Check for path parameters that might indicate a specific resource (like user ID)
        if "{" in endpoint["path"] and "}" in endpoint["path"]:
            if purpose in ["get_user", "update_user", "password_change"]:
                score += 10
                reasons.append("path_parameter")
                
                # Check if the parameter name is relevant to the purpose
                param_names = re.findall(r'\{([^}]+)\}', endpoint["path"])
                relevant_params = ["id", "user", "user_id", "userId", "username", "email"]
                if any(param in relevant_params for param in param_names):
                    score += 5
                    reasons.append("relevant_path_parameter")
        
        # Special case for paths containing 'user' or 'account'
        if purpose in ["get_user", "update_user", "create_user", "register", "user_info"]:
            if "user" in endpoint["path"].lower() or "account" in endpoint["path"].lower():
                score += 10
                reasons.append("path_contains_user")
        
        # Special case for paths containing 'auth' or 'token'
        if purpose in ["login", "refresh_token", "validate"]:
            if "auth" in endpoint["path"].lower() or "token" in endpoint["path"].lower():
                score += 15
                reasons.append("path_contains_auth_or_token")
        
        # Special case for paths containing 'me' or 'my' for user-specific endpoints
        if purpose in ["user_info", "get_user", "device_info", "health_info", "subscription"]:
            if "/me" in endpoint["path"].lower() or "/my" in endpoint["path"].lower():
                score += 20
                reasons.append("path_contains_me_or_my")
        
        # Special case for paths containing 'view' or 'get'
        if purpose == "get_user" and ("view" in endpoint["path"].lower() or 
                                     ("description" in endpoint and "get" in endpoint["description"].lower())):
            score += 10
            reasons.append("path_contains_view_or_description_contains_get")
        
        # Special case for paths containing 'health' or 'medical'
        if purpose == "health_info" and ("health" in endpoint["path"].lower() or "medical" in endpoint["path"].lower()):
            score += 20
            reasons.append("path_contains_health_or_medical")
        
        # Special case for paths containing 'device'
        if purpose == "device_info" and "device" in endpoint["path"].lower():
            score += 20
            reasons.append("path_contains_device")
        
        # Special case for paths containing 'subscription'
        if purpose == "subscription" and "subscription" in endpoint["path"].lower():
            score += 20
            reasons.append("path_contains_subscription")
            
        # Special case for paths containing 'query' or 'search'
        if ("query" in endpoint["path"].lower() or "search" in endpoint["path"].lower() or 
           ("description" in endpoint and ("query" in endpoint["description"].lower() or "search" in endpoint["description"].lower()))):
            score += 10
            reasons.append("contains_query_or_search")
        
        # Special case for record-related endpoints
        if "record" in endpoint["path"].lower() or ("description" in endpoint and "record" in endpoint["description"].lower()):
            score += 5
            reasons.append("contains_record")
        
        # Store the score and reasons if above threshold
        if score > 0:
            endpoint_scores[endpoint["path"]] = {
                "score": score,
                "reasons": reasons,
                "method": endpoint["method"],
                "endpoint": endpoint
            }
    
    # Find the endpoint with the highest score
    if endpoint_scores:
        # Sort by score (descending)
        sorted_endpoints = sorted(endpoint_scores.items(), key=lambda x: x[1]["score"], reverse=True)
        best_match = sorted_endpoints[0]
        best_path = best_match[0]
        best_score = best_match[1]["score"]
        best_reasons = ",".join(best_match[1]["reasons"])
        
        # Log the match details
        logger.info(f"Found {purpose} endpoint: {best_path} (Score: {best_score}, Reasons: {best_reasons})")
        return best_path
    
    # If no match found with sufficient score, check related purposes
    if "related_purposes" in purpose_info:
        for related_purpose in purpose_info["related_purposes"]:
            if related_purpose in purpose_mapping:
                # Try to find a match using the related purpose
                related_path = find_endpoint_by_purpose(endpoints, related_purpose, None)
                if related_path:
                    logger.info(f"Found {purpose} endpoint via related purpose {related_purpose}: {related_path}")
                    return related_path
    
    # If still no match found, return the default path
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
