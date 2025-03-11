"""
Excessive Data Exposure Scanner Module.

This module tests for Excessive Data Exposure vulnerabilities, where APIs return
more data than necessary, potentially exposing sensitive information that should
be filtered or restricted before being sent to clients.
"""

import json
import time
import random
import string
import requests
from typing import Dict, List, Any, Optional, Tuple

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting excessive data exposure vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Initialize endpoints with default values
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        self.login_endpoint = config.get("login_endpoint", "/users/v1/login")
        self.user_endpoint = config.get("user_endpoint", "/users/{username}")
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using debug endpoint: {self.debug_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using user endpoint: {self.user_endpoint}")
        
        # Field names in requests/responses
        self.username_field = config.get("username_field", "username")
        self.password_field = config.get("password_field", "password")
        self.email_field = config.get("email_field", "email")
        self.token_field = config.get("token_field", "auth_token")
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.test_username = config.get("test_username", f"test_user_{timestamp}_{random_suffix}")
        self.test_email = config.get("test_email", f"{self.test_username}@example.com")
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        
        # Sensitive data patterns to look for
        self.sensitive_fields = config.get("sensitive_fields", [
            "password", "passwd", "secret", "token", "api_key", "apikey", "key", 
            "private", "ssn", "social_security", "credit_card", "cc_number", 
            "cvv", "cvc", "pin", "hash", "salt", "internal", "hidden", "private"
        ])
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201, 204])
    
    def _extract_endpoints_from_openapi(self, target: Dict[str, Any]) -> None:
        """
        Extract API endpoints from OpenAPI specification.
        
        Args:
            target: Target configuration containing OpenAPI data
        """
        # Check if OpenAPI data is available in the target configuration
        if "openapi" not in target or not isinstance(target["openapi"], dict):
            self.logger.info("No OpenAPI specification data found in target configuration")
            return
        
        openapi_data = target["openapi"]
        
        # Extract endpoints from the OpenAPI specification
        if "endpoints" not in openapi_data or not isinstance(openapi_data["endpoints"], list):
            self.logger.info("No endpoints found in OpenAPI specification data")
            return
        
        endpoints = openapi_data["endpoints"]
        self.logger.info(f"Found {len(endpoints)} endpoints in OpenAPI specification")
        
        # Use the utility function to find endpoints by purpose
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        self.debug_endpoint = find_endpoint_by_purpose(endpoints, "debug", self.debug_endpoint)
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        
        # Look for user endpoints
        for endpoint in endpoints:
            path = endpoint.get("path", "").lower()
            method = endpoint.get("method", "").upper()
            operation_id = endpoint.get("operation_id", "").lower()
            
            # Find user endpoints
            if ("user" in path or "users" in path) and "{" in path and "}" in path:
                self.user_endpoint = endpoint.get("path")
                self.logger.info(f"Found user endpoint: {self.user_endpoint}")
                break
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting excessive data exposure scanner")
        
        # Test for debug endpoint exposure
        self._test_debug_endpoint()
        
        # Test for sensitive data in responses
        self._test_sensitive_data_in_responses()
        
        # Return findings
        return self.findings
    
    def _test_debug_endpoint(self) -> None:
        """
        Test for the presence of a debug endpoint that exposes excessive data.
        """
        self.logger.info(f"Testing debug endpoint: {self.debug_endpoint}")
        
        try:
            # Make a request to the debug endpoint
            response = self._make_request(
                method="GET",
                endpoint=self.debug_endpoint,
                timeout=10,
                capture_for_evidence=True
            )
            
            # Check if the response contains user data
            if response.status_code in self.success_status_codes:
                try:
                    response_data = response.json()
                    self.logger.debug(f"Debug endpoint response type: {type(response_data)}")
                    
                    # Check if the response contains a list of users or user data
                    if isinstance(response_data, list) and len(response_data) > 0:
                        self.logger.info(f"Debug endpoint returned a list of {len(response_data)} items")
                        self._analyze_debug_response(response_data, response)
                    elif isinstance(response_data, dict):
                        if "users" in response_data and isinstance(response_data["users"], list):
                            self.logger.info(f"Debug endpoint returned a 'users' array with {len(response_data['users'])} items")
                            self._analyze_debug_response(response_data["users"], response)
                        else:
                            # Try to find any array in the response that might contain user data
                            for key, value in response_data.items():
                                if isinstance(value, list) and len(value) > 0:
                                    self.logger.info(f"Debug endpoint returned an array '{key}' with {len(value)} items")
                                    self._analyze_debug_response(value, response)
                                    break
                            else:
                                self.logger.info("Debug endpoint returned a single object, treating as a single user")
                                self._analyze_debug_response([response_data], response)
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.warning(f"Failed to parse response as JSON: {str(e)}")
            else:
                self.logger.info(f"Debug endpoint returned non-success status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error testing debug endpoint: {str(e)}")
    
    def _analyze_debug_response(self, user_data: List[Dict[str, Any]], response: requests.Response) -> None:
        """
        Analyze the response from a debug endpoint for excessive data exposure.
        
        Args:
            user_data: List of user data dictionaries
            response: The HTTP response
        """
        sensitive_fields_found = []
        total_users = len(user_data)
        
        # Extract request and response details
        request_data = getattr(response, '_request_details', {})
        response_data = getattr(response, '_response_details', {})
        
        # Log the structure of the user data for debugging
        self.logger.debug(f"Debug endpoint response structure: {type(user_data)}, length: {total_users}")
        if total_users > 0:
            self.logger.debug(f"First user data keys: {list(user_data[0].keys())}")
        
        # Check for sensitive fields in the response
        for user in user_data:
            if not isinstance(user, dict):
                self.logger.warning(f"Expected user data to be a dictionary, got {type(user)}")
                continue
                
            for field in user.keys():
                field_lower = field.lower()
                for sensitive_field in self.sensitive_fields:
                    if sensitive_field in field_lower and field not in sensitive_fields_found:
                        sensitive_fields_found.append(field)
                        self.logger.info(f"Found sensitive field in debug response: {field}")
        
        if sensitive_fields_found:
            # Found sensitive data in the debug endpoint response
            self.add_finding(
                vulnerability="Excessive Data Exposure - Debug Endpoint",
                details=f"The API exposes a debug endpoint that returns sensitive user data including {', '.join(sensitive_fields_found)}. This endpoint returned data for {total_users} users, which could lead to unauthorized access to sensitive information.",
                severity="CRITICAL",
                endpoint=self.debug_endpoint,
                evidence={
                    "sensitive_fields": sensitive_fields_found,
                    "total_users_exposed": total_users,
                    "status_code": response.status_code
                },
                remediation="Remove or properly secure debug endpoints in production environments. Implement proper authentication and authorization controls. Consider implementing a separate API for debugging that requires elevated privileges.",
                request_data=request_data,
                response_data=response_data
            )
            self.logger.info(f"Found excessive data exposure in debug endpoint with {len(sensitive_fields_found)} sensitive fields")
    
    def _test_sensitive_data_in_responses(self) -> None:
        """
        Test for sensitive data exposure in regular API responses.
        """
        self.logger.info("Testing for sensitive data in API responses")
        
        # First, register a test user
        auth_token = self._register_and_login()
        if not auth_token:
            self.logger.warning("Failed to register and login test user, skipping sensitive data test")
            return
        
        # Test user endpoint for sensitive data
        self._test_user_endpoint_for_sensitive_data(auth_token)
    
    def _register_and_login(self) -> Optional[str]:
        """
        Register a test user and login to get an authentication token.
        
        Returns:
            Authentication token or None if registration/login failed
        """
        self.logger.info(f"Registering test user: {self.test_username}")
        
        # Register a new user
        register_payload = {
            self.username_field: self.test_username,
            self.password_field: self.test_password,
            self.email_field: self.test_email
        }
        
        try:
            register_response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=register_payload,
                timeout=10
            )
            
            if register_response.status_code not in self.success_status_codes:
                self.logger.warning(f"Failed to register test user: {register_response.status_code}")
                return None
            
            # Login with the registered user
            login_payload = {
                self.username_field: self.test_username,
                self.password_field: self.test_password
            }
            
            login_response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=login_payload,
                timeout=10
            )
            
            if login_response.status_code not in self.success_status_codes:
                self.logger.warning(f"Failed to login with test user: {login_response.status_code}")
                return None
            
            # Extract authentication token from response
            try:
                response_data = login_response.json()
                auth_token = response_data.get(self.token_field)
                if not auth_token:
                    self.logger.warning(f"Authentication token not found in login response: {response_data}")
                    return None
                
                return auth_token
            except (json.JSONDecodeError, ValueError):
                self.logger.warning("Failed to parse login response as JSON")
                return None
        except Exception as e:
            self.logger.error(f"Error during registration/login: {str(e)}")
            return None
    
    def _test_user_endpoint_for_sensitive_data(self, auth_token: str) -> None:
        """
        Test the user endpoint for sensitive data exposure.
        
        Args:
            auth_token: Authentication token for the test user
        """
        self.logger.info(f"Testing user endpoint for sensitive data: {self.user_endpoint}")
        
        # Replace username placeholder in the endpoint
        endpoint = self.user_endpoint.replace("{username}", self.test_username)
        
        # Set authorization header
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        try:
            # Make a request to the user endpoint
            response = self._make_request(
                method="GET",
                endpoint=endpoint,
                headers=headers,
                timeout=10,
                capture_for_evidence=True
            )
            
            # Check if the response contains sensitive data
            if response.status_code in self.success_status_codes:
                try:
                    response_data = response.json()
                    
                    # Extract request and response details
                    request_data = getattr(response, '_request_details', {})
                    response_data_for_evidence = getattr(response, '_response_details', {})
                    
                    # Check for sensitive fields in the response
                    sensitive_fields_found = []
                    
                    if isinstance(response_data, dict):
                        for field in response_data.keys():
                            field_lower = field.lower()
                            for sensitive_field in self.sensitive_fields:
                                if sensitive_field in field_lower and field not in sensitive_fields_found:
                                    sensitive_fields_found.append(field)
                    
                    if sensitive_fields_found:
                        # Found sensitive data in the user endpoint response
                        self.add_finding(
                            vulnerability="Excessive Data Exposure - User Data",
                            details=f"The API exposes sensitive user data including {', '.join(sensitive_fields_found)} in the user endpoint response. This could lead to unauthorized access to sensitive information if proper data filtering is not implemented.",
                            severity="HIGH",
                            endpoint=endpoint,
                            evidence={
                                "sensitive_fields": sensitive_fields_found,
                                "status_code": response.status_code
                            },
                            remediation="Implement proper data filtering to ensure that sensitive fields are not returned in API responses. Consider implementing a response transformation layer that removes sensitive data before sending responses to clients.",
                            request_data=request_data,
                            response_data=response_data_for_evidence
                        )
                        self.logger.info(f"Found excessive data exposure in user endpoint with {len(sensitive_fields_found)} sensitive fields")
                except (json.JSONDecodeError, ValueError):
                    self.logger.warning("Failed to parse response as JSON")
        except Exception as e:
            self.logger.error(f"Error testing user endpoint: {str(e)}")
