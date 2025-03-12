"""
Mass Assignment Scanner Module.

This module tests for mass assignment vulnerabilities, where an API allows
setting of properties that should be restricted, potentially leading to
privilege escalation or data manipulation.
"""

import json
import time
import logging
import os
import requests
from typing import Dict, List, Any, Optional, Tuple

import yaml

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting mass assignment vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Get scanner-specific configuration
        self.endpoints = config.get("endpoints", [])
        self.id_field = config.get("id_field", "id")
        
        # Initialize endpoints with default values
        self.create_endpoint = config.get("create_endpoint", "/api/users")
        self.update_endpoint = config.get("update_endpoint", "/api/users/{id}")
        self.get_endpoint = config.get("get_endpoint", "/api/users/{id}")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        
        # Set up authentication details
        auth_config = target.get("auth", {})
        self.auth_type = auth_config.get("type", "none")
        self.auth_token = None
        self.token_expiry = None
        
        # For bearer token authentication with login
        self.login_endpoint = auth_config.get("login_endpoint")
        self.auth_username = None
        self.auth_password = None
        
        # Extract credentials if available
        credentials = auth_config.get("credentials", {})
        if credentials:
            # Support both username and email fields for authentication
            self.auth_username = credentials.get("email", credentials.get("username", ""))
            self.auth_password = credentials.get("password", "")
            
            if self.auth_username and self.auth_password:
                self.logger.info(f"Using credentials for user: {self.auth_username}")
            else:
                self.logger.warn("Incomplete credentials provided for authentication")
        
        # Extract field names for authentication
        self.username_field = auth_config.get("username_field", "email")
        self.password_field = auth_config.get("password_field", "password")
        self.token_field = auth_config.get("token_field", "token")
        
        # For Snorefox API, we need to get an auth token before testing
        if self.auth_type == "bearer" and self.login_endpoint and self.auth_username and self.auth_password:
            self._get_auth_token()
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using create endpoint: {self.create_endpoint}")
        self.logger.info(f"Using update endpoint: {self.update_endpoint}")
        self.logger.info(f"Using get endpoint: {self.get_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using debug endpoint: {self.debug_endpoint}")
        
        self.sensitive_fields = config.get("sensitive_fields", [
            "role", "admin", "is_admin", "isAdmin", "is_superuser", "isSuperuser",
            "permissions", "access_level", "accessLevel", "privilege", "rank",
            "verified", "is_verified", "isVerified", "active", "is_active", "isActive"
        ])
        self.test_values = config.get("test_values", {
            "role": "admin",
            "admin": True,
            "is_admin": True,
            "isAdmin": True,
            "is_superuser": True,
            "isSuperuser": True,
            "permissions": ["admin", "superuser", "*"],
            "access_level": 9999,
            "accessLevel": 9999,
            "privilege": "admin",
            "rank": 9999,
            "verified": True,
            "is_verified": True,
            "isVerified": True,
            "active": True,
            "is_active": True,
            "isActive": True
        })
        self.create_user_payload = config.get("create_user_payload", {
            "username": f"test_mass_assignment_{int(time.time())}",
            "email": f"test_mass_assignment_{int(time.time())}@example.com",
            "password": "Test@123456"
        })
    
    def _get_auth_token(self) -> None:
        """Get authentication token by logging in to the API."""
        if not self.login_endpoint:
            self.logger.warn("No login endpoint provided for authentication")
            return
        
        self.logger.info(f"Attempting to get authentication token from {self.login_endpoint}")
        
        # Prepare login payload based on configured field names
        login_payload = {
            self.username_field: self.auth_username,
            self.password_field: self.auth_password
        }
        
        try:
            # Make login request
            login_url = self._get_full_url(self.login_endpoint)
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
            
            response = requests.post(
                url=login_url,
                json=login_payload,
                headers=headers,
                timeout=10,
                verify=False
            )
            
            if response.status_code in [200, 201, 204]:
                try:
                    data = response.json()
                    
                    # Try to extract the token from various common response formats
                    token = None
                    
                    # Direct token in response
                    if self.token_field in data:
                        token = data[self.token_field]
                    # JWT format with separate access token
                    elif "access_token" in data:
                        token = data["access_token"]
                    elif "accessToken" in data:
                        token = data["accessToken"]
                    # Nested token in data or user object
                    elif "data" in data and isinstance(data["data"], dict):
                        if self.token_field in data["data"]:
                            token = data["data"][self.token_field]
                        elif "access_token" in data["data"]:
                            token = data["data"]["access_token"]
                        elif "accessToken" in data["data"]:
                            token = data["data"]["accessToken"]
                    # Token nested in user object
                    elif "user" in data and isinstance(data["user"], dict):
                        if self.token_field in data["user"]:
                            token = data["user"][self.token_field]
                        elif "access_token" in data["user"]:
                            token = data["user"]["access_token"]
                        elif "accessToken" in data["user"]:
                            token = data["user"]["accessToken"]
                    
                    if token:
                        self.auth_token = token
                        self.logger.info("Successfully obtained authentication token")
                        
                        # Try to extract token expiry time if available
                        if "expires_in" in data:
                            expires_in = data["expires_in"]
                            if isinstance(expires_in, (int, float)):
                                self.token_expiry = time.time() + expires_in
                        elif "exp" in data:
                            self.token_expiry = data["exp"]
                        else:
                            # Default token expiry to 1 hour from now
                            self.token_expiry = time.time() + 3600
                    else:
                        self.logger.warn(f"Could not extract token from login response: {data}")
                except Exception as e:
                    self.logger.error(f"Error parsing login response: {str(e)}")
            else:
                self.logger.warn(f"Failed to get authentication token, status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error getting authentication token: {str(e)}")
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting mass assignment vulnerability scanner")
        
        # Ensure we have a valid authentication token if needed
        if self.auth_type == "bearer" and not self.auth_token and self.login_endpoint and self.auth_username and self.auth_password:
            self._get_auth_token()
        
        # If specific endpoints are provided, test those
        if self.endpoints:
            for endpoint_config in self.endpoints:
                self._test_endpoint(endpoint_config)
        else:
            # Otherwise, test the default create/update flow
            self._test_create_update_flow()
        
        # Test for role change vulnerabilities
        self._test_role_change_vulnerability()
        
        # Test for mass assignment during registration
        self._test_registration_mass_assignment()
        
        # Return findings
        return self.findings
    
    def _make_request(self, method: str, endpoint: str, json_data: Optional[Dict[str, Any]] = None) -> requests.Response:
        """Make an HTTP request to the target API with proper authentication."""
        url = self._get_full_url(endpoint)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        
        # Add authentication token if available
        if self.auth_type == "bearer" and self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
            self.logger.debug("Using bearer token authentication")
        
        # Check if token is expired and refresh if needed
        if self.auth_type == "bearer" and hasattr(self, "token_expiry") and self.token_expiry:
            if time.time() >= (self.token_expiry - 30):  # 30-second buffer
                self.logger.info("Auth token expired or about to expire, refreshing")
                self._get_auth_token()
                if self.auth_token:
                    headers["Authorization"] = f"Bearer {self.auth_token}"
        
        # Store request details for evidence
        request_details = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "json_data": json_data
        }
        
        try:
            self.logger.debug(f"Making {method} request to {url}")
            response = requests.request(
                method=method,
                url=url,
                json=json_data,
                headers=headers,
                timeout=10,
                verify=False
            )
            
            # Store response details for evidence
            response_details = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": self._safely_get_response_body(response)
            }
            
            # Handle 401 Unauthorized by refreshing token and retrying once
            if response.status_code == 401 and self.auth_type == "bearer":
                self.logger.info("Received 401 Unauthorized, refreshing token and retrying")
                self._get_auth_token()
                
                if self.auth_token:
                    # Update authorization header with new token
                    headers["Authorization"] = f"Bearer {self.auth_token}"
                    
                    # Retry the request
                    response = requests.request(
                        method=method,
                        url=url,
                        json=json_data,
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    # Update response details for evidence
                    response_details = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": self._safely_get_response_body(response)
                    }
            
            # Attach request and response details to the response object for later use
            response.request_details = request_details
            response.response_details = response_details
            
            return response
        except Exception as e:
            self.logger.error(f"Error making request to {url}: {str(e)}")
            # Return a dummy response object with an error status code
            response = requests.Response()
            response.status_code = 500
            # Attach request details even for failed requests
            response.request_details = request_details
            response.response_details = {
                "status_code": 500,
                "error": str(e)
            }
            return response
    
    def _safely_get_response_body(self, response: requests.Response) -> Any:
        """Safely extract the response body as JSON or text."""
        try:
            return response.json()
        except ValueError:
            # If not JSON, return text (truncated if too large)
            return response.text[:2000] if len(response.text) > 2000 else response.text
    
    def _get_full_url(self, endpoint: str) -> str:
        """Get the full URL for an endpoint."""
        if endpoint.startswith("http"):
            return endpoint
        
        base_url = self.target.get("base_url", "")
        if not base_url:
            return endpoint
        
        # Handle both with and without trailing/leading slashes
        base_url = base_url.rstrip("/")
        endpoint = endpoint.lstrip("/")
        
        return f"{base_url}/{endpoint}"
    
    def _test_endpoint(self, endpoint_config: Any) -> None:
        """
        Test a specific endpoint for mass assignment vulnerabilities.
        
        Args:
            endpoint_config: Endpoint configuration (can be a string or a dictionary)
        """
        # Handle both string endpoints and dictionary configurations
        if isinstance(endpoint_config, str):
            endpoint = endpoint_config
            method = "POST"  # Default method
            base_payload = {}
            id_param = self.id_field
        else:
            # It's a dictionary configuration
            endpoint = endpoint_config.get("endpoint", "")
            method = endpoint_config.get("method", "POST")
            base_payload = endpoint_config.get("payload", {})
            id_param = endpoint_config.get("id_param", self.id_field)
        
        if not endpoint:
            self.logger.warn("Skipping endpoint with missing URL")
            return
        
        self.logger.info(f"Testing endpoint {method} {endpoint} for mass assignment")
        
        # If the endpoint requires an ID parameter, try to get a valid ID
        if "{id}" in endpoint and id_param:
            # Try to get a valid ID from a list endpoint
            list_endpoint = endpoint_config.get("list_endpoint", endpoint.split("/{id}")[0])
            try:
                response = self._make_request(
                    method="GET",
                    endpoint=list_endpoint
                )
                
                if response.status_code == 200:
                    # Try to parse response and get an ID
                    try:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 0:
                            item_id = data[0].get(id_param)
                            if item_id:
                                endpoint = endpoint.replace("{id}", str(item_id))
                            else:
                                self.logger.warn(f"Could not find ID in response item: {data[0]}")
                                return
                        elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                            item_id = data["data"][0].get(id_param)
                            if item_id:
                                endpoint = endpoint.replace("{id}", str(item_id))
                            else:
                                self.logger.warn(f"Could not find ID in response item: {data['data'][0]}")
                                return
                        else:
                            self.logger.warn(f"Unexpected response format from list endpoint: {list_endpoint}")
                            return
                    except (ValueError, KeyError) as e:
                        self.logger.warn(f"Error parsing response from list endpoint: {str(e)}")
                        return
                else:
                    self.logger.warn(f"Failed to get data from list endpoint: {list_endpoint}, status code: {response.status_code}")
                    return
            except Exception as e:
                self.logger.error(f"Error accessing list endpoint: {str(e)}")
                return
        
        # Test each sensitive field
        for field in self.sensitive_fields:
            # Skip if the field is already in the base payload
            if field in base_payload:
                continue
            
            # Create payload with the sensitive field
            payload = base_payload.copy()
            payload[field] = self.test_values.get(field, True)
            
            try:
                response = self._make_request(
                    method=method,
                    endpoint=endpoint,
                    json_data=payload
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    # Try to verify if the field was actually set
                    if method in ["POST", "PUT", "PATCH"] and isinstance(endpoint_config, dict) and endpoint_config.get("verify_endpoint"):
                        verify_endpoint = endpoint_config.get("verify_endpoint")
                        if "{id}" in verify_endpoint:
                            # Try to get the ID from the response
                            try:
                                data = response.json()
                                item_id = data.get(id_param)
                                if item_id:
                                    verify_endpoint = verify_endpoint.replace("{id}", str(item_id))
                                else:
                                    self.logger.warn(f"Could not find ID in response: {data}")
                                    continue
                            except (ValueError, KeyError) as e:
                                self.logger.warn(f"Error parsing response: {str(e)}")
                                continue
                        
                        # Verify if the field was set
                        try:
                            verify_response = self._make_request(
                                method="GET",
                                endpoint=verify_endpoint
                            )
                            
                            if verify_response.status_code == 200:
                                try:
                                    verify_data = verify_response.json()
                                    if field in verify_data and verify_data[field] == payload[field]:
                                        # Field was successfully set
                                        # Create detailed evidence with full request and response information
                                        evidence = {
                                            "request": {
                                                "method": method,
                                                "endpoint": endpoint,
                                                "url": response.request_details["url"] if hasattr(response, "request_details") else None,
                                                "headers": response.request_details["headers"] if hasattr(response, "request_details") else None,
                                                "payload": payload
                                            },
                                            "response": {
                                                "status_code": response.status_code,
                                                "headers": response.response_details["headers"] if hasattr(response, "response_details") else None,
                                                "body": response.response_details["body"] if hasattr(response, "response_details") else response.text[:1000]
                                            },
                                            "verification": {
                                                "endpoint": verify_endpoint,
                                                "method": "GET",
                                                "url": verify_response.request_details["url"] if hasattr(verify_response, "request_details") else None,
                                                "headers": verify_response.request_details["headers"] if hasattr(verify_response, "request_details") else None,
                                                "status_code": verify_response.status_code,
                                                "response_headers": verify_response.response_details["headers"] if hasattr(verify_response, "response_details") else None,
                                                "response_body": verify_response.response_details["body"] if hasattr(verify_response, "response_details") else None,
                                                "field_value": verify_data.get(field)
                                            }
                                        }
                                        
                                        self.add_finding(
                                            vulnerability="Mass Assignment",
                                            severity="HIGH",
                                            endpoint=endpoint,
                                            details=f"The API allows setting the sensitive field '{field}' via mass assignment, which could lead to privilege escalation.",
                                            evidence=evidence,
                                            remediation="Implement proper server-side filtering of request parameters to prevent setting of sensitive fields."
                                        )
                                except (ValueError, KeyError) as e:
                                    self.logger.warn(f"Error parsing verification response: {str(e)}")
                        except Exception as e:
                            self.logger.error(f"Error verifying field: {str(e)}")
                    else:
                        # Can't verify, but the request was successful
                        # Create detailed evidence with full request and response information
                        evidence = {
                            "request": {
                                "method": method,
                                "endpoint": endpoint,
                                "url": response.request_details["url"] if hasattr(response, "request_details") else None,
                                "headers": response.request_details["headers"] if hasattr(response, "request_details") else None,
                                "payload": payload
                            },
                            "response": {
                                "status_code": response.status_code,
                                "headers": response.response_details["headers"] if hasattr(response, "response_details") else None,
                                "body": response.response_details["body"] if hasattr(response, "response_details") else response.text[:1000]
                            }
                        }
                        
                        self.add_finding(
                            vulnerability="Potential Mass Assignment",
                            severity="MEDIUM",
                            endpoint=endpoint,
                            details=f"The API accepted a request with the sensitive field '{field}' without error, which might indicate a mass assignment vulnerability.",
                            evidence=evidence,
                            remediation="Implement proper server-side filtering of request parameters to prevent setting of sensitive fields."
                        )
            
            except Exception as e:
                self.logger.error(f"Error testing field '{field}': {str(e)}")
            
            # Add delay between requests
            time.sleep(0.5)
    
    def _test_registration_mass_assignment(self) -> None:
        """Test for mass assignment vulnerabilities during user registration."""
        self.logger.info("Testing for mass assignment vulnerabilities during user registration")
        
        # Use the dynamically resolved registration endpoint
        register_endpoint = self.register_endpoint
        
        # Test registering with admin privileges
        timestamp = int(time.time())
        username = f"test_mass_reg_{timestamp}"
        email = f"{username}@example.com"
        password = f"Test@{timestamp}"
        
        # Create registration payload with admin privileges
        register_payload = {
            "username": username,
            "email": email,
            "password": password,
            "admin": True  # Attempting to set admin privileges
        }
        
        self.logger.info(f"Attempting to register user '{username}' with admin privileges")
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=register_endpoint,
                json_data=register_payload
            )
            
            # Check if registration was successful
            if response.status_code in [200, 201, 204]:
                self.logger.info(f"Successfully registered user '{username}'")
                
                # Verify if the admin privileges were actually set
                debug_endpoint = self.debug_endpoint
                
                try:
                    # Add a small delay to allow the server to process the registration
                    time.sleep(1.0)
                    
                    verify_response = self._make_request(
                        method="GET",
                        endpoint=debug_endpoint
                    )
                    
                    if verify_response.status_code == 200:
                        try:
                            verify_data = verify_response.json()
                            users = []
                            if isinstance(verify_data, dict) and "users" in verify_data:
                                users = verify_data["users"]
                            elif isinstance(verify_data, list):
                                users = verify_data
                            
                            # Find the newly registered user
                            for user in users:
                                if user.get("username") == username:
                                    # Check if admin privileges were set
                                    if user.get("admin") is True:
                                        # Admin privileges were successfully set - add finding
                                        # Create detailed evidence with full request and response information
                                        evidence = {
                                            "request": {
                                                "method": "POST",
                                                "endpoint": register_endpoint,
                                                "url": response.request_details["url"] if hasattr(response, "request_details") else None,
                                                "headers": response.request_details["headers"] if hasattr(response, "request_details") else None,
                                                "payload": register_payload
                                            },
                                            "response": {
                                                "status_code": response.status_code,
                                                "headers": response.response_details["headers"] if hasattr(response, "response_details") else None,
                                                "body": response.response_details["body"] if hasattr(response, "response_details") else response.text[:1000]
                                            },
                                            "verification": {
                                                "method": "GET",
                                                "endpoint": debug_endpoint,
                                                "url": verify_response.request_details["url"] if hasattr(verify_response, "request_details") else None,
                                                "headers": verify_response.request_details["headers"] if hasattr(verify_response, "request_details") else None,
                                                "response_code": verify_response.status_code,
                                                "response_headers": verify_response.response_details["headers"] if hasattr(verify_response, "response_details") else None,
                                                "response_body": verify_response.response_details["body"] if hasattr(verify_response, "response_details") else None,
                                                "user": username,
                                                "admin_status": user.get("admin")
                                            }
                                        }
                                        
                                        self.add_finding(
                                            vulnerability="Mass Assignment During Registration",
                                            severity="CRITICAL",
                                            endpoint=register_endpoint,
                                            details=f"The API allows setting admin privileges during user registration via mass assignment.",
                                            evidence=evidence,
                                            remediation="Implement proper server-side filtering of request parameters during registration to prevent setting of sensitive fields like 'admin'."
                                        )
                                        return
                                    else:
                                        self.logger.info(f"User '{username}' was registered but admin privileges were not set")
                                        
                                        # Now try to register another user with admin=false to see if we can control it
                                        self._test_registration_with_admin_false()
                                        return
                            
                            self.logger.warn(f"Could not find newly registered user '{username}' in the user list")
                        except (ValueError, KeyError) as e:
                            self.logger.warn(f"Error parsing verification response: {str(e)}")
                    else:
                        self.logger.warn(f"Failed to verify registration, status code: {verify_response.status_code}")
                except Exception as e:
                    self.logger.error(f"Error verifying registration: {str(e)}")
            else:
                self.logger.info(f"Registration with admin privileges was rejected with status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error attempting registration with admin privileges: {str(e)}")
    
    def _test_registration_with_admin_false(self) -> None:
        """Test registration with admin=false to verify control over the field."""
        timestamp = int(time.time())
        username = f"test_mass_reg_false_{timestamp}"
        email = f"{username}@example.com"
        password = f"Test@{timestamp}"
        
        # Create registration payload with admin=false
        register_payload = {
            "username": username,
            "email": email,
            "password": password,
            "admin": False  # Explicitly setting admin to false
        }
        
        self.logger.info(f"Attempting to register user '{username}' with admin=false")
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=register_payload
            )
            
            # Check if registration was successful
            if response.status_code in [200, 201, 204]:
                self.logger.info(f"Successfully registered user '{username}' with admin=false")
                
                # Verify if the admin field was respected
                try:
                    # Add a small delay to allow the server to process the registration
                    time.sleep(1.0)
                    
                    verify_response = self._make_request(
                        method="GET",
                        endpoint=self.debug_endpoint
                    )
                    
                    if verify_response.status_code == 200:
                        try:
                            verify_data = verify_response.json()
                            users = []
                            if isinstance(verify_data, dict) and "users" in verify_data:
                                users = verify_data["users"]
                            elif isinstance(verify_data, list):
                                users = verify_data
                            
                            # Find the newly registered user
                            for user in users:
                                if user.get("username") == username:
                                    # Check if admin=false was respected
                                    if user.get("admin") is False:
                                        # This confirms we have control over the admin field
                                        self.add_finding(
                                            vulnerability="Mass Assignment During Registration",
                                            severity="CRITICAL",
                                            endpoint=self.register_endpoint,
                                            details=f"The API allows controlling the 'admin' field during user registration. While we couldn't set it to true, we confirmed we can set it to false, indicating mass assignment vulnerability.",
                                            evidence={
                                                "request": {
                                                    "method": "POST",
                                                    "endpoint": self.register_endpoint,
                                                    "payload": register_payload
                                                },
                                                "response": {
                                                    "status_code": response.status_code,
                                                    "body": response.text[:1000]  # Limit response size
                                                },
                                                "verification": {
                                                    "user": username,
                                                    "admin_status": user.get("admin")
                                                }
                                            },
                                            remediation="Implement proper server-side filtering of request parameters during registration to prevent setting of sensitive fields like 'admin'."
                                        )
                                        return
                        except (ValueError, KeyError) as e:
                            self.logger.warn(f"Error parsing verification response: {str(e)}")
                    else:
                        self.logger.warn(f"Failed to verify registration, status code: {verify_response.status_code}")
                except Exception as e:
                    self.logger.error(f"Error verifying registration: {str(e)}")
            else:
                self.logger.info(f"Registration with admin=false was rejected with status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error attempting registration with admin=false: {str(e)}")
    
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
        
        # Find registration endpoints based on path patterns and request body fields
        registration_patterns = ["register", "signup", "sign-up", "create_user", "users", "auth/sign-up"]
        create_user_patterns = ["users", "create_user", "user/create", "api/users"]
        update_user_patterns = ["users", "update_user", "user/update", "api/users"]
        get_user_patterns = ["users", "get_user", "user/get", "api/users"]
        debug_patterns = ["debug", "_debug", "test"]
        
        # Score each endpoint based on how likely it is to be a registration, create, update, or get endpoint
        register_candidates = []
        create_candidates = []
        update_candidates = []
        get_candidates = []
        debug_candidates = []
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            summary = endpoint.get("summary", "").lower()
            description = endpoint.get("description", "").lower()
            operation_id = endpoint.get("operationId", "").lower()
            
            # Check for debug endpoints
            if any(pattern in path.lower() for pattern in debug_patterns) or any(pattern in summary for pattern in debug_patterns) or any(pattern in description for pattern in debug_patterns):
                debug_candidates.append((endpoint, 10))
                continue
            
            # Registration endpoint scoring
            if method == "POST":
                register_score = 0
                for pattern in registration_patterns:
                    if pattern in path.lower():
                        register_score += 5
                    if pattern in summary or pattern in description or pattern in operation_id:
                        register_score += 3
                
                # Check request body for username/email/password fields
                request_body = endpoint.get("requestBody", {})
                if request_body:
                    properties = self._extract_request_properties(request_body)
                    if properties:
                        username_found = any(prop for prop in properties if "user" in prop.lower() or "name" in prop.lower())
                        email_found = any(prop for prop in properties if "email" in prop.lower())
                        password_found = any(prop for prop in properties if "pass" in prop.lower())
                        
                        if username_found:
                            register_score += 2
                        if email_found:
                            register_score += 2
                        if password_found:
                            register_score += 2
                            
                if register_score > 0:
                    register_candidates.append((endpoint, register_score))
            
            # Create user endpoint scoring
            if method == "POST":
                create_score = 0
                for pattern in create_user_patterns:
                    if pattern in path.lower():
                        create_score += 5
                    if pattern in summary or pattern in description or pattern in operation_id:
                        create_score += 3
                
                # Check if path doesn't contain parameters (like {id})
                if "{" not in path and "}" not in path:
                    create_score += 2
                    
                if create_score > 0:
                    create_candidates.append((endpoint, create_score))
            
            # Update user endpoint scoring
            if method in ["PUT", "PATCH"]:
                update_score = 0
                for pattern in update_user_patterns:
                    if pattern in path.lower():
                        update_score += 5
                    if pattern in summary or pattern in description or pattern in operation_id:
                        update_score += 3
                
                # Check if path contains parameters (like {id})
                if "{" in path and "}" in path:
                    update_score += 4
                    
                if update_score > 0:
                    update_candidates.append((endpoint, update_score))
            
            # Get user endpoint scoring
            if method == "GET":
                get_score = 0
                for pattern in get_user_patterns:
                    if pattern in path.lower():
                        get_score += 5
                    if pattern in summary or pattern in description or pattern in operation_id:
                        get_score += 3
                
                # Check if path contains parameters (like {id})
                if "{" in path and "}" in path:
                    get_score += 4
                    
                if get_score > 0:
                    get_candidates.append((endpoint, get_score))
        
        # Select the highest scoring candidates
        if register_candidates:
            register_candidates.sort(key=lambda x: x[1], reverse=True)
            best_register = register_candidates[0][0]
            self.register_endpoint = best_register.get("path")
            self.logger.info(f"Found registration endpoint: {self.register_endpoint}")
        
        if debug_candidates:
            debug_candidates.sort(key=lambda x: x[1], reverse=True)
            best_debug = debug_candidates[0][0]
            self.debug_endpoint = best_debug.get("path")
            self.logger.info(f"Found debug endpoint: {self.debug_endpoint}")
        
        if create_candidates:
            create_candidates.sort(key=lambda x: x[1], reverse=True)
            best_create = create_candidates[0][0]
            self.create_endpoint = best_create.get("path")
            self.logger.info(f"Found create user endpoint: {self.create_endpoint}")
        
        if update_candidates:
            update_candidates.sort(key=lambda x: x[1], reverse=True)
            best_update = update_candidates[0][0]
            self.update_endpoint = best_update.get("path")
            self.logger.info(f"Found update user endpoint: {self.update_endpoint}")
        
        if get_candidates:
            get_candidates.sort(key=lambda x: x[1], reverse=True)
            best_get = get_candidates[0][0]
            self.get_endpoint = best_get.get("path")
            self.logger.info(f"Found get user endpoint: {self.get_endpoint}")
    
    def _extract_request_properties(self, request_body: Dict[str, Any]) -> List[str]:
        """
        Extract property names from a request body schema.
        
        Args:
            request_body: Request body object from OpenAPI spec
            
        Returns:
            List of property names
        """
        properties = []
        
        # Handle different OpenAPI structures
        if "content" in request_body:
            content = request_body.get("content", {})
            for content_type, content_schema in content.items():
                if "schema" in content_schema:
                    schema = content_schema["schema"]
                    if "properties" in schema:
                        properties.extend(schema["properties"].keys())
        elif "schema" in request_body:
            schema = request_body["schema"]
            if "properties" in schema:
                properties.extend(schema["properties"].keys())
        
        return properties
    
    def _test_create_update_flow(self) -> None:
        """Test the create and update flow for mass assignment vulnerabilities."""
        self.logger.info("Testing create and update flow for mass assignment")
        
        # Step 1: Create a normal user
        user_id = None
        create_payload = self.create_user_payload.copy()
        
        # Adapt field names for Snorefox API
        if "username" in create_payload and "email" not in create_payload:
            create_payload["email"] = create_payload["username"] + "@example.com"
        
        # Try alternative endpoints if the default one fails
        endpoints_to_try = [
            self.create_endpoint,
            "/users",
            "/api/users",
            "/api/v1/users",
            "/auth/sign-up",  # Snorefox specific
            "/api/v1/auth/sign-up"  # Snorefox specific with prefix
        ]
        
        success = False
        for endpoint in endpoints_to_try:
            try:
                self.logger.info(f"Attempting to create user with endpoint: {endpoint}")
                response = self._make_request(
                    method="POST",
                    endpoint=endpoint,
                    json_data=create_payload
                )
                
                if response.status_code in [200, 201, 204]:
                    self.logger.info(f"Successfully created test user with endpoint: {endpoint}")
                    success = True
                    
                    # Try to get the user ID from the response
                    try:
                        data = response.json()
                        # Try common ID field variations
                        for field in [self.id_field, "id", "userId", "user_id", "_id", "uuid"]:
                            if field in data:
                                user_id = data[field]
                                self.logger.info(f"Found user ID in field: {field}")
                                break
                        
                        # If we couldn't find the ID directly, check if it's nested
                        if not user_id and "user" in data and isinstance(data["user"], dict):
                            user_data = data["user"]
                            for field in [self.id_field, "id", "userId", "user_id", "_id", "uuid"]:
                                if field in user_data:
                                    user_id = user_data[field]
                                    self.logger.info(f"Found user ID in nested user object, field: {field}")
                                    break
                        
                        # If we still couldn't find an ID, try to use the username/email as identifier
                        if not user_id:
                            # For APIs that use email or username as the identifier
                            if "email" in create_payload:
                                user_id = create_payload["email"]
                                self.logger.info("Using email as user identifier")
                            elif "username" in create_payload:
                                user_id = create_payload["username"]
                                self.logger.info("Using username as user identifier")
                            else:
                                self.logger.warn("Could not determine user identifier")
                                continue
                    except Exception as e:
                        self.logger.warn(f"Error parsing user creation response: {str(e)}")
                        continue
                    
                    # If we got a user ID, break out of the loop
                    if user_id:
                        # Update the create endpoint to the one that worked
                        self.create_endpoint = endpoint
                        break
                else:
                    self.logger.warn(f"Failed to create user with endpoint {endpoint}, status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error creating user with endpoint {endpoint}: {str(e)}")
        
        if not success or not user_id:
            self.logger.warn("Failed to create test user with any endpoint, skipping mass assignment test")
            return
        
        # Step 2: Try to update the user with sensitive fields
        if user_id:
            update_endpoint = self.update_endpoint.replace("{id}", str(user_id))
            
            for field in self.sensitive_fields:
                update_payload = {
                    field: self.test_values.get(field, True)
                }
                
                try:
                    response = self._make_request(
                        method="PUT",  # or PATCH
                        endpoint=update_endpoint,
                        json_data=update_payload
                    )
                    
                    # Check if the update was successful
                    if response.status_code in [200, 201, 204]:
                        # Step 3: Verify if the field was actually set
                        get_endpoint = self.get_endpoint.replace("{id}", str(user_id))
                        
                        try:
                            verify_response = self._make_request(
                                method="GET",
                                endpoint=get_endpoint
                            )
                            
                            if verify_response.status_code == 200:
                                try:
                                    verify_data = verify_response.json()
                                    if field in verify_data and verify_data[field] == update_payload[field]:
                                        # Field was successfully set
                                        self.add_finding(
                                            vulnerability="Mass Assignment",
                                            severity="HIGH",
                                            endpoint=update_endpoint,
                                            details=f"The API allows setting the sensitive field '{field}' via mass assignment, which could lead to privilege escalation.",
                                            evidence={
                                                "request": {
                                                    "method": "PUT",
                                                    "endpoint": update_endpoint,
                                                    "payload": update_payload
                                                },
                                                "response": {
                                                    "status_code": response.status_code,
                                                    "body": response.text[:1000]  # Limit response size
                                                },
                                                "verification": {
                                                    "endpoint": get_endpoint,
                                                    "status_code": verify_response.status_code,
                                                    "field_value": verify_data.get(field)
                                                }
                                            },
                                            remediation="Implement proper server-side filtering of request parameters to prevent setting of sensitive fields."
                                        )
                                except (ValueError, KeyError) as e:
                                    self.logger.warn(f"Error parsing verification response: {str(e)}")
                        except Exception as e:
                            self.logger.error(f"Error verifying field: {str(e)}")
                    
                except Exception as e:
                    self.logger.error(f"Error testing field '{field}': {str(e)}")
                
                # Add delay between requests
                time.sleep(0.5)
    
    def _test_role_change_vulnerability(self) -> None:
        """Test for vulnerabilities that allow changing user roles between admin and regular user."""
        self.logger.info("Testing for role change vulnerabilities (admin to regular user and vice versa)")
        
        # Step 1: Get existing accounts to find admin and regular users
        debug_endpoint = "/users/v1/_debug"  # Endpoint to retrieve user accounts
        admin_user = None
        regular_user = None
        
        try:
            response = self._make_request(
                method="GET",
                endpoint=debug_endpoint
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Handle different response formats
                    users = []
                    if isinstance(data, dict) and "users" in data:
                        users = data["users"]
                    elif isinstance(data, list):
                        users = data
                    
                    # Find an admin user and a regular user
                    for user in users:
                        # Check for common admin field names
                        is_admin = False
                        for field in ["admin", "is_admin", "isAdmin", "role"]:
                            if field in user and user[field] in [True, "admin", "administrator"]:
                                is_admin = True
                                break
                        
                        if is_admin and not admin_user:
                            admin_user = user
                        elif not is_admin and not regular_user:
                            regular_user = user
                        
                        if admin_user and regular_user:
                            break
                    
                    self.logger.info(f"Found admin user: {admin_user is not None}, regular user: {regular_user is not None}")
                except (ValueError, KeyError) as e:
                    self.logger.error(f"Error parsing user data: {str(e)}")
                    return
            else:
                self.logger.warn(f"Failed to get user accounts, status code: {response.status_code}")
                return
        except Exception as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
            return
        
        # If we couldn't find both types of users, we can't proceed
        if not admin_user or not regular_user:
            self.logger.warn("Could not find both admin and regular users to test role change")
            return
        
        # Step 2: Test changing a regular user to admin
        self._test_change_user_role(regular_user, True)
        
        # Step 3: Test changing an admin user to regular
        self._test_change_user_role(admin_user, False)
    
    def _test_change_user_role(self, user: Dict[str, Any], make_admin: bool) -> None:
        """Test changing a user's role between admin and regular user.
        
        Args:
            user: The user to modify
            make_admin: True to make the user an admin, False to make the user regular
        """
        # Determine the username and current admin status
        username = None
        for field in ["username", "user", "name", "id"]:
            if field in user:
                username = user[field]
                break
        
        if not username:
            self.logger.warn("Could not determine username for role change test")
            return
        
        # Determine which admin field to use
        admin_field = None
        for field in ["admin", "is_admin", "isAdmin", "role"]:
            if field in user:
                admin_field = field
                break
        
        if not admin_field:
            self.logger.warn("Could not determine admin field for role change test")
            return
        
        # Prepare the update endpoint and payload
        # Use a dynamic endpoint if available, otherwise fall back to a default pattern
        update_endpoint = self.update_endpoint.replace("{id}", str(username)) if "{id}" in self.update_endpoint else f"/users/v1/{username}"
        
        # Create payload based on the admin field type
        update_payload = {}
        if admin_field == "role":
            update_payload[admin_field] = "admin" if make_admin else "user"
        else:
            update_payload[admin_field] = make_admin
        
        self.logger.info(f"Attempting to {'make admin' if make_admin else 'revoke admin'} for user '{username}'")
        
        # Try different HTTP methods
        for method in ["PUT", "PATCH", "POST"]:
            try:
                response = self._make_request(
                    method=method,
                    endpoint=update_endpoint,
                    json_data=update_payload
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    self.logger.info(f"Successfully sent {method} request to change role for user '{username}'")
                    
                    # Verify the role change
                    try:
                        verify_response = self._make_request(
                            method="GET",
                            endpoint=self.debug_endpoint
                        )
                        
                        if verify_response.status_code == 200:
                            try:
                                verify_data = verify_response.json()
                                users = []
                                if isinstance(verify_data, dict) and "users" in verify_data:
                                    users = verify_data["users"]
                                elif isinstance(verify_data, list):
                                    users = verify_data
                                
                                # Find the user and check if the role was changed
                                for u in users:
                                    user_match = False
                                    for field in ["username", "user", "name", "id"]:
                                        if field in u and u[field] == username:
                                            user_match = True
                                            break
                                    
                                    if user_match:
                                        role_changed = False
                                        if admin_field in u:
                                            if admin_field == "role":
                                                role_changed = (u[admin_field] == "admin") == make_admin
                                            else:
                                                role_changed = u[admin_field] == make_admin
                                        
                                        if role_changed:
                                            # Role was successfully changed - add finding
                                            self.add_finding(
                                                vulnerability="Role Change via Mass Assignment",
                                                severity="CRITICAL",
                                                endpoint=update_endpoint,
                                                details=f"The API allows {'elevating privileges' if make_admin else 'demoting privileges'} by directly modifying the '{admin_field}' field.",
                                                evidence={
                                                    "request": {
                                                        "method": method,
                                                        "endpoint": update_endpoint,
                                                        "payload": update_payload
                                                    },
                                                    "response": {
                                                        "status_code": response.status_code,
                                                        "body": response.text[:1000]  # Limit response size
                                                    },
                                                    "verification": {
                                                        "original_value": not make_admin if admin_field == "role" else make_admin,
                                                        "new_value": u[admin_field]
                                                    }
                                                },
                                                remediation="Implement proper authorization checks and server-side filtering to prevent unauthorized role changes."
                                            )
                                            return  # Found the vulnerability, no need to try other methods
                            except (ValueError, KeyError) as e:
                                self.logger.warn(f"Error parsing verification response: {str(e)}")
                        else:
                            self.logger.warn(f"Failed to verify role change, status code: {verify_response.status_code}")
                    except Exception as e:
                        self.logger.error(f"Error verifying role change: {str(e)}")
                else:
                    self.logger.info(f"{method} request to change role was rejected with status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error attempting to change role with {method}: {str(e)}")
            
            # Add delay between requests
            time.sleep(0.5)
    

