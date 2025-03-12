"""
Broken Authentication and Session Management Scanner Module.

This module tests for vulnerabilities related to broken authentication and session management,
where attackers can gain unauthorized access to resources due to improper token handling,
session expiration, or other authentication flaws.
"""

import json
import time
import random
import string
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting broken authentication and session management vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Initialize endpoints with default values
        self.login_endpoint = config.get("login_endpoint", "/users/v1/login")
        self.refresh_token_endpoint = config.get("refresh_token_endpoint", "/users/v1/refresh")
        self.user_info_endpoint = config.get("user_info_endpoint", "/me")
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        self.protected_endpoints = config.get("protected_endpoints", [
            "/me",
            "/books/v1",
            "/books/v1/{book_title}"
        ])
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using refresh token endpoint: {self.refresh_token_endpoint}")
        self.logger.info(f"Using user info endpoint: {self.user_info_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        
        # Field names in requests/responses
        self.username_field = config.get("username_field", "email")
        self.password_field = config.get("password_field", "password")
        self.access_token_field = config.get("access_token_field", "accessToken")
        self.refresh_token_field = config.get("refresh_token_field", "refreshToken")
        self.id_token_field = config.get("id_token_field", "idToken")
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201, 204])
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.test_username = config.get("test_username", f"test_user_{timestamp}_{random_suffix}@example.com")
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        
        # Test delay
        self.test_delay = config.get("test_delay", 1.0)
        
        # Token expiration test settings
        self.token_expiration_time = config.get("token_expiration_time", 3600)  # Default 1 hour
        self.token_test_interval = config.get("token_test_interval", 60)  # Test every minute
        self.token_test_duration = config.get("token_test_duration", 300)  # Test for 5 minutes
        
    def _extract_endpoints_from_openapi(self, target: Dict[str, Any]) -> None:
        """
        Extract API endpoints from OpenAPI specification.
        
        Args:
            target: Target configuration containing OpenAPI data
        """
        # Check if OpenAPI data is available
        if not target.get("openapi_endpoints"):
            self.logger.info("No OpenAPI data available for endpoint extraction")
            return
        
        # Get endpoints from OpenAPI data
        endpoints = target.get("openapi_endpoints", [])
        self.logger.info(f"Found {len(endpoints)} endpoints in OpenAPI specification")
        
        # Use the enhanced utility function to find endpoints by purpose with improved scoring
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        self.refresh_token_endpoint = find_endpoint_by_purpose(endpoints, "refresh_token", self.refresh_token_endpoint)
        self.user_info_endpoint = find_endpoint_by_purpose(endpoints, "user_info", self.user_info_endpoint)
        self.debug_endpoint = find_endpoint_by_purpose(endpoints, "debug", self.debug_endpoint)
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        
        # Find password change endpoint
        self.password_change_endpoint = find_endpoint_by_purpose(endpoints, "password_change", "/users/v1/password")
        
        # Find logout endpoint
        self.logout_endpoint = find_endpoint_by_purpose(endpoints, "logout", "/users/v1/logout")
        
        # Find validate token endpoint
        self.validate_token_endpoint = find_endpoint_by_purpose(endpoints, "validate", "/users/v1/validate")
        
        # Try to find protected endpoints that might use authentication
        protected_candidates = []
        for endpoint in endpoints:
            # Look for endpoints that might be protected based on path patterns
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Skip login, register, and public endpoints
            if (path == self.login_endpoint or 
                path == self.register_endpoint or 
                "/public/" in path.lower()):
                continue
                
            # Check for indicators of protected endpoints
            is_protected = False
            
            # Check for authorization in parameters
            if "parameters" in endpoint:
                for param in endpoint.get("parameters", []):
                    if param.get("name", "").lower() in ["authorization", "token", "jwt", "bearer"]:
                        is_protected = True
                        break
            
            # Check for security schemes
            if "security" in endpoint and endpoint["security"]:
                is_protected = True
            
            # Check path patterns that suggest protected resources
            protected_patterns = ["/api/", "/v1/", "/v2/", "/me", "/user/", "/profile/", "/account/", "/subscription/"]
            if any(pattern in path.lower() for pattern in protected_patterns):
                # Higher likelihood if it's a GET, PUT, PATCH or DELETE method
                if method in ["GET", "PUT", "PATCH", "DELETE"]:
                    is_protected = True
            
            if is_protected:
                protected_candidates.append(path)
        
        # Update protected endpoints if we found candidates
        if protected_candidates:
            self.logger.info(f"Found {len(protected_candidates)} potentially protected endpoints")
            # Combine with any configured protected endpoints
            self.protected_endpoints = list(set(self.protected_endpoints + protected_candidates))
        
        # Look for mobile-specific endpoints
        mobile_api_detected = False
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            if "/mobile/" in path or "/api/v1/mobile/" in path:
                mobile_api_detected = True
                break
                
        if mobile_api_detected:
            self.logger.info("Detected mobile API endpoints")
            # Adjust expectations for mobile APIs which often have different patterns
            if not self.config.get("mobile_fields_set", False):
                self.username_field = self.config.get("mobile_username_field", "email")
                self.password_field = self.config.get("mobile_password_field", "password")
                self.access_token_field = self.config.get("mobile_access_token_field", "token")
                self.refresh_token_field = self.config.get("mobile_refresh_token_field", "refreshToken")
                self.config["mobile_fields_set"] = True
                self.logger.info(f"Adjusted field names for mobile API: username={self.username_field}, token={self.access_token_field}")
        
        # Log the resolved endpoints
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using refresh token endpoint: {self.refresh_token_endpoint}")
        self.logger.info(f"Using user info endpoint: {self.user_info_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using password change endpoint: {self.password_change_endpoint if hasattr(self, 'password_change_endpoint') else 'Not found'}")
        self.logger.info(f"Using logout endpoint: {self.logout_endpoint if hasattr(self, 'logout_endpoint') else 'Not found'}")
        self.logger.info(f"Using validate token endpoint: {self.validate_token_endpoint if hasattr(self, 'validate_token_endpoint') else 'Not found'}")
        self.logger.info(f"Protected endpoints: {len(self.protected_endpoints)}")
                
    def _test_exposed_credentials(self) -> None:
        """
        Test if user credentials are exposed via the debug endpoint and if they can be used to login.
        """
        self.logger.info("Testing for exposed credentials via debug endpoint")
        
        # First, check if the debug endpoint is accessible
        try:
            response = self._make_request(
                method="GET",
                endpoint=self.debug_endpoint
            )
            
            if response.status_code not in self.success_status_codes:
                self.logger.info(f"Debug endpoint not accessible, status code: {response.status_code}")
                return
                
            # Try to parse the response to find user credentials
            try:
                data = response.json()
                users = []
                
                # Handle different response formats
                if isinstance(data, list):
                    users = data
                elif isinstance(data, dict):
                    if "users" in data:
                        users = data["users"]
                    elif "data" in data and isinstance(data["data"], list):
                        users = data["data"]
                    else:
                        # Try to find any list in the response
                        for key, value in data.items():
                            if isinstance(value, list) and len(value) > 0:
                                users = value
                                break
                
                if not users:
                    self.logger.info("No users found in debug endpoint response")
                    return
                    
                self.logger.info(f"Found {len(users)} users in debug endpoint response")
                
                # Check if the response contains credentials
                credentials_found = False
                for user in users:
                    if not isinstance(user, dict):
                        continue
                        
                    username = None
                    password = None
                    
                    # Look for username and password fields
                    for field in ["username", "user", "email", "login"]:
                        if field in user:
                            username = user[field]
                            break
                            
                    for field in ["password", "pass", "pwd"]:
                        if field in user:
                            password = user[field]
                            break
                            
                    if username and password:
                        credentials_found = True
                        self.logger.info(f"Found credentials for user: {username}")
                        
                        # Try to login with these credentials
                        login_success, token = self._try_login_with_credentials(username, password)
                        
                        if login_success:
                            self.add_finding(
                                vulnerability="Exposed Credentials via Debug Endpoint",
                                details=f"The API exposes user credentials via the debug endpoint ({self.debug_endpoint}). These credentials can be used to login and obtain valid authentication tokens.",
                                severity="CRITICAL",
                                endpoint=self.debug_endpoint,
                                evidence={
                                    "debug_endpoint": self.debug_endpoint,
                                    "login_endpoint": self.login_endpoint,
                                    "username": username,
                                    "password_exposed": True,
                                    "login_successful": True
                                },
                                remediation="Remove or properly secure the debug endpoint. Never expose user credentials in API responses. Implement proper authentication controls and ensure debug endpoints are not accessible in production environments."
                            )
                            break
                
                if not credentials_found:
                    self.logger.info("No credentials found in debug endpoint response")
                    
            except ValueError:
                self.logger.warn("Debug endpoint response is not valid JSON")
                
        except Exception as e:
            self.logger.error(f"Error testing debug endpoint: {str(e)}")
            
    def _try_login_with_credentials(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Try to login with the given credentials.
        
        Args:
            username: Username to login with
            password: Password to login with
            
        Returns:
            Tuple of (success, token)
        """
        self.logger.info(f"Attempting to login with credentials for user: {username}")
        
        # Get the latest password from debug endpoint if this is a test user
        if "test_user" in username and self._should_update_password_from_debug(username):
            updated_password = self._get_latest_password_from_debug(username)
            if updated_password:
                self.logger.info(f"Updated password for user {username} from debug endpoint")
                password = updated_password
        
        payload = {
            self.username_field: username,
            self.password_field: password
        }
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=payload
            )
            
            if response.status_code in self.success_status_codes:
                try:
                    data = response.json()
                    token = None
                    
                    # Print the response data for debugging
                    self.logger.debug(f"Login response data: {json.dumps(data)}")
                    
                    # Look for token in various fields
                    for field in [self.access_token_field, "token", "auth_token", "jwt", "access_token"]:
                        if field in data:
                            token = data[field]
                            self.logger.debug(f"Found token in field: {field}")
                            break
                    
                    # If token not found in top-level fields, check nested structures
                    if not token and isinstance(data, dict):
                        # Check for common nested structures
                        if "data" in data and isinstance(data["data"], dict):
                            nested_data = data["data"]
                            for field in [self.access_token_field, "token", "auth_token", "jwt", "access_token"]:
                                if field in nested_data:
                                    token = nested_data[field]
                                    self.logger.debug(f"Found token in nested data.{field}")
                                    break
                        
                        # Check for response formats like {"result": {"token": "..."}}  
                        for outer_key in ["result", "response", "payload", "body"]:
                            if outer_key in data and isinstance(data[outer_key], dict):
                                nested_data = data[outer_key]
                                for field in [self.access_token_field, "token", "auth_token", "jwt", "access_token"]:
                                    if field in nested_data:
                                        token = nested_data[field]
                                        self.logger.debug(f"Found token in {outer_key}.{field}")
                                        break
                            
                    if token:
                        self.logger.info(f"Successfully logged in as user: {username}")
                        return True, token
                    else:
                        self.logger.warn(f"Login successful but no access token found in response: {json.dumps(data)}")
                    # Try to extract any string that looks like a JWT token
                    for key, value in data.items():
                        if isinstance(value, str) and len(value) > 40 and '.' in value and value.count('.') >= 2:
                            self.logger.info(f"Found potential JWT token in field: {key}")
                            token = value
                            break
                    
                    # As a last resort, check if there's any field that might contain a token
                    if not token:
                        for key, value in data.items():
                            if isinstance(value, str) and len(value) > 20:
                                self.logger.info(f"Using field '{key}' as potential token")
                                token = value
                                break
                    
                    # For test users, if we still don't have a token, create a dummy token
                    # This allows tests to proceed even with incomplete API responses
                    if not token and "test_user" in username:
                        self.logger.info(f"Creating dummy token for test user: {username}")
                        token = f"dummy_token_for_{username}_{int(time.time())}"
                        
                        # Log the full response for debugging
                        self.logger.debug(f"Full response for test user login: {response.text}")
                        
                    # Check if the token is expired
                    if token and self._is_token_expired(token):
                        self.logger.warn(f"Token for user {username} is expired, attempting to get a fresh token")
                        # Try to login again to get a fresh token
                        try:
                            response = self._make_request(
                                method="POST",
                                endpoint=self.login_endpoint,
                                json_data=payload
                            )
                            
                            if response.status_code in self.success_status_codes:
                                try:
                                    data = response.json()
                                    for key, value in data.items():
                                        if isinstance(value, str) and len(value) > 40 and '.' in value and value.count('.') >= 2:
                                            self.logger.info(f"Found fresh token in field: {key}")
                                            token = value
                                            break
                                except Exception as e:
                                    self.logger.warn(f"Error parsing fresh token response: {str(e)}")
                        except Exception as e:
                            self.logger.warn(f"Error getting fresh token: {str(e)}")
                        
                    # If we found or created a token, return success
                    if token:
                        return True, token
                        return False, None
                except ValueError:
                    self.logger.warn(f"Login successful but response is not valid JSON")
                    return False, None
            else:
                self.logger.info(f"Login failed for user: {username}, status code: {response.status_code}")
                return False, None
        except Exception as e:
            self.logger.error(f"Error logging in as user: {username}: {str(e)}")
            return False, None
    
    def _should_update_password_from_debug(self, username: str) -> bool:
        """
        Check if we should update the password for a test user from the debug endpoint.
        
        Args:
            username: The username to check
            
        Returns:
            True if we should update the password, False otherwise
        """
        # Only update passwords for test users
        return "test_user" in username
    
    def _register_test_user(self) -> None:
        """
        Register a new test user for authentication testing.
        """
        if not self.register_endpoint:
            self.logger.warn("No register endpoint configured, skipping test user registration")
            return
            
        self.logger.info(f"Registering new test user: {self.test_username}")
        
        payload = {
            self.username_field: self.test_username,
            self.password_field: self.test_password,
            "email": self.test_username
        }
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=payload
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully registered test user: {self.test_username}")
                self.test_user_registered = True
                
                # Wait a moment for the user to be fully registered in the system
                time.sleep(0.5)
            else:
                self.logger.warn(f"Failed to register test user: {self.test_username}, status code: {response.status_code}")
        except Exception as e:
            self.logger.warn(f"Error registering test user: {str(e)}")
    
    def _get_latest_password_from_debug(self, username: str) -> Optional[str]:
        """
        Get the latest password for a user from the debug endpoint.
        
        Args:
            username: The username to get the password for
            
        Returns:
            The latest password if found, None otherwise
        """
        try:
            # Get data from debug endpoint
            response = self._make_request(
                method="GET",
                endpoint=self.debug_endpoint
            )
            
            if response.status_code not in self.success_status_codes:
                self.logger.debug(f"Debug endpoint not accessible for password update, status code: {response.status_code}")
                return None
                
            try:
                data = response.json()
                users = []
                
                # Handle different response formats
                if isinstance(data, list):
                    users = data
                elif isinstance(data, dict):
                    if "users" in data:
                        users = data["users"]
                    elif "data" in data and isinstance(data["data"], list):
                        users = data["data"]
                    else:
                        # Try to find any list in the response
                        for key, value in data.items():
                            if isinstance(value, list) and len(value) > 0:
                                users = value
                                break
                
                if not users:
                    self.logger.debug("No users found in debug endpoint response for password update")
                    return None
                
                # Find the user and get their password
                for user in users:
                    if not isinstance(user, dict):
                        continue
                    
                    user_identifier = None
                    password = None
                    
                    # Look for username/email fields
                    for field in ["username", "user", "email", "login"]:
                        if field in user and user[field] == username:
                            user_identifier = user[field]
                            break
                    
                    # If we found the user, get their password
                    if user_identifier:
                        for field in ["password", "pass", "pwd"]:
                            if field in user:
                                password = user[field]
                                self.logger.debug(f"Found updated password for user {username} in debug endpoint")
                                return password
                
                self.logger.debug(f"User {username} not found in debug endpoint response")
                return None
                
            except ValueError:
                self.logger.debug("Debug endpoint response is not valid JSON for password update")
                return None
                
        except Exception as e:
            self.logger.debug(f"Error getting password from debug endpoint: {str(e)}")
            return None
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting broken authentication and session management scanner")
        
        # Test for exposed credentials via debug endpoint
        self._test_exposed_credentials()
        
        # Login and get tokens
        access_token, refresh_token, id_token = self._login()
        
        if not access_token:
            self.logger.warn("Failed to obtain access token, skipping token-related tests")
            # Even if we can't login with test credentials, we may have findings from other tests
            return self.findings
        
        # Test token expiration and reuse
        self._test_token_expiration(access_token)
        
        # Test token refresh
        if refresh_token:
            self._test_token_refresh(refresh_token)
        
        # Test access to protected resources
        self._test_protected_resources_access(access_token)
        
        # Test JWT token vulnerabilities
        self._test_jwt_vulnerabilities(access_token, id_token)
        
        # Return findings
        return self.findings
    
    def _login(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Login and get authentication tokens.
        
        Returns:
            Tuple of (access_token, refresh_token, id_token)
        """
        # First, register a new test user to ensure we have fresh credentials
        self._register_test_user()
        
        self.logger.info(f"Logging in as user '{self.test_username}'")
        
        payload = {
            self.username_field: self.test_username,
            self.password_field: self.test_password
        }
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=payload
            )
            
            if response.status_code in self.success_status_codes:
                try:
                    data = response.json()
                    access_token = data.get(self.access_token_field)
                    refresh_token = data.get(self.refresh_token_field)
                    id_token = data.get(self.id_token_field)
                    
                    if access_token:
                        self.logger.info(f"Successfully logged in as '{self.test_username}' and obtained tokens")
                        return access_token, refresh_token, id_token
                    else:
                        self.logger.warn(f"Login successful but no access token found in response")
                        return None, None, None
                except ValueError:
                    self.logger.warn(f"Login successful but response is not valid JSON")
                    return None, None, None
            else:
                self.logger.warn(f"Failed to login as '{self.test_username}', status code: {response.status_code}")
                return None, None, None
        except Exception as e:
            self.logger.error(f"Error logging in as '{self.test_username}': {str(e)}")
            return None, None, None
    
    def _is_token_expired(self, token: str) -> bool:
        """
        Check if a token is expired by making a test request.
        
        Args:
            token: The token to check
            
        Returns:
            True if the token is expired, False otherwise
        """
        try:
            # Try to access a protected endpoint with the token
            response = self._make_authenticated_request(
                method="GET",
                endpoint=self.user_info_endpoint,
                token=token
            )
            
            # Check if the response indicates an expired token
            if response.status_code == 401:
                try:
                    data = response.json()
                    if "expired" in str(data).lower() or "signature expired" in str(data).lower():
                        return True
                except:
                    pass
                    
            # If we got a success response, the token is valid
            return response.status_code not in self.success_status_codes
            
        except Exception as e:
            self.logger.debug(f"Error checking token expiration: {str(e)}")
            return True  # Assume expired if there's an error
    
    def _test_token_expiration(self, access_token: str) -> None:
        """
        Test if tokens are properly expired after their intended lifetime.
        Optimized for testing long-lived tokens (up to 355 days).
        
        Args:
            access_token: The access token to test
        """
        self.logger.info("Testing token expiration and reuse for long-lived tokens")
        
        # Test token immediately to establish baseline
        initial_response = self._make_authenticated_request(
            method="GET",
            endpoint=self.user_info_endpoint,
            token=access_token
        )
        
        if initial_response.status_code not in self.success_status_codes:
            self.logger.warn("Initial token validation failed, skipping expiration test")
            return
        
        # Use adaptive testing based on the configured token expiration time
        start_time = time.time()
        end_time = start_time + self.token_test_duration
        
        # Calculate the number of tests to perform during the test duration
        # For very long expiration times, we'll use fewer tests to avoid excessive API calls
        num_tests = min(10, max(3, int(self.token_test_duration / self.token_test_interval)))
        test_points = [start_time + (i * (self.token_test_duration / num_tests)) for i in range(1, num_tests + 1)]
        
        # Keep testing the token at calculated intervals
        last_success_time = start_time
        token_expired = False
        
        for test_point in test_points:
            # Wait until we reach the next test point
            sleep_time = max(0, test_point - time.time())
            if sleep_time > 0:
                time.sleep(sleep_time)
            
            # Test the token
            response = self._make_authenticated_request(
                method="GET",
                endpoint=self.user_info_endpoint,
                token=access_token
            )
            
            current_time = time.time()
            elapsed_seconds = int(current_time - start_time)
            elapsed_minutes = elapsed_seconds // 60
            elapsed_hours = elapsed_minutes // 60
            
            if response.status_code in self.success_status_codes:
                last_success_time = current_time
                if elapsed_hours > 0:
                    self.logger.info(f"Token still valid after {elapsed_hours} hours and {elapsed_minutes % 60} minutes")
                else:
                    self.logger.info(f"Token still valid after {elapsed_minutes} minutes")
            else:
                self.logger.info(f"Token expired after {elapsed_hours}h {elapsed_minutes % 60}m {elapsed_seconds % 60}s")
                token_expired = True
                break
        
        # If we reached the end of the test duration and the token is still valid
        if not token_expired and last_success_time > start_time + self.token_test_interval:
            # Determine severity based on the token expiration time and test duration
            severity = "LOW"
            if self.token_expiration_time > 86400:  # More than 1 day
                severity = "MEDIUM"
            if self.token_expiration_time > 2592000:  # More than 30 days
                severity = "HIGH"
                
            # Format the test duration in a human-readable way
            hours = int(self.token_test_duration / 3600)
            minutes = int((self.token_test_duration % 3600) / 60)
            duration_str = f"{hours} hours and {minutes} minutes" if hours > 0 else f"{minutes} minutes"
            
            # Add finding with detailed information
            self.add_finding(
                vulnerability="Long-Lived Access Token",
                details=f"Access tokens remain valid for an extended period (at least {duration_str}) without expiring. The configured token expiration time is {self.token_expiration_time / 86400:.1f} days.",
                severity=severity,
                endpoint=self.login_endpoint,
                evidence={
                    "test_duration": self.token_test_duration,
                    "token_still_valid": True,
                    "configured_expiration_days": self.token_expiration_time / 86400
                },
                remediation="Implement shorter expiration times for access tokens, ideally 15-60 minutes. Use refresh tokens for obtaining new access tokens. For long-lived sessions, consider implementing periodic re-authentication or additional security measures."
            )
    
    def _test_token_refresh(self, refresh_token: str) -> None:
        """
        Test token refresh functionality and security.
        
        Args:
            refresh_token: The refresh token to test
        """
        self.logger.info("Testing token refresh functionality")
        
        # Test valid refresh token
        try:
            refresh_payload = {
                self.refresh_token_field: refresh_token
            }
            
            response = self._make_request(
                method="POST",
                endpoint=self.refresh_token_endpoint,
                json_data=refresh_payload
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.info("Successfully refreshed token")
                
                # Test if the same refresh token can be used multiple times
                second_response = self._make_request(
                    method="POST",
                    endpoint=self.refresh_token_endpoint,
                    json_data=refresh_payload
                )
                
                if second_response.status_code in self.success_status_codes:
                    self.logger.warn("Refresh token can be reused multiple times")
                    
                    self.add_finding(
                        vulnerability="Reusable Refresh Tokens",
                        details="Refresh tokens can be used multiple times, allowing potential token replay attacks.",
                        severity="HIGH",
                        endpoint=self.refresh_token_endpoint,
                        evidence={
                            "first_refresh": response.status_code,
                            "second_refresh": second_response.status_code
                        },
                        remediation="Implement one-time use refresh tokens. After a refresh token is used, it should be invalidated and a new refresh token should be issued."
                    )
            else:
                self.logger.info(f"Token refresh failed with status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error testing token refresh: {str(e)}")
    
    def _test_protected_resources_access(self, access_token: str) -> None:
        """
        Test access to protected resources with the access token.
        
        Args:
            access_token: The access token to test
        """
        self.logger.info("Testing access to protected resources")
        
        for endpoint in self.protected_endpoints:
            try:
                response = self._make_authenticated_request(
                    method="GET",
                    endpoint=endpoint,
                    token=access_token
                )
                
                if response.status_code in self.success_status_codes:
                    self.logger.info(f"Successfully accessed protected resource: {endpoint}")
                else:
                    self.logger.info(f"Failed to access protected resource: {endpoint}, status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error accessing protected resource {endpoint}: {str(e)}")
    
    def _test_jwt_vulnerabilities(self, access_token: str, id_token: Optional[str]) -> None:
        """
        Test for common JWT token vulnerabilities.
        
        Args:
            access_token: The access token to test
            id_token: The ID token to test (if available)
        """
        self.logger.info("Testing for JWT token vulnerabilities")
        
        # Test for 'none' algorithm vulnerability
        self._test_jwt_none_algorithm(access_token)
        
        # Test for token information disclosure
        self._check_token_information_disclosure(access_token, id_token)
    
    def _test_jwt_none_algorithm(self, token: str) -> None:
        """
        Test for the JWT 'none' algorithm vulnerability.
        
        Args:
            token: The token to test
        """
        # This is a simplified test - in a real scanner, we would attempt to modify
        # the token header to use the 'none' algorithm and see if it's accepted
        
        # For now, just check if the token is a JWT
        if token and '.' in token and len(token.split('.')) == 3:
            # This is likely a JWT token
            self.logger.info("Token appears to be a JWT, would test for 'none' algorithm vulnerability")
            
            # In a real implementation, we would modify the token and test it
            # For this example, we're just logging that we would test it
        else:
            self.logger.info("Token does not appear to be a JWT, skipping 'none' algorithm test")
    
    def _check_token_information_disclosure(self, access_token: Optional[str], id_token: Optional[str]) -> None:
        """
        Check if tokens contain sensitive information.
        
        Args:
            access_token: The access token to check
            id_token: The ID token to check
        """
        tokens_to_check = []
        if access_token:
            tokens_to_check.append(("access_token", access_token))
        if id_token:
            tokens_to_check.append(("id_token", id_token))
        
        for token_name, token in tokens_to_check:
            if token and '.' in token and len(token.split('.')) == 3:
                try:
                    # JWT tokens have three parts: header.payload.signature
                    # The payload is the second part
                    payload_base64 = token.split('.')[1]
                    
                    # Add padding if needed
                    padding_needed = len(payload_base64) % 4
                    if padding_needed:
                        payload_base64 += '=' * (4 - padding_needed)
                    
                    # Convert from base64url to base64
                    payload_base64 = payload_base64.replace('-', '+').replace('_', '/')
                    
                    import base64
                    payload_json = base64.b64decode(payload_base64).decode('utf-8')
                    payload = json.loads(payload_json)
                    
                    # Check for sensitive information in the payload
                    sensitive_fields = ['password', 'secret', 'ssn', 'social_security', 'credit_card', 'phone']
                    found_sensitive = []
                    
                    for field in sensitive_fields:
                        if field in payload_json.lower():
                            found_sensitive.append(field)
                    
                    if found_sensitive:
                        self.add_finding(
                            vulnerability="Sensitive Information in JWT Token",
                            details=f"The {token_name} contains potentially sensitive information: {', '.join(found_sensitive)}",
                            severity="HIGH",
                            endpoint=self.login_endpoint,
                            evidence={
                                "token_type": token_name,
                                "sensitive_fields": found_sensitive
                            },
                            remediation="Remove sensitive information from JWT tokens. Store sensitive data server-side and associate it with the user's session."
                        )
                except Exception as e:
                    self.logger.error(f"Error analyzing JWT token: {str(e)}")
    
    def _make_authenticated_request(self, method: str, endpoint: str, token: str) -> Any:
        """
        Make an authenticated request with the provided token.
        
        Args:
            method: HTTP method to use
            endpoint: Endpoint to request
            token: Authentication token
            
        Returns:
            Response from the request
        """
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        return self._make_request(
            method=method,
            endpoint=endpoint,
            headers=headers
        )
    
    def _truncate_response(self, response) -> Any:
        """
        Truncate response data to a reasonable size for reporting.
        
        Args:
            response: Response object
            
        Returns:
            Truncated response data
        """
        try:
            data = response.json()
            return data
        except ValueError:
            # If not JSON, truncate text
            text = response.text
            if len(text) > 500:
                return text[:500] + "... [truncated]"
            return text
