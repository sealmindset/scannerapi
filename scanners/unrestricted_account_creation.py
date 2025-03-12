"""
Unrestricted Account Creation and Authorization Scanner Module.

This module tests for vulnerabilities related to unrestricted account creation,
unauthorized password changes, and other authorization issues that can lead to 
account enumeration, privilege escalation, and unauthorized access.
"""

import json
import time
import random
import string
from typing import Dict, List, Any, Optional, Tuple

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting unrestricted account creation and authorization vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Get scanner-specific configuration for account creation
        endpoints = config.get("endpoints", [])
        self.endpoint = config.get("endpoint", "/api/users")
        # If endpoints is provided as a list, use the first one
        if endpoints and isinstance(endpoints, list) and len(endpoints) > 0:
            self.endpoint = endpoints[0]
            
        self.method = config.get("method", "POST")
        self.test_count = config.get("test_count", 5)
        self.test_delay = config.get("test_delay", 1.0)
        self.username_field = config.get("username_field", "username")
        self.email_field = config.get("email_field", "email")
        self.password_field = config.get("password_field", "password")
        
        # Additional fields to include in the request
        self.additional_fields = config.get("additional_fields", {})
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201])
        self.success_response_contains = config.get("success_response_contains", [])
        
        # Validation indicators
        self.validation_status_codes = config.get("validation_status_codes", [400, 422])
        self.validation_response_contains = config.get("validation_response_contains", [])
        
        # Rate limiting indicators
        self.rate_limit_status_codes = config.get("rate_limit_status_codes", [429])
        self.rate_limit_response_contains = config.get("rate_limit_response_contains", [])
        
        # Unauthorized password change configuration
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        self.login_endpoint = config.get("login_endpoint", "/users/v1/login")
        self.password_change_endpoint = config.get("password_change_endpoint", "/users/v1/{username}/password")
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using endpoint: {self.endpoint}")
        self.logger.info(f"Using debug endpoint: {self.debug_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using password change endpoint: {self.password_change_endpoint}")
        self.admin_field = config.get("admin_field", "admin")
        self.auth_token_field = config.get("auth_token_field", "auth_token")
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.test_username = config.get("test_username", f"test_user_{timestamp}_{random_suffix}")
        self.test_email = config.get("test_email", f"{self.test_username}@example.com")
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        self.new_password = config.get("new_password", f"NewPass@{timestamp}")
        
        # Debug and simulation mode
        self.debug = config.get("debug", False)
        self.simulate_vulnerabilities = config.get("simulate_vulnerabilities", False)
        
        if self.debug:
            self.logger.info("Debug mode enabled")
            if self.simulate_vulnerabilities:
                self.logger.info("Simulation mode enabled - simulating vulnerabilities")
    
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
        # For account creation, we need to look for both create_user and register endpoints
        self.endpoint = find_endpoint_by_purpose(endpoints, "create_user", self.endpoint)
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        
        # If we didn't find a specific create_user endpoint but found a register endpoint,
        # use the register endpoint for both
        if self.endpoint == "/api/users" and self.register_endpoint != "/users/v1/register":
            self.endpoint = self.register_endpoint
            self.logger.info(f"Using register endpoint as create_user endpoint: {self.endpoint}")
        
        # Find login endpoint for authentication testing
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        
        # Find password change endpoint
        self.password_change_endpoint = find_endpoint_by_purpose(endpoints, "password_change", self.password_change_endpoint)
        
        # Find user info endpoint (often used to verify successful account creation)
        self.user_info_endpoint = find_endpoint_by_purpose(endpoints, "user_info", "/users/v1/me")
        
        # Find debug endpoint
        self.debug_endpoint = find_endpoint_by_purpose(endpoints, "debug", self.debug_endpoint)
        
        # Try to find admin endpoints that might be vulnerable to privilege escalation
        admin_candidates = []
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Look for admin-related patterns in the path
            admin_patterns = ["/admin", "/manage", "/dashboard", "/control"]
            if any(pattern in path.lower() for pattern in admin_patterns):
                admin_candidates.append(path)
                
            # Look for admin-related patterns in tags
            if "tags" in endpoint and endpoint["tags"]:
                for tag in endpoint["tags"]:
                    if "admin" in tag.lower() or "manage" in tag.lower():
                        admin_candidates.append(path)
                        break
        
        if admin_candidates:
            self.admin_endpoints = list(set(admin_candidates))
            self.logger.info(f"Found {len(self.admin_endpoints)} potential admin endpoints")
        else:
            self.admin_endpoints = []
            
        # Look for mobile-specific endpoints
        if "/mobile/" in self.endpoint or "/api/v1/mobile/" in self.endpoint:
            self.logger.info("Detected mobile API endpoint pattern")
            # Adjust expectations for mobile APIs which often have different patterns
            # Mobile APIs often use different field names or structures
            if not self.config.get("mobile_fields_set", False):
                self.username_field = self.config.get("mobile_username_field", "email")
                self.email_field = self.config.get("mobile_email_field", "email")
                self.password_field = self.config.get("mobile_password_field", "password")
                self.config["mobile_fields_set"] = True
                self.logger.info(f"Adjusted field names for mobile API: username={self.username_field}, email={self.email_field}")
        
        # Log the resolved endpoints
        self.logger.info(f"Using endpoint for account creation: {self.endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using password change endpoint: {self.password_change_endpoint}")
        self.logger.info(f"Using user info endpoint: {self.user_info_endpoint if hasattr(self, 'user_info_endpoint') else 'Not found'}")
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        self.password_change_endpoint = find_endpoint_by_purpose(endpoints, "password_change", self.password_change_endpoint)
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info(f"Starting unrestricted account creation and authorization scanner")
        
        # If in simulation mode, add simulated findings directly
        if self.simulate_vulnerabilities:
            self.logger.info("Simulating unrestricted account creation vulnerabilities")
            
            # Ensure endpoint is properly set
            if not self.endpoint:
                self.endpoint = "/api/users"
                self.logger.info(f"Using default endpoint for simulation: {self.endpoint}")
            else:
                self.logger.info(f"Using configured endpoint for simulation: {self.endpoint}")
            
            # Simulate unrestricted account creation with no rate limiting
            self.logger.info("Adding simulated finding: Unrestricted Account Creation - No Rate Limiting")
            self.add_finding(
                vulnerability="Unrestricted Account Creation - No Rate Limiting",
                severity="HIGH",
                endpoint=self.endpoint,
                details="The API does not implement rate limiting for account creation. Successfully created 10 accounts in rapid succession without any restrictions.",
                evidence={
                    "successful_creations": 10,
                    "test_count": 10,
                    "time_between_requests": "0.1 seconds"
                },
                remediation="Implement rate limiting for account creation to prevent abuse and automated account creation attacks."
            )
            
            # Simulate lack of input validation
            self.logger.info("Adding simulated finding: Unrestricted Account Creation - Lack of Input Validation")
            self.add_finding(
                vulnerability="Unrestricted Account Creation - Lack of Input Validation",
                severity="CRITICAL",
                endpoint=self.endpoint,
                details="The API allows account creation with invalid input including SQL injection patterns in the username field. This could potentially lead to SQL injection attacks.",
                evidence={
                    "request": {
                        self.username_field: "' OR 1=1 --",
                        self.email_field: "sqli@example.com",
                        self.password_field: "Test@123456"
                    },
                    "response": {
                        "status_code": 201,
                        "body": "{\"id\": 123, \"username\": \"' OR 1=1 --\", \"email\": \"sqli@example.com\"}"
                    }
                },
                remediation="Implement proper input validation and sanitization for all user registration fields to prevent SQL injection and other injection attacks."
            )
            
            # Simulate username enumeration
            self.logger.info("Adding simulated finding: Unrestricted Account Creation - Username Enumeration")
            self.add_finding(
                vulnerability="Unrestricted Account Creation - Username Enumeration",
                severity="MEDIUM",
                endpoint=self.endpoint,
                details="The API reveals whether a username already exists during account creation, which can be used for user enumeration attacks to discover valid usernames.",
                evidence={
                    "request": {
                        self.username_field: "existing_user",
                        self.email_field: "existing@example.com",
                        self.password_field: "Test@123456"
                    },
                    "response": {
                        "status_code": 400,
                        "body": "{\"error\": \"Username already exists\"}"
                    }
                },
                remediation="Use generic error messages that don't reveal whether a username exists. For example, use 'Invalid registration information' instead of 'Username already exists'."
            )
            
            self.logger.info(f"Added {len(self.findings)} simulated findings for unrestricted account creation")
            return self.findings
        
        # Test for basic account creation
        self._test_basic_account_creation()
        
        # Test for account creation without validation
        self._test_account_creation_without_validation()
        
        # Test for account creation rate limiting
        self._test_account_creation_rate_limiting()
        
        # Test for account enumeration
        self._test_account_enumeration()
        
        # Test for unauthorized password change vulnerability
        self._test_unauthorized_password_change()
        
        # Return findings
        return self.findings
    
    def _test_basic_account_creation(self) -> None:
        """Test for basic account creation functionality."""
        self.logger.info("Testing basic account creation")
        
        # Create a test account
        username = f"test_user_{int(time.time())}"
        email = f"{username}@example.com"
        password = "Test@123456"
        
        payload = {
            self.username_field: username,
            self.email_field: email,
            self.password_field: password
        }
        
        # Add additional fields
        payload.update(self.additional_fields)
        
        try:
            response = self._make_request(
                method=self.method,
                endpoint=self.endpoint,
                json_data=payload
            )
            
            # Check if account creation was successful
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully created test account: {username}")
                
                # Check if response contains expected success indicators
                response_text = response.text.lower()
                all_indicators_found = True
                
                for indicator in self.success_response_contains:
                    if indicator.lower() not in response_text:
                        all_indicators_found = False
                        self.logger.warn(f"Success response does not contain expected indicator: {indicator}")
                
                if all_indicators_found and self.success_response_contains:
                    self.logger.info("Response contains all expected success indicators")
            else:
                self.logger.warn(f"Failed to create test account: {username}, status code: {response.status_code}")
        
        except Exception as e:
            self.logger.error(f"Error testing basic account creation: {str(e)}")
    
    def _test_account_creation_without_validation(self) -> None:
        """Test for account creation without proper validation."""
        self.logger.info("Testing account creation without proper validation")
        
        # Test cases for invalid input
        test_cases = [
            {
                "name": "Empty username",
                "payload": {
                    self.username_field: "",
                    self.email_field: "test@example.com",
                    self.password_field: "Test@123456"
                }
            },
            {
                "name": "Invalid email format",
                "payload": {
                    self.username_field: f"test_user_{int(time.time())}",
                    self.email_field: "invalid-email",
                    self.password_field: "Test@123456"
                }
            },
            {
                "name": "Short password",
                "payload": {
                    self.username_field: f"test_user_{int(time.time())}",
                    self.email_field: f"test{int(time.time())}@example.com",
                    self.password_field: "short"
                }
            },
            {
                "name": "SQL injection in username",
                "payload": {
                    self.username_field: "' OR 1=1 --",
                    self.email_field: f"sqli{int(time.time())}@example.com",
                    self.password_field: "Test@123456"
                }
            },
            {
                "name": "XSS in username",
                "payload": {
                    self.username_field: "<script>alert(1)</script>",
                    self.email_field: f"xss{int(time.time())}@example.com",
                    self.password_field: "Test@123456"
                }
            }
        ]
        
        for test_case in test_cases:
            self.logger.info(f"Testing: {test_case['name']}")
            
            # Add additional fields
            payload = test_case["payload"].copy()
            payload.update(self.additional_fields)
            
            try:
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload
                )
                
                # Check if validation is working
                if response.status_code in self.success_status_codes:
                    # Account was created with invalid input
                    self.add_finding(
                        vulnerability="Unrestricted Account Creation - Lack of Input Validation",
                        severity="HIGH",
                        endpoint=self.endpoint,
                        details=f"The API allows account creation with invalid input: {test_case['name']}",
                        evidence={
                            "request": payload,
                            "response": {
                                "status_code": response.status_code,
                                "headers": dict(response.headers),
                                "body": response.text[:1000]  # Limit response size
                            }
                        },
                        remediation="Implement proper input validation for all user registration fields."
                    )
                elif response.status_code in self.validation_status_codes:
                    # Validation is working as expected
                    self.logger.info(f"Validation working for: {test_case['name']}")
                else:
                    self.logger.warn(f"Unexpected status code {response.status_code} for: {test_case['name']}")
            
            except Exception as e:
                self.logger.error(f"Error testing {test_case['name']}: {str(e)}")
            
            # Add delay between requests
            time.sleep(self.test_delay)
    
    def _test_account_creation_rate_limiting(self) -> None:
        """Test for rate limiting on account creation."""
        self.logger.info("Testing account creation rate limiting")
        
        # Create multiple accounts in rapid succession
        successful_creations = 0
        rate_limited = False
        
        for i in range(self.test_count):
            username = f"test_user_rate_{int(time.time())}_{i}"
            email = f"{username}@example.com"
            password = "Test@123456"
            
            payload = {
                self.username_field: username,
                self.email_field: email,
                self.password_field: password
            }
            
            # Add additional fields
            payload.update(self.additional_fields)
            
            try:
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload
                )
                
                if response.status_code in self.success_status_codes:
                    successful_creations += 1
                elif response.status_code in self.rate_limit_status_codes:
                    rate_limited = True
                    self.logger.info(f"Rate limiting detected after {successful_creations} successful creations")
                    break
                
                # Check response body for rate limit indicators
                if not rate_limited:
                    response_text = response.text.lower()
                    for indicator in self.rate_limit_response_contains:
                        if indicator.lower() in response_text:
                            rate_limited = True
                            self.logger.info(f"Rate limiting detected from response body after {successful_creations} successful creations")
                            break
                
                if rate_limited:
                    break
            
            except Exception as e:
                self.logger.error(f"Error testing rate limiting: {str(e)}")
                break
        
        # Check if rate limiting is implemented
        if not rate_limited and successful_creations >= self.test_count:
            self.add_finding(
                vulnerability="Unrestricted Account Creation - No Rate Limiting",
                severity="MEDIUM",
                endpoint=self.endpoint,
                details=f"The API does not implement rate limiting for account creation. Successfully created {successful_creations} accounts in rapid succession.",
                evidence={
                    "successful_creations": successful_creations,
                    "test_count": self.test_count
                },
                remediation="Implement rate limiting for account creation to prevent abuse."
            )
    
    def _test_account_enumeration(self) -> None:
        """Test for account enumeration during account creation."""
        self.logger.info("Testing for account enumeration")
        
        # Create an initial account
        username = f"enum_user_{int(time.time())}"
        email = f"{username}@example.com"
        password = "Test@123456"
        
        payload = {
            self.username_field: username,
            self.email_field: email,
            self.password_field: password
        }
        
        # Add additional fields
        payload.update(self.additional_fields)
        
        try:
            # Create the initial account
            response = self._make_request(
                method=self.method,
                endpoint=self.endpoint,
                json_data=payload
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Created initial account for enumeration test: {username}")
                
                # Try to create the same account again
                time.sleep(self.test_delay)
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload
                )
                
                # Check if the response reveals that the username/email already exists
                response_text = response.text.lower()
                username_indicators = ["username already exists", "username taken", "username is already in use"]
                email_indicators = ["email already exists", "email taken", "email is already in use", "email already registered"]
                
                username_enumeration = any(indicator in response_text for indicator in username_indicators)
                email_enumeration = any(indicator in response_text for indicator in email_indicators)
                
                if username_enumeration:
                    self.add_finding(
                        vulnerability="Unrestricted Account Creation - Username Enumeration",
                        severity="MEDIUM",
                        endpoint=self.endpoint,
                        details="The API reveals whether a username already exists during account creation, which can be used for user enumeration attacks.",
                        evidence={
                            "request": payload,
                            "response": {
                                "status_code": response.status_code,
                                "body": response.text[:1000]  # Limit response size
                            }
                        },
                        remediation="Use generic error messages that don't reveal whether a username exists."
                    )
                
                if email_enumeration:
                    self.add_finding(
                        vulnerability="Unrestricted Account Creation - Email Enumeration",
                        severity="MEDIUM",
                        endpoint=self.endpoint,
                        details="The API reveals whether an email already exists during account creation, which can be used for user enumeration attacks.",
                        evidence={
                            "request": payload,
                            "response": {
                                "status_code": response.status_code,
                                "body": response.text[:1000]  # Limit response size
                            }
                        },
                        remediation="Use generic error messages that don't reveal whether an email exists."
                    )
            
        except Exception as e:
            self.logger.error(f"Error testing account enumeration: {str(e)}")
    
    def _test_unauthorized_password_change(self) -> None:
        """Test for unauthorized password change vulnerability."""
        self.logger.info("Testing for unauthorized password change vulnerability")
        
        # Step 1: Get the list of existing accounts through debug endpoint
        self.logger.info(f"Retrieving existing accounts from {self.debug_endpoint}")
        existing_accounts = self._get_existing_accounts()
        if not existing_accounts:
            self.logger.warn("Failed to retrieve existing accounts, skipping unauthorized password change test")
            return
        
        # Step 2: Register a new user with admin privileges
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
            
            if register_response.status_code not in self.success_status_codes:
                self.logger.warn(f"Failed to register test user, status code: {register_response.status_code}")
                self.logger.debug(f"Response: {register_response.text}")
                return
            
            self.logger.info(f"Successfully registered test user '{self.test_username}'")
            self.logger.debug(f"Registration response: {register_response.text}")
            
            # Step 3: Verify the new account was created
            time.sleep(self.test_delay)
            self.logger.info("Verifying test user was created")
            updated_accounts = self._get_existing_accounts()
            
            test_user_created = False
            for account in updated_accounts:
                if account.get(self.username_field) == self.test_username:
                    test_user_created = True
                    self.logger.info(f"Verified test user '{self.test_username}' was created successfully")
                    break
            
            if not test_user_created:
                self.logger.warn(f"Test user '{self.test_username}' was not found in the user list")
                return
            
            # Step 4: Login as the new user to get auth token
            self.logger.info(f"Logging in as test user '{self.test_username}'")
            login_payload = {
                self.username_field: self.test_username,
                self.password_field: self.test_password
            }
            
            login_response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=login_payload
            )
            
            if login_response.status_code not in self.success_status_codes:
                self.logger.warn(f"Failed to login as test user, status code: {login_response.status_code}")
                self.logger.debug(f"Login response: {login_response.text}")
                return
            
            # Extract auth token from response
            try:
                login_data = login_response.json()
                auth_token = login_data.get(self.auth_token_field)
                
                if not auth_token:
                    self.logger.warn(f"Auth token not found in login response: {login_data}")
                    return
                
                self.logger.info(f"Successfully logged in as test user and obtained auth token")
                self.logger.debug(f"Auth token: {auth_token}")
                
                # Step 5: Attempt to change another user's password
                # Find a target user that is not our test user
                target_user = None
                for account in existing_accounts:
                    if account.get(self.username_field) != self.test_username:
                        target_user = account.get(self.username_field)
                        break
                
                if not target_user:
                    self.logger.warn("No target user found to test password change")
                    return
                
                self.logger.info(f"Attempting to change password for user '{target_user}'")
                password_change_endpoint = self.password_change_endpoint.replace("{username}", target_user)
                
                password_change_payload = {
                    self.password_field: self.new_password
                }
                
                # Set up authorization header with the token
                headers = {"Authorization": f"Bearer {auth_token}"}
                
                password_change_response = self._make_request(
                    method="PUT",
                    endpoint=password_change_endpoint,
                    json_data=password_change_payload,
                    headers=headers
                )
                
                # Step 6: Check if the password change was successful
                if password_change_response.status_code in self.success_status_codes:
                    self.logger.info(f"Password change request for user '{target_user}' was accepted")
                    
                    # Step 7: Verify the password was actually changed by trying to login
                    self.logger.info(f"Verifying password change by attempting to login as '{target_user}'")
                    verify_login_payload = {
                        self.username_field: target_user,
                        self.password_field: self.new_password
                    }
                    
                    verify_login_response = self._make_request(
                        method="POST",
                        endpoint=self.login_endpoint,
                        json_data=verify_login_payload
                    )
                    
                    if verify_login_response.status_code in self.success_status_codes:
                        # Successfully logged in with the new password - vulnerability confirmed
                        self.logger.info(f"Successfully logged in as '{target_user}' with the new password - vulnerability confirmed!")
                        
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
                                    "payload": password_change_payload
                                },
                                "password_change_response": {
                                    "status_code": password_change_response.status_code,
                                    "body": password_change_response.text[:1000]  # Limit response size
                                },
                                "verification": {
                                    "login_status_code": verify_login_response.status_code,
                                    "login_response": verify_login_response.text[:1000]  # Limit response size
                                }
                            },
                            remediation="Implement proper authorization checks to ensure users can only change their own passwords. Verify the user's identity from the authentication token and compare it with the requested resource."
                        )
                    else:
                        self.logger.info(f"Could not login as '{target_user}' with the new password. Password change might not have been successful.")
                        self.logger.debug(f"Verification login response: {verify_login_response.text}")
                else:
                    self.logger.info(f"Password change request was rejected with status code: {password_change_response.status_code}")
                    self.logger.debug(f"Password change response: {password_change_response.text}")
            
            except (ValueError, KeyError) as e:
                self.logger.error(f"Error parsing login response: {str(e)}")
        
        except Exception as e:
            self.logger.error(f"Error testing unauthorized password change: {str(e)}")
    
    def _get_existing_accounts(self) -> List[Dict[str, Any]]:
        """Get the list of existing accounts from the debug endpoint."""
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
                        return data["users"]
                    elif isinstance(data, list):
                        return data
                    else:
                        self.logger.warn(f"Unexpected format in debug endpoint response: {data}")
                        return []
                except (ValueError, KeyError) as e:
                    self.logger.error(f"Error parsing debug endpoint response: {str(e)}")
                    return []
            else:
                self.logger.warn(f"Failed to get existing accounts, status code: {response.status_code}")
                return []
        except Exception as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
            return []
