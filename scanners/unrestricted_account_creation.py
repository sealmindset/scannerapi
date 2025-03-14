"""
Unrestricted Account Creation and Authorization Scanner Module.

This module tests for vulnerabilities related to unrestricted account creation,
unauthorized password changes, and other authorization issues that can lead to 
account enumeration, privilege escalation, and unauthorized access.

Enhanced to detect vulnerabilities across different API structures, including:
- RESTful APIs with /auth/sign-up and /auth/sign-in patterns (like Snorefox API)
- Traditional APIs with /users or /register endpoints
- Mobile-specific API endpoints
- APIs with different field naming conventions
"""

import json
import time
import random
import string
import re
import os
import base64
from typing import Dict, List, Any, Optional, Tuple, Set, Union

# Import the account cache
try:
    from core.account_cache import account_cache
except ImportError:
    # For backwards compatibility, create a simple in-memory cache if the module doesn't exist
    class SimpleCache:
        def __init__(self):
            self.accounts = []
        
        def add_account(self, account):
            self.accounts.append(account)
        
        def get_account(self, endpoint=None):
            return self.accounts[0] if self.accounts else None
        
        def get_all_accounts(self):
            return self.accounts
    
    account_cache = SimpleCache()

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
        
        # Enhanced test configuration with higher default values for better detection
        self.test_count = config.get("test_count", 15)  # Increased from 5 to 15 for better detection
        self.test_delay = config.get("test_delay", 0.5)  # Reduced from 1.0 to 0.5 for faster testing
        
        # Rate limiting adaptation configuration
        self.adapt_to_rate_limiting = config.get("adapt_to_rate_limiting", True)  # Auto-adjust to rate limiting
        self.initial_delay = self.test_delay  # Store initial delay for reference
        self.max_delay = config.get("max_delay", 10.0)  # Maximum delay to try (in seconds)
        self.min_delay = config.get("min_delay", 0.1)  # Minimum delay to try (in seconds)
        self.delay_increment = config.get("delay_increment", 0.5)  # How much to increase delay when rate limited
        self.delay_decrement = config.get("delay_decrement", 0.1)  # How much to decrease delay when testing optimal rate
        self.success_threshold = config.get("success_threshold", 3)  # Number of successful requests needed to confirm a working rate
        
        # Aggressive test configuration for rate limiting detection
        self.aggressive_test_count = config.get("aggressive_test_count", 30)  # For aggressive testing
        self.aggressive_test_delay = config.get("aggressive_test_delay", 0.1)  # Very short delay for aggressive testing
        
        # Field names with better defaults
        self.username_field = config.get("username_field", "username")
        self.email_field = config.get("email_field", "email")
        self.password_field = config.get("password_field", "password")
        
        # Additional fields to include in the request
        self.additional_fields = config.get("additional_fields", {})
        
        # Track successful creation rates
        self.creation_rates = []  # Will store tuples of (delay, requests_per_second)
        
        # Success indicators with expanded defaults
        self.success_status_codes = config.get("success_status_codes", [200, 201, 202, 204])
        self.success_response_contains = config.get("success_response_contains", [])
        
        # Validation indicators with expanded defaults
        self.validation_status_codes = config.get("validation_status_codes", [400, 422, 409, 403])
        self.validation_response_contains = config.get("validation_response_contains", [])
        
        # Rate limiting indicators with expanded detection patterns
        self.rate_limit_status_codes = config.get("rate_limit_status_codes", [429, 403, 503])
        self.rate_limit_response_contains = config.get("rate_limit_response_contains", [
            "rate limit", "too many requests", "try again later", "throttled", 
            "slow down", "too many attempts", "too frequent", "wait", "limit exceeded"
        ])
        
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
        
        # Admin and auth fields
        self.admin_field = config.get("admin_field", "admin")
        self.auth_token_field = config.get("auth_token_field", "auth_token")
        
        # Test user credentials with better randomization
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.test_username = config.get("test_username", f"test_user_{timestamp}_{random_suffix}")
        self.test_email = config.get("test_email", f"{self.test_username}@example.com")
        
        # More complex password that meets common requirements
        self.test_password = config.get("test_password", f"Test@{timestamp}#{random_suffix}")
        self.new_password = config.get("new_password", f"NewPass@{timestamp}#{random_suffix}")
        
        # Debug and simulation mode
        self.debug = config.get("debug", False)
        self.simulate_vulnerabilities = config.get("simulate_vulnerabilities", False)
        
        # Track successful account creations for later use
        self.created_accounts = []
        
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
        
        # Enhanced endpoint detection for account creation/registration
        # Look for both standard patterns and RESTful API patterns like Snorefox
        register_patterns = [
            "create_user", "register", "signup", "sign-up", "sign_up", 
            "auth/sign-up", "auth/signup", "auth/register", "users/create",
            "account/create", "account/register", "new-user", "new-account"
        ]
        
        # Find registration endpoint with improved pattern matching
        best_register_endpoint = self.register_endpoint
        best_score = 0
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            description = endpoint.get("description", "").lower()
            summary = endpoint.get("summary", "").lower()
            operation_id = endpoint.get("operationId", "").lower()
            
            # Only consider POST methods for registration
            if method != "POST":
                continue
                
            score = 0
            # Check path for registration patterns
            for pattern in register_patterns:
                if pattern in path.lower():
                    score += 3
                    
            # Check description, summary, and operationId
            for pattern in ["register", "signup", "sign up", "sign-up", "create user", "create account"]:
                if pattern in description:
                    score += 2
                if pattern in summary:
                    score += 2
                if pattern in operation_id:
                    score += 2
            
            # Check for request body parameters that indicate registration
            if "requestBody" in endpoint:
                schema = endpoint.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
                properties = schema.get("properties", {})
                
                # Check for common registration fields
                for field in ["username", "email", "password", "name", "firstName", "lastName"]:
                    if field in properties:
                        score += 1
                        
                # If we have at least 3 registration-related fields, this is likely a registration endpoint
                if score >= 3:
                    score += 3
            
            if score > best_score:
                best_score = score
                best_register_endpoint = path
        
        # Update endpoints if we found better matches
        if best_score > 0:
            self.register_endpoint = best_register_endpoint
            self.endpoint = best_register_endpoint  # Use the same endpoint for account creation
            self.logger.info(f"Found registration endpoint with score {best_score}: {best_register_endpoint}")
        
        # Enhanced login endpoint detection
        login_patterns = [
            "login", "signin", "sign-in", "sign_in", "auth", "authenticate",
            "auth/sign-in", "auth/login", "session", "token"
        ]
        
        best_login_endpoint = self.login_endpoint
        best_score = 0
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            description = endpoint.get("description", "").lower()
            summary = endpoint.get("summary", "").lower()
            operation_id = endpoint.get("operationId", "").lower()
            
            # Only consider POST methods for login
            if method != "POST":
                continue
                
            score = 0
            # Check path for login patterns
            for pattern in login_patterns:
                if pattern in path.lower():
                    score += 3
                    
            # Check description, summary, and operationId
            for pattern in ["login", "signin", "sign in", "sign-in", "authenticate", "auth"]:
                if pattern in description:
                    score += 2
                if pattern in summary:
                    score += 2
                if pattern in operation_id:
                    score += 2
            
            # Check for request body parameters that indicate login
            if "requestBody" in endpoint:
                schema = endpoint.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
                properties = schema.get("properties", {})
                
                # Check for common login fields
                login_fields = ["username", "email", "password", "token"]
                for field in login_fields:
                    if field in properties:
                        score += 1
                
                # If we have username/email and password, this is likely a login endpoint
                if ("username" in properties or "email" in properties) and "password" in properties:
                    score += 3
            
            if score > best_score:
                best_score = score
                best_login_endpoint = path
        
        if best_score > 0:
            self.login_endpoint = best_login_endpoint
            self.logger.info(f"Found login endpoint with score {best_score}: {best_login_endpoint}")
        
        # Find password change endpoint with improved detection
        password_patterns = [
            "password", "change-password", "reset-password", "update-password",
            "users/*/password", "auth/password", "me/password", "users/me/password"
        ]
        
        best_password_endpoint = self.password_change_endpoint
        best_score = 0
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Password change endpoints are typically PUT or POST
            if method not in ["PUT", "POST", "PATCH"]:
                continue
                
            score = 0
            # Check path for password patterns
            for pattern in password_patterns:
                if pattern in path.lower():
                    score += 3
            
            if score > best_score:
                best_score = score
                best_password_endpoint = path
        
        if best_score > 0:
            self.password_change_endpoint = best_password_endpoint
            self.logger.info(f"Found password change endpoint with score {best_score}: {best_password_endpoint}")
        
        # Find user info endpoint (often used to verify successful account creation)
        user_info_patterns = [
            "me", "profile", "user-info", "userinfo", "current-user",
            "users/me", "auth/me", "user/profile", "account/profile"
        ]
        
        best_user_info_endpoint = "/users/v1/me"  # Default
        best_score = 0
        
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # User info endpoints are typically GET
            if method != "GET":
                continue
                
            score = 0
            # Check path for user info patterns
            for pattern in user_info_patterns:
                if pattern in path.lower():
                    score += 3
            
            if score > best_score:
                best_score = score
                best_user_info_endpoint = path
        
        if best_score > 0:
            self.user_info_endpoint = best_user_info_endpoint
            self.logger.info(f"Found user info endpoint with score {best_score}: {best_user_info_endpoint}")
        
        # Try to find admin endpoints that might be vulnerable to privilege escalation
        admin_candidates = []
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Look for admin-related patterns in the path
            admin_patterns = ["/admin", "/manage", "/dashboard", "/control", "/settings"]
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
        
        # Detect API field naming conventions by analyzing request bodies
        self._detect_field_naming_conventions(endpoints)
        
        # Log the resolved endpoints
        self.logger.info(f"Using endpoint for account creation: {self.endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using password change endpoint: {self.password_change_endpoint}")
        self.logger.info(f"Using user info endpoint: {self.user_info_endpoint if hasattr(self, 'user_info_endpoint') else 'Not found'}")
    
    def _detect_field_naming_conventions(self, endpoints: List[Dict[str, Any]]) -> None:
        """
        Detect API field naming conventions by analyzing request bodies.
        
        Args:
            endpoints: List of endpoints from OpenAPI specification
        """
        # Skip if already configured
        if self.config.get("field_names_detected", False):
            return
            
        # Collect all property names from request bodies
        all_properties = {}
        
        for endpoint in endpoints:
            if "requestBody" not in endpoint:
                continue
                
            schema = endpoint.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {})
            properties = schema.get("properties", {})
            
            for prop_name, prop_details in properties.items():
                prop_type = prop_details.get("type", "")
                prop_description = prop_details.get("description", "").lower()
                
                if prop_name not in all_properties:
                    all_properties[prop_name] = {
                        "count": 0,
                        "types": set(),
                        "descriptions": []
                    }
                
                all_properties[prop_name]["count"] += 1
                all_properties[prop_name]["types"].add(prop_type)
                if prop_description:
                    all_properties[prop_name]["descriptions"].append(prop_description)
        
        # Detect username field
        username_candidates = [
            "username", "userName", "user_name", "login", "loginId", "login_id",
            "userId", "user_id", "email", "emailAddress", "email_address"
        ]
        
        for field in username_candidates:
            if field in all_properties:
                self.username_field = field
                self.logger.info(f"Detected username field: {field}")
                break
        
        # Detect email field
        email_candidates = [
            "email", "emailAddress", "email_address", "userEmail", "user_email",
            "mail", "contact_email", "contactEmail"
        ]
        
        for field in email_candidates:
            if field in all_properties:
                self.email_field = field
                self.logger.info(f"Detected email field: {field}")
                break
        
        # Detect password field
        password_candidates = [
            "password", "passwd", "pass", "userPassword", "user_password",
            "pwd", "secret", "credentials"
        ]
        
        for field in password_candidates:
            if field in all_properties:
                self.password_field = field
                self.logger.info(f"Detected password field: {field}")
                break
        
        # Mark as detected
        self.config["field_names_detected"] = True
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
        
        # Test for JWT authentication bypass
        self.logger.info("Testing JWT authentication bypass for account creation")
        self._test_jwt_bypass_account_creation_restrictions()
        
        # Test for account enumeration
        self._test_account_enumeration()
        
        # Test for unauthorized password change vulnerability
        self._test_unauthorized_password_change()
        
        # Return findings
        return self.findings
    
    def _test_jwt_bypass_account_creation_restrictions(self) -> None:
        """
        Test if forged JWT tokens can be used to bypass account creation restrictions.
        
        This test checks if the API incorrectly trusts forged JWTs to bypass authentication
        requirements for account creation, allowing attackers to create accounts when
        authentication should be required.
        """
        self.logger.info("Testing for JWT manipulation to bypass account creation restrictions")
        
        # Step 1: First try to create an account without authentication to see if auth is required
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        username = f"test_user_{timestamp}_{random_suffix}"
        email = f"{username}@example.com"
        password = "Test@123456"
        
        # For Snorefox API, include all required fields
        payload = {
            self.username_field: email,
            self.email_field: email,
            self.password_field: password
        }
        
        # Add additional fields
        payload.update(self.additional_fields)
        
        # Make a request without authentication to check if auth is required
        try:
            self.logger.info("Testing account creation without authentication")
            unauthenticated_response = self._make_request(
                method=self.method,
                endpoint=self.endpoint,
                json_data=payload
            )
            
            # Check if authentication is required (expecting 401, 403, or 404 with auth required message)
            auth_required = False
            auth_required_indicators = ["auth", "authentication", "token", "jwt", "login", "unauthorized", "forbidden"]
            
            if unauthenticated_response.status_code in [401, 403, 404]:
                auth_required = True
                self.logger.info(f"Authentication appears to be required for account creation: {unauthenticated_response.status_code}")
                
                # Check response body for auth required messages
                if unauthenticated_response.text:
                    response_text = unauthenticated_response.text.lower()
                    if any(indicator in response_text for indicator in auth_required_indicators):
                        self.logger.info(f"Response confirms authentication is required: {unauthenticated_response.text[:100]}")
            
            # For testing purposes, always proceed with JWT bypass tests
            # This ensures we test for JWT vulnerabilities even when authentication doesn't appear to be required
            # Comment: We're removing the early return to ensure tests run in all cases
            # if not auth_required:
            #     self.logger.info("Authentication does not appear to be required for account creation, skipping JWT bypass test")
            #     return
                
            # Step 2: Create a test account to get a valid JWT token for manipulation
            # We'll use a different endpoint or method to create this initial account
            self.logger.info("Creating a test account to obtain a valid JWT token")
            
            # Try to create an account normally (this might work through a different flow)
            initial_account_email = f"test_initial_{timestamp}@example.com"
            initial_account_payload = {
                self.username_field: initial_account_email,
                self.email_field: initial_account_email,
                self.password_field: password
            }
            initial_account_payload.update(self.additional_fields)
            
            # Try to create the initial account (this might fail if auth is required)
            initial_response = self._make_request(
                method=self.method,
                endpoint=self.endpoint,
                json_data=initial_account_payload
            )
            
            # If we couldn't create an account, we'll need to find another way to get a token
            # For example, we might need to use a pre-existing account or a different endpoint
            auth_token = None
            
            if initial_response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully created initial test account: {initial_account_email}")
                
                # Now try to login to get a JWT token
                login_payload = {
                    self.username_field: initial_account_email,
                    self.password_field: password
                }
                
                login_response = self._make_request(
                    method="POST",
                    endpoint=self.login_endpoint,
                    json_data=login_payload
                )
                
                if login_response.status_code in self.success_status_codes:
                    auth_token = self._extract_token_from_response(login_response)
            
            # If we couldn't get a token through normal means, try to create a completely forged token
            if not auth_token or not self._is_jwt_token(auth_token):
                self.logger.info("Could not obtain a valid JWT token through normal means, creating a completely forged token")
                # Create a completely forged token with common claims
                auth_token = self._create_completely_forged_token()
            
            if not auth_token:
                self.logger.warning("Failed to create or obtain any JWT token for testing")
                return
                
            self.logger.info(f"Successfully obtained/created JWT token: {auth_token[:20]}...")
            
            # Step 3: Test various forged tokens to see if they can bypass authentication requirements
            # Test 1: 'none' algorithm attack
            none_algorithm_token = self._create_none_algorithm_token(auth_token)
            self._test_forged_token_for_auth_bypass(none_algorithm_token, "'none' algorithm")
            
            # Test 2: Algorithm switching attack (RS256 to HS256)
            alg_switch_token = self._create_algorithm_switch_token(auth_token)
            self._test_forged_token_for_auth_bypass(alg_switch_token, "algorithm switching (RS256 to HS256)")
            
            # Test 3: Modified payload claims (adding admin role)
            admin_token = self._create_admin_role_token(auth_token)
            self._test_forged_token_for_auth_bypass(admin_token, "modified payload (added admin role)")
            
            # Test 4: Completely forged token with common claims
            forged_token = self._create_completely_forged_token()
            self._test_forged_token_for_auth_bypass(forged_token, "completely forged token")
            
        except Exception as e:
            self.logger.error(f"Error testing JWT bypass for account creation: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def _extract_token_from_response(self, response) -> Optional[str]:
        """
        Extract JWT token from login response.
        
        Args:
            response: The login response
            
        Returns:
            The JWT token if found, None otherwise
        """
        try:
            data = response.json()
            
            # Try common token field names
            for field in ["token", "access_token", "accessToken", "jwt", "auth_token", "authToken"]:
                if field in data and isinstance(data[field], str):
                    return data[field]
            
            # Try nested structures
            for outer_key in ["data", "result", "response", "user", "auth"]:
                if outer_key in data and isinstance(data[outer_key], dict):
                    nested_data = data[outer_key]
                    for field in ["token", "access_token", "accessToken", "jwt", "auth_token"]:
                        if field in nested_data and isinstance(nested_data[field], str):
                            return nested_data[field]
            
            # Look for any string that looks like a JWT
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 40 and '.' in value and value.count('.') >= 2:
                    return value
                    
            return None
        except Exception as e:
            self.logger.error(f"Error extracting token from response: {str(e)}")
            return None
    
    def _is_jwt_token(self, token: str) -> bool:
        """
        Check if a token is a valid JWT.
        
        Args:
            token: The token to check
            
        Returns:
            True if the token is a JWT, False otherwise
        """
        if not token:
            return False
            
        # JWT tokens have three parts separated by dots: header.payload.signature
        parts = token.split('.')
        if len(parts) != 3:
            return False
            
        # Try to decode the header and payload
        try:
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            
            # Check if it has typical JWT header fields
            if not ("alg" in header and "typ" in header):
                return False
                
            # Try to decode the payload
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Check if it has typical JWT payload fields
            jwt_fields = ["sub", "iat", "exp", "iss", "aud", "nbf", "jti"]
            found_fields = 0
            for field in jwt_fields:
                if field in payload:
                    found_fields += 1
                    
            # If it has at least 1 typical JWT field, consider it a JWT
            return found_fields >= 1
        except Exception as e:
            self.logger.debug(f"Error checking JWT token: {str(e)}")
            return False
    
    def _decode_jwt_part(self, encoded_part: str) -> str:
        """
        Decode a base64url-encoded part of a JWT.
        
        Args:
            encoded_part: The encoded part to decode
            
        Returns:
            The decoded string
        """
        # Convert from base64url to base64
        encoded_part = encoded_part.replace('-', '+').replace('_', '/')
        
        # Add padding if needed
        padding_needed = len(encoded_part) % 4
        if padding_needed:
            encoded_part += '=' * (4 - padding_needed)
            
        # Decode
        return base64.b64decode(encoded_part).decode('utf-8')
    
    def _encode_jwt_part(self, data: Dict[str, Any]) -> str:
        """
        Encode a dictionary as a base64url-encoded JWT part.
        
        Args:
            data: The data to encode
            
        Returns:
            The encoded string
        """
        # Convert to JSON
        json_str = json.dumps(data, separators=(',', ':'))
        
        # Encode to base64
        encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        
        # Convert to base64url
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')
    
    def _create_none_algorithm_token(self, token: str) -> str:
        """
        Create a forged token using the 'none' algorithm attack.
        
        Args:
            token: The original token
            
        Returns:
            The forged token
        """
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Create a new token with 'none' algorithm
            modified_header = header.copy()
            modified_header['alg'] = 'none'
            new_header = self._encode_jwt_part(modified_header)
            new_payload = self._encode_jwt_part(payload)
            
            # Create the modified token without a signature
            modified_token = f"{new_header}.{new_payload}."
            
            self.logger.info(f"Created 'none' algorithm token: {modified_token[:30]}...")
            return modified_token
        except Exception as e:
            self.logger.error(f"Error creating 'none' algorithm token: {str(e)}")
            return token
    
    def _create_algorithm_switch_token(self, token: str) -> str:
        """
        Create a forged token using the algorithm switching attack (RS256 to HS256).
        
        Args:
            token: The original token
            
        Returns:
            The forged token
        """
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Create a new token with switched algorithm
            modified_header = header.copy()
            if modified_header.get('alg') == 'RS256':
                modified_header['alg'] = 'HS256'
            elif modified_header.get('alg') == 'ES256':
                modified_header['alg'] = 'HS256'
            else:
                modified_header['alg'] = 'HS256'  # Default to HS256
                
            new_header = self._encode_jwt_part(modified_header)
            new_payload = self._encode_jwt_part(payload)
            
            # For simplicity, we're using an empty signature
            # In a real attack, the attacker would sign with the public key as the secret
            modified_token = f"{new_header}.{new_payload}.{parts[2]}"
            
            self.logger.info(f"Created algorithm switch token: {modified_token[:30]}...")
            return modified_token
        except Exception as e:
            self.logger.error(f"Error creating algorithm switch token: {str(e)}")
            return token
    
    def _create_admin_role_token(self, token: str) -> str:
        """
        Create a forged token by modifying the payload to add admin privileges.
        
        Args:
            token: The original token
            
        Returns:
            The forged token
        """
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Modify the payload to add admin privileges
            modified_payload = payload.copy()
            
            # Try common role/privilege field names
            for field_name in ['role', 'roles', 'permissions', 'groups', 'authorities', 'scopes', 'claims']:
                if field_name in modified_payload:
                    if isinstance(modified_payload[field_name], str):
                        modified_payload[field_name] = 'admin'
                    elif isinstance(modified_payload[field_name], list):
                        if 'admin' not in modified_payload[field_name]:
                            modified_payload[field_name].append('admin')
            
            # If no role field found, add common ones
            if 'role' not in modified_payload:
                modified_payload['role'] = 'admin'
            if 'isAdmin' not in modified_payload:
                modified_payload['isAdmin'] = True
            if 'admin' not in modified_payload:
                modified_payload['admin'] = True
                
            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(modified_payload)
            
            # For simplicity, we're using the original signature
            # In a real attack, this would likely be invalid, but we're testing if the API verifies signatures
            modified_token = f"{new_header}.{new_payload}.{parts[2]}"
            
            self.logger.info(f"Created admin role token: {modified_token[:30]}...")
            return modified_token
        except Exception as e:
            self.logger.error(f"Error creating admin role token: {str(e)}")
            return token
    
    def _create_rate_limit_bypass_token(self, token: str) -> str:
        """
        Create a forged token by modifying the payload to add rate limit bypass claims.
        
        Args:
            token: The original token
            
        Returns:
            The forged token
        """
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Modify the payload to add rate limit bypass claims
            modified_payload = payload.copy()
            
            # Add common rate limiting bypass claims
            modified_payload['bypassRateLimit'] = True
            modified_payload['rateLimit'] = 0
            modified_payload['noLimit'] = True
            modified_payload['unlimited'] = True
            modified_payload['premium'] = True
            modified_payload['verified'] = True
            
            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(modified_payload)
            
            # For simplicity, we're using the original signature
            modified_token = f"{new_header}.{new_payload}.{parts[2]}"
            
            self.logger.info(f"Created rate limit bypass token: {modified_token[:30]}...")
            return modified_token
        except Exception as e:
            self.logger.error(f"Error creating rate limit bypass token: {str(e)}")
            return token
    
    def _test_rate_limiting_with_token(self, auth_token: str) -> bool:
        """
        Test if rate limiting is in place for account creation with a legitimate token.
        
        Args:
            auth_token: The authentication token to use
            
        Returns:
            True if rate limiting was detected, False otherwise
        """
        self.logger.info("Testing if rate limiting is in place for account creation")
        
        # Try to create multiple accounts in rapid succession
        success_count = 0
        failure_count = 0
        max_attempts = 10
        
        for i in range(max_attempts):
            timestamp = int(time.time())
            random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
            username = f"test_user_{timestamp}_{random_suffix}_{i}"
            email = f"{username}@example.com"
            password = "Test@123456"
            
            payload = {
                self.username_field: email,
                self.email_field: email,
                self.password_field: password
            }
            payload.update(self.additional_fields)
            
            try:
                # Add the auth token to the request
                headers = {"Authorization": f"Bearer {auth_token}"}
                
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload,
                    headers=headers
                )
                
                if response.status_code in self.success_status_codes:
                    success_count += 1
                    self.logger.info(f"Successfully created account {i+1}/{max_attempts}: {email}")
                else:
                    failure_count += 1
                    self.logger.info(f"Failed to create account {i+1}/{max_attempts}: {email}, status code: {response.status_code}")
                    
                    # Check for rate limiting indicators in the response
                    rate_limit_indicators = [
                        "rate limit", "ratelimit", "too many requests", "try again later",
                        "slow down", "too frequent", "too fast", "429"
                    ]
                    
                    response_text = response.text.lower()
                    for indicator in rate_limit_indicators:
                        if indicator in response_text or response.status_code == 429:
                            self.logger.info(f"Rate limiting detected: {response.status_code} - {response.text[:100]}")
                            return True
            except Exception as e:
                self.logger.error(f"Error creating account {i+1}/{max_attempts}: {str(e)}")
                failure_count += 1
            
            # No delay to trigger rate limiting
        
        # If we had more failures than successes, and we had at least some successes,
        # it's likely that rate limiting is in place
        if failure_count > success_count and success_count > 0:
            self.logger.info(f"Rate limiting likely in place: {success_count} successes, {failure_count} failures")
            return True
        
        self.logger.info(f"No rate limiting detected: {success_count} successes, {failure_count} failures")
        return False
    
    def _test_forged_token_for_account_creation(self, forged_token: str, attack_type: str) -> None:
        """
        Test if a forged token can be used to bypass account creation restrictions.
        
        Args:
            forged_token: The forged token to test
            attack_type: The type of attack being tested
        """
        self.logger.info(f"Testing if {attack_type} token can bypass account creation restrictions")
        
        # Try to create multiple accounts in rapid succession with the forged token
        success_count = 0
        max_attempts = 10
        evidence = []
        
        for i in range(max_attempts):
            timestamp = int(time.time())
            random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
            username = f"test_user_{timestamp}_{random_suffix}_{i}"
            email = f"{username}@example.com"
            password = "Test@123456"
            
            payload = {
                self.username_field: email,
                self.email_field: email,
                self.password_field: password
            }
            payload.update(self.additional_fields)
            
            try:
                # Add the forged token to the request
                headers = {"Authorization": f"Bearer {forged_token}"}
                
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload,
                    headers=headers
                )
                
                if response.status_code in self.success_status_codes:
                    success_count += 1
                    self.logger.info(f"Successfully created account with forged token {i+1}/{max_attempts}: {email}")
                    
                    # Add to evidence
                    evidence.append({
                        "request": {
                            "method": self.method,
                            "endpoint": self.endpoint,
                            "token_type": attack_type,
                            "payload": payload
                        },
                        "response": {
                            "status_code": response.status_code,
                            "body": response.text[:200] + ("..." if len(response.text) > 200 else "")
                        }
                    })
                else:
                    self.logger.info(f"Failed to create account with forged token {i+1}/{max_attempts}: {email}, status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error creating account with forged token {i+1}/{max_attempts}: {str(e)}")
            
            # No delay to test if rate limiting is bypassed
        
        # If we were able to create multiple accounts successfully, it's likely that
        # the forged token allowed bypassing rate limiting
        if success_count >= 5:  # If we created at least half of the accounts successfully
            self.logger.warning(f"JWT {attack_type} attack successful for bypassing account creation restrictions!")
            
            self.add_finding(
                vulnerability=f"JWT {attack_type.capitalize()} Bypass for Account Creation Restrictions",
                details=f"The application accepts forged JWT tokens using {attack_type} attack, allowing bypass of rate limiting or other restrictions on account creation. This could be exploited to create large numbers of accounts rapidly.",
                severity="CRITICAL",
                endpoint=self.endpoint,
                evidence={
                    "attack_type": attack_type,
                    "forged_token": forged_token[:50] + "...",  # Truncate for readability
                    "success_rate": f"{success_count}/{max_attempts}",
                    "test_examples": evidence[:3]  # Include up to 3 examples in the evidence
                },
                remediation="Implement proper JWT validation including signature verification, algorithm validation, and claims checking. Never accept 'none' algorithm tokens and ensure proper key management for asymmetric algorithms. Additionally, implement rate limiting that is not solely dependent on JWT token validation."
            )
        elif success_count > 0:  # If we had some successes but not enough to be certain
            self.logger.warning(f"JWT {attack_type} attack partially successful for bypassing account creation restrictions")
            
            self.add_finding(
                vulnerability=f"Potential JWT {attack_type.capitalize()} Bypass for Account Creation Restrictions",
                details=f"The application may be vulnerable to JWT {attack_type} attacks for bypassing account creation restrictions. Some account creation attempts with forged tokens were successful.",
                severity="HIGH",
                endpoint=self.endpoint,
                evidence={
                    "attack_type": attack_type,
                    "forged_token": forged_token[:50] + "...",  # Truncate for readability
                    "success_rate": f"{success_count}/{max_attempts}",
                    "test_examples": evidence[:2]  # Include up to 2 examples in the evidence
                },
                remediation="Implement proper JWT validation including signature verification, algorithm validation, and claims checking. Never accept 'none' algorithm tokens and ensure proper key management for asymmetric algorithms. Additionally, implement rate limiting that is not solely dependent on JWT token validation."
            )
        else:
            self.logger.info(f"JWT {attack_type} attack failed for bypassing account creation restrictions (this is the expected behavior)")
    
    def _get_cached_or_create_test_account(self) -> Optional[Dict[str, Any]]:
        """Get a cached test account or create a new one if none exists.
        
        Returns:
            A dictionary containing account credentials if successful, None otherwise
        """
        # First check if we have a cached account for this endpoint
        cached_account = account_cache.get_account(self.endpoint)
        if cached_account:
            self.logger.info(f"Using cached account: {cached_account.get('username', cached_account.get('email'))}")
            return cached_account
            
        # No cached account, create a new one
        self.logger.info("No cached account found, creating a new test account")
        
        # Create a test account with unique identifiers
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        username = f"test_user_{timestamp}_{random_suffix}"
        email = f"{username}@example.com"
        password = "Test@123456"
        
        # For Snorefox API, the username field is actually the email
        payload = {
            self.username_field: email,  # Use email as username for Snorefox API
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
                account_data = {
                    "username": email,  # Using email as username for Snorefox API
                    "email": email,
                    "password": password,
                    "endpoint": self.endpoint,
                    "created_by": "unrestricted_account_creation_scanner",
                    "test_type": "basic_test",
                    "response_code": response.status_code
                }
                
                # Add to global account cache
                account_cache.add_account(account_data)
                
                self.logger.info(f"Successfully created test account: {email}")
                return account_data
            else:
                self.logger.warning(f"Failed to create test account: {email}, status code: {response.status_code}")
                if hasattr(response, 'text') and response.text:
                    self.logger.warning(f"Response body: {response.text[:200]}...")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating test account: {str(e)}")
            return None
    
    def _test_basic_account_creation(self) -> None:
        """Test for basic account creation functionality."""
        self.logger.info("Testing basic account creation")
        
        # Try to get a cached account or create a new one
        account = self._get_cached_or_create_test_account()
        
        if not account:
            self.logger.warning("Failed to create or retrieve a test account, skipping basic account creation test")
            return
            
        username = account.get('username')
        email = account.get('email')
        password = account.get('password')
        
        # Get the response from the account creation
        try:
            # Make a login request to verify the account works
            login_payload = {
                self.username_field: username,
                self.password_field: password
            }
            
            response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=login_payload
            )
            
            # Check if login was successful
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully logged in with test account: {username}")
                
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
        
        # Generate a unique timestamp for this test run
        timestamp = int(time.time())
        
        # Enhanced test cases for invalid input with more comprehensive tests
        test_cases = [
            # Username validation tests
            {
                "name": "Empty username",
                "category": "username_validation",
                "severity": "HIGH",
                "payload": {
                    self.username_field: "",
                    self.email_field: f"valid{timestamp}@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "Very short username",
                "category": "username_validation",
                "severity": "MEDIUM",
                "payload": {
                    self.username_field: "a",
                    self.email_field: f"valid{timestamp}@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "SQL injection in username",
                "category": "injection",
                "severity": "CRITICAL",
                "payload": {
                    self.username_field: "' OR 1=1 --",
                    self.email_field: f"sqli{timestamp}@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "More complex SQL injection in username",
                "category": "injection",
                "severity": "CRITICAL",
                "payload": {
                    self.username_field: "admin'); DROP TABLE users; --",
                    self.email_field: f"sqli2{timestamp}@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "XSS in username",
                "category": "injection",
                "severity": "HIGH",
                "payload": {
                    self.username_field: "<script>alert(1)</script>",
                    self.email_field: f"xss{timestamp}@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "More complex XSS in username",
                "category": "injection",
                "severity": "HIGH",
                "payload": {
                    self.username_field: "<img src=x onerror=alert('XSS')>",
                    self.email_field: f"xss2{timestamp}@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            
            # Email validation tests
            {
                "name": "Empty email",
                "category": "email_validation",
                "severity": "HIGH",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}",
                    self.email_field: "",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "Invalid email format (no @)",
                "category": "email_validation",
                "severity": "MEDIUM",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}_2",
                    self.email_field: "invalid-email",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "Invalid email format (no domain)",
                "category": "email_validation",
                "severity": "MEDIUM",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}_3",
                    self.email_field: "user@",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            {
                "name": "SQL injection in email",
                "category": "injection",
                "severity": "CRITICAL",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}_4",
                    self.email_field: "' OR 1=1 --@example.com",
                    self.password_field: f"Valid@Password{timestamp}"
                }
            },
            
            # Password validation tests
            {
                "name": "Empty password",
                "category": "password_validation",
                "severity": "HIGH",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}_5",
                    self.email_field: f"valid{timestamp}_5@example.com",
                    self.password_field: ""
                }
            },
            {
                "name": "Short password",
                "category": "password_validation",
                "severity": "MEDIUM",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}_6",
                    self.email_field: f"valid{timestamp}_6@example.com",
                    self.password_field: "short"
                }
            },
            {
                "name": "Common password",
                "category": "password_validation",
                "severity": "MEDIUM",
                "payload": {
                    self.username_field: f"valid_user_{timestamp}_7",
                    self.email_field: f"valid{timestamp}_7@example.com",
                    self.password_field: "password123"
                }
            },
            {
                "name": "Password same as username",
                "category": "password_validation",
                "severity": "MEDIUM",
                "payload": {}
                # Will be set dynamically below
            }
        ]
        
        # Set the dynamic payload for "Password same as username" test
        same_username = f"valid_user_{timestamp}_8"
        for test_case in test_cases:
            if test_case["name"] == "Password same as username":
                test_case["payload"] = {
                    self.username_field: same_username,
                    self.email_field: f"valid{timestamp}_8@example.com",
                    self.password_field: same_username
                }
        
        # Track findings by category to avoid duplicate reports
        findings_by_category = {}
        
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
                
                # Record response details for evidence
                response_details = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                }
                
                # Truncate response text to avoid excessive data
                if len(response.text) > 500:
                    response_details["body"] = response.text[:500] + "..."
                else:
                    response_details["body"] = response.text
                
                # Check if validation is working
                if response.status_code in self.success_status_codes:
                    # Account was created with invalid input - this is a vulnerability
                    category = test_case.get("category", "general_validation")
                    severity = test_case.get("severity", "HIGH")
                    
                    # Only add one finding per category to avoid report bloat
                    if category not in findings_by_category:
                        finding_title = f"Unrestricted Account Creation - Lack of {category.replace('_', ' ').title()}"
                        
                        # Customize details based on category
                        if "injection" in category:
                            details = f"The API allows account creation with potential injection attacks in the {test_case['name'].split(' in ')[1]} field. This could lead to SQL injection or XSS vulnerabilities."
                            remediation = "Implement proper input sanitization and validation to prevent injection attacks. Use parameterized queries for database operations and encode output for XSS prevention."
                        elif "password" in category:
                            details = "The API allows account creation with weak or invalid passwords, which could lead to account compromise."
                            remediation = "Implement strong password policies requiring minimum length, complexity, and prohibiting common passwords or passwords matching the username."
                        elif "email" in category:
                            details = "The API allows account creation with invalid email addresses, which could lead to communication issues or account takeover."
                            remediation = "Implement proper email validation using standard libraries or regular expressions. Consider email verification via confirmation links."
                        elif "username" in category:
                            details = "The API allows account creation with invalid usernames, which could lead to identification issues or potential injection attacks."
                            remediation = "Implement proper username validation with minimum/maximum length requirements and character restrictions."
                        else:
                            details = f"The API allows account creation with invalid input: {test_case['name']}"
                            remediation = "Implement proper input validation for all user registration fields."
                        
                        self.add_finding(
                            vulnerability=finding_title,
                            severity=severity,
                            endpoint=self.endpoint,
                            details=details,
                            evidence={
                                "test_case": test_case['name'],
                                "request": payload,
                                "response": response_details
                            },
                            remediation=remediation
                        )
                        
                        findings_by_category[category] = True
                    else:
                        # Just log that we found another issue in this category
                        self.logger.info(f"Found additional {category} validation issue: {test_case['name']}")
                    
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
        
        # Two-phase testing approach:
        # 1. Normal testing with moderate speed
        # 2. Aggressive testing with very rapid requests if normal testing doesn't trigger rate limiting
        # 3. (New) If rate limiting is detected, adapt and find optimal creation rate
        
        # Phase 1: Normal testing
        self.logger.info(f"Phase 1: Normal rate limiting test with {self.test_count} requests")
        rate_limited, successful_creations, response_details = self._perform_rate_limit_test(
            self.test_count, 
            self.test_delay,
            "normal"
        )
        
        # Calculate and record the creation rate
        if successful_creations > 0:
            requests_per_second = 1.0 / self.test_delay
            self.creation_rates.append((self.test_delay, requests_per_second))
            self.logger.info(f"Normal testing rate: {requests_per_second:.2f} requests/second ({successful_creations} successful)")
        
        # If rate limiting wasn't detected in normal testing, try aggressive testing
        if not rate_limited and successful_creations >= self.test_count:
            self.logger.info(f"No rate limiting detected in normal testing. Proceeding to aggressive testing.")
            self.logger.info(f"Phase 2: Aggressive rate limiting test with {self.aggressive_test_count} requests")
            
            # Short pause before aggressive testing to avoid false positives
            time.sleep(2.0)
            
            rate_limited, aggressive_successful, aggressive_response_details = self._perform_rate_limit_test(
                self.aggressive_test_count,
                self.aggressive_test_delay,
                "aggressive"
            )
            
            # Calculate and record the aggressive creation rate
            if aggressive_successful > 0:
                aggressive_requests_per_second = 1.0 / self.aggressive_test_delay
                self.creation_rates.append((self.aggressive_test_delay, aggressive_requests_per_second))
                self.logger.info(f"Aggressive testing rate: {aggressive_requests_per_second:.2f} requests/second ({aggressive_successful} successful)")
            
            # Update successful creations count
            total_successful = successful_creations + aggressive_successful
            
            # Check if rate limiting was detected in aggressive testing
            if rate_limited:
                self.logger.info(f"Rate limiting detected during aggressive testing after {aggressive_successful} successful creations")
                # This is not a vulnerability since rate limiting was eventually triggered
                self.logger.info("Rate limiting is implemented but only triggered under aggressive load")
                
                # If auto-adaptation is enabled, find the optimal rate
                if self.adapt_to_rate_limiting:
                    self.logger.info("Phase 3: Adapting to rate limiting to find optimal creation rate")
                    optimal_delay, optimal_rate, optimal_evidence = self._find_optimal_creation_rate()
                    
                    # Add finding with the optimal rate information
                    self.add_finding(
                        vulnerability="Rate-Limited Account Creation",
                        severity="MEDIUM",
                        endpoint=self.endpoint,
                        details=f"The API implements rate limiting for account creation, but accounts can still be created at a rate of {optimal_rate:.2f} accounts per second (one every {optimal_delay:.2f} seconds). While rate limiting is present, it may not be strict enough to prevent automated account creation.",
                        evidence={
                            "normal_test": {
                                "successful_creations": successful_creations,
                                "test_count": self.test_count,
                                "delay_between_requests": f"{self.test_delay} seconds",
                                "requests_per_second": f"{1.0/self.test_delay:.2f}"
                            },
                            "aggressive_test": {
                                "successful_creations": aggressive_successful,
                                "test_count": self.aggressive_test_count,
                                "delay_between_requests": f"{self.aggressive_test_delay} seconds",
                                "requests_per_second": f"{1.0/self.aggressive_test_delay:.2f}"
                            },
                            "optimal_rate": {
                                "delay_between_requests": f"{optimal_delay:.2f} seconds",
                                "requests_per_second": f"{optimal_rate:.2f}",
                                "test_details": optimal_evidence
                            }
                        },
                        remediation="Consider implementing stricter rate limiting for account creation. The current rate allows for automated account creation, albeit at a reduced rate. Implement additional protections such as CAPTCHA, email verification, or IP-based rate limiting."
                    )
            else:
                # No rate limiting detected even with aggressive testing
                self.add_finding(
                    vulnerability="Unrestricted Account Creation - No Rate Limiting",
                    severity="HIGH",  # Increased severity from MEDIUM to HIGH
                    endpoint=self.endpoint,
                    details=f"The API does not implement rate limiting for account creation. Successfully created {total_successful} accounts in rapid succession without any restrictions, including {aggressive_successful} accounts with only {self.aggressive_test_delay} seconds between requests.",
                    evidence={
                        "normal_test": {
                            "successful_creations": successful_creations,
                            "test_count": self.test_count,
                            "delay_between_requests": f"{self.test_delay} seconds",
                            "requests_per_second": f"{1.0/self.test_delay:.2f}",
                            "response_details": response_details
                        },
                        "aggressive_test": {
                            "successful_creations": aggressive_successful,
                            "test_count": self.aggressive_test_count,
                            "delay_between_requests": f"{self.aggressive_test_delay} seconds",
                            "requests_per_second": f"{1.0/self.aggressive_test_delay:.2f}",
                            "response_details": aggressive_response_details
                        },
                        "total_successful_creations": total_successful
                    },
                    remediation="Implement rate limiting for account creation to prevent abuse and automated account creation attacks. Consider implementing IP-based rate limiting, CAPTCHA, or other anti-automation measures."
                )
        elif rate_limited:
            # Rate limiting was detected in normal testing - this is good
            self.logger.info(f"Rate limiting properly implemented, triggered after {successful_creations} account creations")
            
            # If auto-adaptation is enabled, find the optimal rate
            if self.adapt_to_rate_limiting:
                self.logger.info("Phase 3: Adapting to rate limiting to find optimal creation rate")
                optimal_delay, optimal_rate, optimal_evidence = self._find_optimal_creation_rate()
                
                # Add finding with the optimal rate information
                self.add_finding(
                    vulnerability="Rate-Limited Account Creation",
                    severity="MEDIUM",
                    endpoint=self.endpoint,
                    details=f"The API implements rate limiting for account creation, but accounts can still be created at a rate of {optimal_rate:.2f} accounts per second (one every {optimal_delay:.2f} seconds). While rate limiting is present, it may not be strict enough to prevent automated account creation.",
                    evidence={
                        "normal_test": {
                            "successful_creations": successful_creations,
                            "test_count": self.test_count,
                            "delay_between_requests": f"{self.test_delay} seconds",
                            "requests_per_second": f"{1.0/self.test_delay:.2f}",
                            "response_details": response_details
                        },
                        "optimal_rate": {
                            "delay_between_requests": f"{optimal_delay:.2f} seconds",
                            "requests_per_second": f"{optimal_rate:.2f}",
                            "test_details": optimal_evidence
                        }
                    },
                    remediation="Consider implementing stricter rate limiting for account creation. The current rate allows for automated account creation, albeit at a reduced rate. Implement additional protections such as CAPTCHA, email verification, or IP-based rate limiting."
                )
        else:
            # Some other issue prevented testing
            self.logger.warn(f"Rate limit testing inconclusive: only {successful_creations} accounts created successfully")
    
    def _find_optimal_creation_rate(self) -> Tuple[float, float, List[Dict[str, Any]]]:
        """Find the optimal rate at which accounts can be created without triggering rate limiting.
        
        Returns:
            Tuple containing:
                - Optimal delay between requests (seconds)
                - Optimal rate (requests per second)
                - Evidence of testing
        """
        self.logger.info("Finding optimal account creation rate that avoids rate limiting")
        
        # Start with a conservative delay (higher than what triggered rate limiting)
        current_delay = min(self.test_delay * 2, self.max_delay)
        optimal_delay = None
        optimal_rate = 0
        all_evidence = []
        
        # Binary search approach to find optimal rate
        min_delay = self.min_delay
        max_delay = self.max_delay
        
        # First, find a working delay that doesn't trigger rate limiting
        while min_delay <= max_delay:
            self.logger.info(f"Testing creation rate with {current_delay:.2f} seconds delay")
            
            # Wait a bit before trying a new rate to avoid false positives from cumulative rate limiting
            time.sleep(3.0)
            
            # Try to create a few accounts with this delay
            rate_limited, successful, evidence = self._perform_rate_limit_test(
                self.success_threshold,  # Just need a few successful requests to confirm it works
                current_delay,
                f"optimal_{current_delay:.2f}"
            )
            
            all_evidence.extend(evidence)
            
            if rate_limited:
                # This delay still triggers rate limiting, increase it
                min_delay = current_delay + self.delay_increment
                self.logger.info(f"Rate limiting still triggered at {current_delay:.2f}s delay, increasing")
            else:
                # This delay works, record it and try a faster rate
                optimal_delay = current_delay
                optimal_rate = 1.0 / current_delay
                max_delay = current_delay - self.delay_decrement
                self.logger.info(f"Found working delay: {current_delay:.2f}s ({optimal_rate:.2f} req/sec)")
                
                # Record this successful rate
                self.creation_rates.append((current_delay, optimal_rate))
            
            # Update current delay for next iteration (midpoint of new range)
            current_delay = (min_delay + max_delay) / 2
            
            # If we've narrowed down to a small range, stop
            if max_delay - min_delay < self.delay_decrement:
                break
        
        # If we didn't find a working delay, use the most conservative one
        if optimal_delay is None:
            optimal_delay = self.max_delay
            optimal_rate = 1.0 / optimal_delay
            self.logger.info(f"Could not find optimal rate, using conservative {optimal_delay:.2f}s delay ({optimal_rate:.2f} req/sec)")
        
        # Verify the optimal rate with a larger sample
        self.logger.info(f"Verifying optimal rate: {optimal_rate:.2f} req/sec ({optimal_delay:.2f}s delay)")
        verification_count = min(10, self.test_count)  # Don't create too many accounts
        
        rate_limited, successful, evidence = self._perform_rate_limit_test(
            verification_count,
            optimal_delay,
            "optimal_verification"
        )
        
        all_evidence.extend(evidence)
        
        if rate_limited:
            self.logger.info(f"Rate limiting triggered during verification, adjusting optimal rate")
            # If rate limiting was triggered during verification, use a more conservative rate
            optimal_delay = optimal_delay * 1.5
            optimal_rate = 1.0 / optimal_delay
        else:
            self.logger.info(f"Verified optimal rate: {optimal_rate:.2f} req/sec ({successful} accounts created successfully)")
        
        return optimal_delay, optimal_rate, all_evidence
    
    def _perform_rate_limit_test(self, count: int, delay: float, test_type: str) -> Tuple[bool, int, List[Dict[str, Any]]]:
        """Helper method to perform rate limit testing with specified parameters.
        
        Args:
            count: Number of accounts to attempt to create
            delay: Delay between requests in seconds
            test_type: Type of test (normal or aggressive) for logging
            
        Returns:
            Tuple containing:
                - Whether rate limiting was detected
                - Number of successful account creations
                - List of response details for evidence
        """
        successful_creations = 0
        rate_limited = False
        response_details = []
        
        # Generate a unique prefix for this test run to avoid username conflicts
        timestamp = int(time.time())
        test_prefix = f"test_{test_type}_{timestamp}"
        
        # Track consecutive failures to detect rate limiting earlier
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        for i in range(count):
            # Create unique usernames with test type and timestamp
            username = f"{test_prefix}_{i}"
            email = f"{username}@example.com"
            
            # Use a more complex password that meets common requirements
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
            password = f"Test@{timestamp}#{random_suffix}"
            
            # For Snorefox API, the username field is actually the email
            payload = {
                self.username_field: email,  # Use email as username for Snorefox API
                self.email_field: email,
                self.password_field: password
            }
            
            # Add additional fields
            payload.update(self.additional_fields)
            
            try:
                start_time = time.time()
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload
                )
                request_time = time.time() - start_time
                
                # Record response details for evidence
                response_detail = {
                    "request_number": i + 1,
                    "username": email,  # Using email as username for Snorefox API
                    "status_code": response.status_code,
                    "response_time": request_time,
                    "response_size": len(response.text)
                }
                
                # Truncate response text to avoid excessive data
                if len(response.text) > 200:
                    response_detail["response_excerpt"] = response.text[:200] + "..."
                else:
                    response_detail["response_excerpt"] = response.text
                    
                response_details.append(response_detail)
                
                if response.status_code in self.success_status_codes:
                    successful_creations += 1
                    consecutive_failures = 0  # Reset consecutive failures counter
                    
                    # Track created accounts for potential cleanup later
                    account_data = {
                        "username": email,  # Using email as username for Snorefox API
                        "email": email,
                        "password": password,
                        "endpoint": self.endpoint,
                        "created_by": "unrestricted_account_creation_scanner",
                        "test_type": test_type,
                        "response_code": response.status_code
                    }
                    self.created_accounts.append(account_data)
                    
                    # Add to global account cache for other scanners to use
                    account_cache.add_account(account_data)
                    
                    self.logger.info(f"Successfully created account {i+1}/{count}: {email}")
                elif response.status_code in self.rate_limit_status_codes:
                    rate_limited = True
                    self.logger.info(f"Rate limiting detected (status code {response.status_code}) after {successful_creations} successful creations")
                    response_detail["rate_limited"] = True
                    response_details.append(response_detail)
                    break
                else:
                    consecutive_failures += 1
                    self.logger.info(f"Unexpected status code {response.status_code} for account {i+1}/{count}")
                    
                    # Check if we've had too many consecutive failures, which might indicate rate limiting
                    if consecutive_failures >= max_consecutive_failures:
                        self.logger.warning(f"Possible rate limiting detected after {consecutive_failures} consecutive failures")
                        rate_limited = True
                        response_detail["rate_limited"] = True
                        response_detail["rate_limit_indicator"] = "consecutive_failures"
                        break
                
                # Enhanced check for rate limit indicators in response body
                if not rate_limited and response.text:
                    response_text = response.text.lower()
                    rate_limit_indicators = [
                        "rate limit", "ratelimit", "too many requests", 
                        "try again later", "slow down", "too frequent",
                        "limit exceeded", "wait", "throttle", "quota"
                    ]
                    
                    for indicator in rate_limit_indicators:
                        if indicator in response_text:
                            rate_limited = True
                            self.logger.info(f"Rate limiting detected from response body after {successful_creations} successful creations")
                            response_detail["rate_limited"] = True
                            response_detail["rate_limit_indicator"] = indicator
                            response_details.append(response_detail)
                            break
                
                if rate_limited:
                    break
                
                # Add delay between requests with small random jitter to avoid predictable patterns
                jitter = random.uniform(-0.1, 0.1) * delay
                actual_delay = max(0.1, delay + jitter)  # Ensure delay is at least 0.1 seconds
                time.sleep(actual_delay)
            
            except Exception as e:
                consecutive_failures += 1
                self.logger.error(f"Error testing rate limiting: {str(e)}")
                response_details.append({
                    "request_number": i + 1,
                    "username": email,
                    "error": str(e)
                })
                
                # If we get several consecutive exceptions, it might be rate limiting
                if consecutive_failures >= max_consecutive_failures:
                    self.logger.warning(f"Possible rate limiting causing exceptions after {consecutive_failures} consecutive failures")
                    rate_limited = True
                    break
        
        # If we had a significant drop in successful creations, it might be silent rate limiting
        if not rate_limited and count > 0 and successful_creations < count * 0.7 and successful_creations > 0:
            self.logger.warning(f"Possible silent rate limiting: only {successful_creations}/{count} accounts created successfully")
            rate_limited = True
            
        return rate_limited, successful_creations, response_details
    
    def _test_account_enumeration(self) -> None:
        """Test for account enumeration during account creation."""
        self.logger.info("Testing for account enumeration")
        
        # Create an initial account
        timestamp = int(time.time())
        username = f"enum_user_{timestamp}"
        email = f"{username}@example.com"
        password = "Test@123456"
        
        # For Snorefox API, the username field is actually the email
        payload = {
            self.username_field: email,  # Use email as username for Snorefox API
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
                self.logger.info(f"Created initial account for enumeration test: {email}")
                
                # Try to create the same account again
                time.sleep(self.test_delay)
                response = self._make_request(
                    method=self.method,
                    endpoint=self.endpoint,
                    json_data=payload
                )
                
                # Check if the response reveals that the username/email already exists
                response_text = response.text.lower()
                username_indicators = ["username already exists", "username taken", "username is already in use", "user already exists"]
                email_indicators = ["email already exists", "email taken", "email is already in use", "email already registered", "already registered"]
                
                username_enumeration = any(indicator in response_text for indicator in username_indicators)
                email_enumeration = any(indicator in response_text for indicator in email_indicators)
                
                self.logger.info(f"Enumeration test response: {response.status_code} - {response.text[:200]}")
                
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
            
    def _create_completely_forged_token(self) -> str:
        """
        Create a completely forged JWT token with common claims.
        
        This creates a token from scratch rather than modifying an existing one.
        
        Returns:
            A forged JWT token string
        """
        try:
            # Create a header with 'none' algorithm
            header = {
                "alg": "none",
                "typ": "JWT"
            }
            
            # Create a payload with common claims
            timestamp = int(time.time())
            payload = {
                "sub": "admin",
                "name": "Administrator",
                "email": "admin@example.com",
                "role": "admin",
                "permissions": ["create_user", "delete_user", "update_user", "read_user"],
                "iat": timestamp,
                "exp": timestamp + 3600,  # 1 hour from now
                "iss": "https://api.example.com",
                "aud": "https://api.example.com"
            }
            
            # Encode header and payload
            header_base64 = self._encode_jwt_part(header)
            payload_base64 = self._encode_jwt_part(payload)
            
            # Create token without signature
            token = f"{header_base64}.{payload_base64}."
            
            self.logger.info(f"Created completely forged token: {token[:20]}...")
            return token
            
        except Exception as e:
            self.logger.error(f"Error creating completely forged token: {str(e)}")
            return ""
    
    def _test_forged_token_for_auth_bypass(self, forged_token: str, attack_type: str) -> None:
        """
        Test if a forged token can bypass authentication requirements for account creation.
        
        Args:
            forged_token: The forged token to test
            attack_type: The type of attack being tested (e.g., 'none' algorithm, algorithm switching)
        """
        self.logger.info(f"Testing if {attack_type} token can bypass authentication requirements")
        
        # Create a test account payload
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
        username = f"test_user_{timestamp}_{random_suffix}"
        email = f"{username}@example.com"
        password = "Test@123456"
        
        payload = {
            self.username_field: email,
            self.email_field: email,
            self.password_field: password
        }
        payload.update(self.additional_fields)
        
        try:
            # First attempt without any token to establish baseline
            no_token_response = self._make_request(
                method=self.method,
                endpoint=self.endpoint,
                json_data=payload
            )
            
            # Now try with the forged token
            headers = {"Authorization": f"Bearer {forged_token}"}
            forged_token_response = self._make_request(
                method=self.method,
                endpoint=self.endpoint,
                json_data=payload,
                headers=headers
            )
            
            # Log the responses for debugging
            self.logger.info(f"No token response status: {no_token_response.status_code}")
            self.logger.info(f"Forged token response status: {forged_token_response.status_code}")
            
            # Now let's implement the actual logic to check for JWT bypass vulnerabilities
            if forged_token_response.status_code in self.success_status_codes:
                self.logger.warning(f"JWT {attack_type} attack successful for bypassing authentication requirements!")
                
                # Check if the no-token request failed but the forged token request succeeded
                if no_token_response.status_code not in self.success_status_codes:
                    self.logger.warning("Authentication appears to be required, but was bypassed with a forged token!")
                    
                    self.add_finding(
                        vulnerability=f"JWT {attack_type.capitalize()} Authentication Bypass",
                        details=f"The application accepts forged JWT tokens using {attack_type} attack, allowing bypass of authentication requirements for account creation. This indicates a critical vulnerability in the JWT validation process.",
                        severity="CRITICAL",
                        endpoint=self.endpoint,
                        evidence={
                            "attack_type": attack_type,
                            "forged_token": forged_token[:50] + "...",  # Truncate for readability
                            "no_token_response": {
                                "status_code": no_token_response.status_code,
                                "body": no_token_response.text[:200] + ("..." if len(no_token_response.text) > 200 else "")
                            },
                            "forged_token_response": {
                                "status_code": forged_token_response.status_code,
                                "body": forged_token_response.text[:200] + ("..." if len(forged_token_response.text) > 200 else "")
                            }
                        },
                        remediation="Implement proper JWT validation including signature verification, algorithm validation, and claims checking. Never accept 'none' algorithm tokens and ensure proper key management for asymmetric algorithms. Additionally, implement proper authentication checks before allowing account creation."
                    )
                else:
                    self.logger.info("Authentication does not appear to be required for account creation")
                    
                    self.add_finding(
                        vulnerability="Unrestricted Account Creation",
                        details="The application allows account creation without proper authentication, which could lead to unauthorized account creation and potential abuse.",
                        severity="HIGH",
                        endpoint=self.endpoint,
                        evidence={
                            "no_token_response": {
                                "status_code": no_token_response.status_code,
                                "body": no_token_response.text[:200] + ("..." if len(no_token_response.text) > 200 else "")
                            }
                        },
                        remediation="Implement proper authentication requirements before allowing account creation. This should include validating JWT tokens and ensuring that only authorized users can create accounts."
                    )
            else:
                # Check response for JWT validation errors
                response_text = forged_token_response.text.lower()
                jwt_validation_indicators = [
                    "invalid token", "invalid signature", "token invalid", "signature invalid",
                    "jwt", "token expired", "malformed token", "algorithm not supported"
                ]
                
                validation_error_found = False
                for indicator in jwt_validation_indicators:
                    if indicator in response_text:
                        validation_error_found = True
                        self.logger.info(f"JWT validation error detected: '{indicator}'")
                        break
                
                if validation_error_found:
                    self.logger.info(f"JWT {attack_type} attack failed - proper validation in place (this is good)")
                else:
                    self.logger.info(f"JWT {attack_type} attack failed, but no specific JWT validation error was detected")
                    
                    # If we didn't get a clear JWT validation error, add a low severity finding
                    if forged_token_response.status_code >= 400:
                        self.add_finding(
                            vulnerability=f"Potential JWT Validation Issue",
                            details=f"The application rejected the forged JWT token but did not return a specific JWT validation error. This might indicate that the token is being rejected for reasons other than proper JWT validation.",
                            severity="LOW",
                            endpoint=self.endpoint,
                            evidence={
                                "attack_type": attack_type,
                                "forged_token": forged_token[:50] + "...",
                                "response": {
                                    "status_code": forged_token_response.status_code,
                                    "body": forged_token_response.text[:200] + ("..." if len(forged_token_response.text) > 200 else "")
                                }
                            },
                            remediation="Ensure proper JWT validation with clear error messages. Implement comprehensive JWT validation including signature verification, algorithm validation, and claims checking."
                        )
                    
        except Exception as e:
            self.logger.error(f"Error testing forged token for auth bypass: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
