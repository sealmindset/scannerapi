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
from typing import Dict, List, Any, Optional, Tuple, Set, Union

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
        
        # Aggressive test configuration for rate limiting detection
        self.aggressive_test_count = config.get("aggressive_test_count", 30)  # For aggressive testing
        self.aggressive_test_delay = config.get("aggressive_test_delay", 0.1)  # Very short delay for aggressive testing
        
        # Field names with better defaults
        self.username_field = config.get("username_field", "username")
        self.email_field = config.get("email_field", "email")
        self.password_field = config.get("password_field", "password")
        
        # Additional fields to include in the request
        self.additional_fields = config.get("additional_fields", {})
        
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
        
        # Phase 1: Normal testing
        self.logger.info(f"Phase 1: Normal rate limiting test with {self.test_count} requests")
        rate_limited, successful_creations, response_details = self._perform_rate_limit_test(
            self.test_count, 
            self.test_delay,
            "normal"
        )
        
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
            
            # Update successful creations count
            total_successful = successful_creations + aggressive_successful
            
            # Check if rate limiting was detected in aggressive testing
            if rate_limited:
                self.logger.info(f"Rate limiting detected during aggressive testing after {aggressive_successful} successful creations")
                # This is not a vulnerability since rate limiting was eventually triggered
                self.logger.info("Rate limiting is implemented but only triggered under aggressive load")
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
                            "response_details": response_details
                        },
                        "aggressive_test": {
                            "successful_creations": aggressive_successful,
                            "test_count": self.aggressive_test_count,
                            "delay_between_requests": f"{self.aggressive_test_delay} seconds",
                            "response_details": aggressive_response_details
                        },
                        "total_successful_creations": total_successful
                    },
                    remediation="Implement rate limiting for account creation to prevent abuse and automated account creation attacks. Consider implementing IP-based rate limiting, CAPTCHA, or other anti-automation measures."
                )
        elif rate_limited:
            # Rate limiting was detected in normal testing - this is good
            self.logger.info(f"Rate limiting properly implemented, triggered after {successful_creations} account creations")
        else:
            # Some other issue prevented testing
            self.logger.warn(f"Rate limit testing inconclusive: only {successful_creations} accounts created successfully")
    
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
        
        for i in range(count):
            # Create unique usernames with test type and timestamp
            username = f"{test_prefix}_{i}"
            email = f"{username}@example.com"
            
            # Use a more complex password that meets common requirements
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
            password = f"Test@{timestamp}#{random_suffix}"
            
            payload = {
                self.username_field: username,
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
                    "username": username,
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
                    # Track created accounts for potential cleanup later
                    self.created_accounts.append({
                        "username": username,
                        "email": email,
                        "password": password
                    })
                    self.logger.info(f"Successfully created account {i+1}/{count}: {username}")
                elif response.status_code in self.rate_limit_status_codes:
                    rate_limited = True
                    self.logger.info(f"Rate limiting detected (status code {response.status_code}) after {successful_creations} successful creations")
                    response_detail["rate_limited"] = True
                    response_details.append(response_detail)
                    break
                else:
                    self.logger.info(f"Unexpected status code {response.status_code} for account {i+1}/{count}")
                
                # Check response body for rate limit indicators
                if not rate_limited and response.text:
                    response_text = response.text.lower()
                    for indicator in self.rate_limit_response_contains:
                        if indicator.lower() in response_text:
                            rate_limited = True
                            self.logger.info(f"Rate limiting detected from response body after {successful_creations} successful creations")
                            response_detail["rate_limited"] = True
                            response_detail["rate_limit_indicator"] = indicator
                            response_details.append(response_detail)
                            break
                
                if rate_limited:
                    break
                
                # Add delay between requests
                time.sleep(delay)
            
            except Exception as e:
                self.logger.error(f"Error testing rate limiting: {str(e)}")
                response_details.append({
                    "request_number": i + 1,
                    "username": username,
                    "error": str(e)
                })
                break
        
        return rate_limited, successful_creations, response_details
    
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
