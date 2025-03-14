"""
Enhanced Broken Access Control Scanner Module.

This module tests for vulnerabilities related to broken access control,
where users can gain unauthorized access to resources or perform actions
that should be restricted based on their role or permissions.

Enhanced to detect:
1. Traditional broken access control vulnerabilities
2. JWT bypass methods for accessing protected resources
3. Different API structures (RESTful, traditional, mobile)
4. Different field naming conventions
"""

import json
import time
import random
import string
import base64
from typing import Dict, List, Any, Optional, Tuple

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class EnhancedBrokenAccessControlScanner(BaseScanner):
    """Enhanced scanner for detecting broken access control vulnerabilities including JWT bypass methods."""
    
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
        self.admin_endpoint = config.get("admin_endpoint", "/admin")
        self.user_endpoint = config.get("user_endpoint", "/users/{username}")
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using debug endpoint: {self.debug_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using admin endpoint: {self.admin_endpoint}")
        self.logger.info(f"Using user endpoint: {self.user_endpoint}")
        
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
        
        # Admin user credentials
        self.admin_username = config.get("admin_username", f"admin_user_{timestamp}_{random_suffix}")
        self.admin_email = config.get("admin_email", f"{self.admin_username}@example.com")
        self.admin_password = config.get("admin_password", f"Admin@{timestamp}")
        
        # Test delay
        self.test_delay = config.get("test_delay", 1.0)
        
        # Protected resources to test
        self.protected_resources = config.get("protected_resources", [
            {"endpoint": "/admin/users", "method": "GET"},
            {"endpoint": "/admin/settings", "method": "GET"},
            {"endpoint": "/users", "method": "GET"},
            {"endpoint": "/users/me", "method": "GET"},
            {"endpoint": "/profile", "method": "GET"},
            {"endpoint": "/account", "method": "GET"}
        ])
        
        # JWT testing configuration
        self.test_jwt_bypass = config.get("test_jwt_bypass", True)
        self.jwt_token = None
        self.jwt_header = {}
        self.jwt_payload = {}
    
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
        
        # Enhanced endpoint detection for login/registration
        # Look for both standard patterns and RESTful API patterns like Snorefox
        register_patterns = [
            "create_user", "register", "signup", "sign-up", "sign_up", 
            "auth/sign-up", "auth/signup", "auth/register", "users/create",
            "account/create", "account/register", "new-user", "new-account"
        ]
        
        login_patterns = [
            "login", "signin", "sign-in", "sign_in", 
            "auth/sign-in", "auth/signin", "auth/login", "users/login",
            "account/login", "account/signin", "token"
        ]
        
        admin_patterns = [
            "admin", "dashboard", "control", "manage", "settings",
            "users/admin", "admin/users", "admin/dashboard", "admin/settings",
            "admin/control", "admin/manage"
        ]
        
        # Find registration endpoint
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Only consider POST methods for registration
            if method != "POST":
                continue
                
            # Check path for registration patterns
            for pattern in register_patterns:
                if pattern in path.lower():
                    self.register_endpoint = path
                    self.logger.info(f"Found registration endpoint: {path}")
                    break
        
        # Find login endpoint
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Only consider POST methods for login
            if method != "POST":
                continue
                
            # Check path for login patterns
            for pattern in login_patterns:
                if pattern in path.lower():
                    self.login_endpoint = path
                    self.logger.info(f"Found login endpoint: {path}")
                    break
        
        # Find admin endpoints
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Check path for admin patterns
            for pattern in admin_patterns:
                if pattern in path.lower():
                    self.admin_endpoint = path
                    self.logger.info(f"Found admin endpoint: {path}")
                    
                    # Add to protected resources
                    self.protected_resources.append({"endpoint": path, "method": method})
                    break
        
        # Find user endpoints
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            
            # Check for user-specific endpoints
            if "/users/" in path.lower() or "/user/" in path.lower():
                if "{" in path and "}" in path:
                    self.user_endpoint = path
                    self.logger.info(f"Found user endpoint: {path}")
                    break
        
        # Find protected resources
        for endpoint in endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            security = endpoint.get("security", [])
            
            # Check if endpoint has security requirements
            if security:
                self.protected_resources.append({"endpoint": path, "method": method})
                self.logger.info(f"Found protected resource: {path}")
    
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
            if response.status_code in self.success_status_codes:
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
            
        try:
            response = self._make_request(
                method="POST",
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
    
    def _login_user(self, username: str, password: str) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Login a user and get an authentication token.
        
        Args:
            username: Username for the user
            password: Password for the user
            
        Returns:
            Tuple of (success, token, response_data)
        """
        self.logger.info(f"Logging in user '{username}'")
        
        # Prepare payload with common field names
        payload = {
            self.username_field: username,
            self.email_field: username,
            self.password_field: password
        }
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=payload
            )
            
            # Check if login was successful
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully logged in user '{username}'")
                try:
                    response_data = response.json()
                    
                    # Try to extract token from response
                    token = None
                    token_fields = ["token", "access_token", "accessToken", "id_token", "idToken", "jwt", self.auth_token_field]
                    
                    for field in token_fields:
                        if field in response_data:
                            token = response_data[field]
                            if isinstance(token, str):
                                self.logger.info(f"Found token in {field} field")
                                break
                    
                    # Look for token in nested objects
                    if not token:
                        for key, value in response_data.items():
                            if isinstance(value, dict):
                                for field in token_fields:
                                    if field in value:
                                        token = value[field]
                                        if isinstance(token, str):
                                            self.logger.info(f"Found token in {key}.{field} field")
                                            break
                    
                    return True, token, response_data
                except (ValueError, json.JSONDecodeError):
                    return True, None, {"status_code": response.status_code, "text": response.text}
            else:
                self.logger.info(f"Failed to login user '{username}', status code: {response.status_code}")
                try:
                    response_data = response.json()
                    return False, None, response_data
                except (ValueError, json.JSONDecodeError):
                    return False, None, {"status_code": response.status_code, "text": response.text}
        except Exception as e:
            self.logger.error(f"Error logging in user '{username}': {str(e)}")
            return False, None, None
    
    def _test_privilege_escalation_during_registration(self) -> None:
        """Test for privilege escalation during registration."""
        self.logger.info("Testing for privilege escalation during registration")
        
        # Try to register an admin user
        success, response_data = self._register_user(
            username=self.admin_username,
            email=self.admin_email,
            password=self.admin_password,
            admin=True
        )
        
        if success:
            self.logger.warning("Privilege escalation vulnerability detected during registration")
            self.add_finding(
                vulnerability="Privilege Escalation During Registration",
                severity="CRITICAL",
                endpoint=self.register_endpoint,
                details=(
                    "The API allows users to escalate their privileges during registration by including an admin field. "
                    "Successfully registered an admin user by including an admin field in the request."
                ),
                evidence={
                    "username": self.admin_username,
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
            self.logger.info("No privilege escalation vulnerability detected during registration")
    
    def _test_jwt_bypass_for_privilege_escalation(self) -> None:
        """Test for JWT bypass for privilege escalation."""
        if not self.test_jwt_bypass:
            self.logger.info("Skipping JWT bypass test")
            return
            
        self.logger.info("Testing for JWT bypass for privilege escalation")
        
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
        
        # Try to access admin resources with the modified token
        for resource in self.protected_resources:
            endpoint = resource["endpoint"]
            method = resource["method"]
            
            try:
                self.logger.info(f"Testing JWT bypass on {endpoint}")
                response = self._make_request(
                    method=method,
                    endpoint=endpoint,
                    headers={"Authorization": f"Bearer {modified_token}"},
                    try_auth_if_needed=False
                )
                
                # Check if access was successful
                if response.status_code in self.success_status_codes:
                    self.logger.warning(f"JWT bypass vulnerability detected on {endpoint}")
                    self.add_finding(
                        vulnerability="JWT Bypass for Privilege Escalation",
                        severity="CRITICAL",
                        endpoint=endpoint,
                        details=(
                            "The API allows privilege escalation by using a modified JWT token. "
                            "Successfully accessed a protected resource by using a token with the 'none' algorithm and admin privileges."
                        ),
                        evidence={
                            "endpoint": endpoint,
                            "method": method,
                            "modified_token": modified_token,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Reject tokens with 'none' algorithm by explicitly checking the algorithm.\n"
                            "2. Implement proper signature verification for all tokens.\n"
                            "3. Validate all claims in the token, especially role and permission claims.\n"
                            "4. Implement proper role-based access control for all protected resources."
                        )
                    )
                    return  # Found a vulnerability, no need to check other resources
            except Exception as e:
                self.logger.debug(f"Error testing JWT bypass on {endpoint}: {str(e)}")
        
        self.logger.info("No JWT bypass vulnerability detected")
    
    def _test_unauthorized_access_to_admin_resources(self) -> None:
        """Test for unauthorized access to admin resources."""
        self.logger.info("Testing for unauthorized access to admin resources")
        
        # Register a regular user
        success, response_data = self._register_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password,
            admin=False
        )
        
        if not success:
            self.logger.warning("Failed to register test user, skipping unauthorized access test")
            return
            
        # Login as the regular user
        login_success, token, login_data = self._login_user(
            username=self.test_username,
            password=self.test_password
        )
        
        if not login_success or not token:
            self.logger.warning("Failed to login as test user, skipping unauthorized access test")
            return
            
        # Try to access admin resources with the regular user's token
        for resource in self.protected_resources:
            endpoint = resource["endpoint"]
            method = resource["method"]
            
            try:
                self.logger.info(f"Testing unauthorized access to {endpoint}")
                response = self._make_request(
                    method=method,
                    endpoint=endpoint,
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                # Check if access was successful
                if response.status_code in self.success_status_codes:
                    self.logger.warning(f"Unauthorized access vulnerability detected on {endpoint}")
                    self.add_finding(
                        vulnerability="Unauthorized Access to Admin Resources",
                        severity="HIGH",
                        endpoint=endpoint,
                        details=(
                            "The API allows unauthorized access to admin resources. "
                            "Successfully accessed a protected resource with a regular user's token."
                        ),
                        evidence={
                            "endpoint": endpoint,
                            "method": method,
                            "username": self.test_username,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Implement proper role-based access control for all protected resources.\n"
                            "2. Validate user roles and permissions before allowing access to admin resources.\n"
                            "3. Use middleware or decorators to enforce access control consistently.\n"
                            "4. Implement proper error handling for unauthorized access attempts."
                        )
                    )
            except Exception as e:
                self.logger.debug(f"Error testing unauthorized access to {endpoint}: {str(e)}")
    
    def _test_horizontal_privilege_escalation(self, existing_users: List[Dict[str, Any]]) -> None:
        """
        Test for horizontal privilege escalation (accessing other users' data).
        
        Args:
            existing_users: List of existing user accounts
        """
        self.logger.info("Testing for horizontal privilege escalation")
        
        # Skip if no existing users
        if not existing_users:
            self.logger.info("No existing users found, skipping horizontal privilege escalation test")
            return
            
        # Register a regular user
        success, response_data = self._register_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password,
            admin=False
        )
        
        if not success:
            self.logger.warning("Failed to register test user, skipping horizontal privilege escalation test")
            return
            
        # Login as the regular user
        login_success, token, login_data = self._login_user(
            username=self.test_username,
            password=self.test_password
        )
        
        if not login_success or not token:
            self.logger.warning("Failed to login as test user, skipping horizontal privilege escalation test")
            return
            
        # Try to access other users' data
        for user in existing_users:
            # Skip if the user is the test user
            if user.get(self.username_field) == self.test_username or user.get("username") == self.test_username:
                continue
                
            # Get the username
            username = user.get(self.username_field, user.get("username", ""))
            if not username:
                continue
                
            # Try to access the user's data
            endpoint = self.user_endpoint.replace("{username}", username)
            
            try:
                self.logger.info(f"Testing horizontal privilege escalation on {endpoint}")
                response = self._make_request(
                    method="GET",
                    endpoint=endpoint,
                    headers={"Authorization": f"Bearer {token}"}
                )
                
                # Check if access was successful
                if response.status_code in self.success_status_codes:
                    self.logger.warning(f"Horizontal privilege escalation vulnerability detected on {endpoint}")
                    self.add_finding(
                        vulnerability="Horizontal Privilege Escalation",
                        severity="HIGH",
                        endpoint=endpoint,
                        details=(
                            "The API allows horizontal privilege escalation (accessing other users' data). "
                            f"Successfully accessed user '{username}' data with a different user's token."
                        ),
                        evidence={
                            "endpoint": endpoint,
                            "method": "GET",
                            "username": self.test_username,
                            "target_username": username,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Implement proper access control for user-specific resources.\n"
                            "2. Validate that the authenticated user is only accessing their own data.\n"
                            "3. Use middleware or decorators to enforce access control consistently.\n"
                            "4. Implement proper error handling for unauthorized access attempts."
                        )
                    )
                    return  # Found a vulnerability, no need to check other users
            except Exception as e:
                self.logger.debug(f"Error testing horizontal privilege escalation on {endpoint}: {str(e)}")
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting enhanced broken access control scanner")
        
        # Get existing users
        existing_users = self._get_existing_accounts()
        
        # Test for privilege escalation during registration
        self._test_privilege_escalation_during_registration()
        
        # Test for JWT bypass for privilege escalation
        self._test_jwt_bypass_for_privilege_escalation()
        
        # Test for unauthorized access to admin resources
        self._test_unauthorized_access_to_admin_resources()
        
        # Test for horizontal privilege escalation (accessing other users' data)
        self._test_horizontal_privilege_escalation(existing_users)
        
        # Return findings
        return self.findings
