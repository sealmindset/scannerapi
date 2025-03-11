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
from typing import Dict, List, Any, Optional, Tuple

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


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
