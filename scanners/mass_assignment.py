"""
Mass Assignment Scanner Module.

This module tests for mass assignment vulnerabilities, where an API allows
setting of properties that should be restricted, potentially leading to
privilege escalation or data manipulation.
"""

import json
import time
import logging
import os
from typing import Dict, List, Any, Optional, Tuple

import yaml

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting mass assignment vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Get scanner-specific configuration
        self.endpoints = config.get("endpoints", [])
        self.id_field = config.get("id_field", "id")
        
        # Initialize endpoints with default values
        self.create_endpoint = config.get("create_endpoint", "/api/users")
        self.update_endpoint = config.get("update_endpoint", "/api/users/{id}")
        self.get_endpoint = config.get("get_endpoint", "/api/users/{id}")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using create endpoint: {self.create_endpoint}")
        self.logger.info(f"Using update endpoint: {self.update_endpoint}")
        self.logger.info(f"Using get endpoint: {self.get_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Using debug endpoint: {self.debug_endpoint}")
        
        self.sensitive_fields = config.get("sensitive_fields", [
            "role", "admin", "is_admin", "isAdmin", "is_superuser", "isSuperuser",
            "permissions", "access_level", "accessLevel", "privilege", "rank",
            "verified", "is_verified", "isVerified", "active", "is_active", "isActive"
        ])
        self.test_values = config.get("test_values", {
            "role": "admin",
            "admin": True,
            "is_admin": True,
            "isAdmin": True,
            "is_superuser": True,
            "isSuperuser": True,
            "permissions": ["admin", "superuser", "*"],
            "access_level": 9999,
            "accessLevel": 9999,
            "privilege": "admin",
            "rank": 9999,
            "verified": True,
            "is_verified": True,
            "isVerified": True,
            "active": True,
            "is_active": True,
            "isActive": True
        })
        self.create_user_payload = config.get("create_user_payload", {
            "username": f"test_mass_assignment_{int(time.time())}",
            "email": f"test_mass_assignment_{int(time.time())}@example.com",
            "password": "Test@123456"
        })
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting mass assignment vulnerability scanner")
        
        # If specific endpoints are provided, test those
        if self.endpoints:
            for endpoint_config in self.endpoints:
                self._test_endpoint(endpoint_config)
        else:
            # Otherwise, test the default create/update flow
            self._test_create_update_flow()
        
        # Test for role change vulnerabilities
        self._test_role_change_vulnerability()
        
        # Test for mass assignment during registration
        self._test_registration_mass_assignment()
        
        # Return findings
        return self.findings
    
    def _test_endpoint(self, endpoint_config: Any) -> None:
        """
        Test a specific endpoint for mass assignment vulnerabilities.
        
        Args:
            endpoint_config: Endpoint configuration (can be a string or a dictionary)
        """
        # Handle both string endpoints and dictionary configurations
        if isinstance(endpoint_config, str):
            endpoint = endpoint_config
            method = "POST"  # Default method
            base_payload = {}
            id_param = self.id_field
        else:
            # It's a dictionary configuration
            endpoint = endpoint_config.get("endpoint", "")
            method = endpoint_config.get("method", "POST")
            base_payload = endpoint_config.get("payload", {})
            id_param = endpoint_config.get("id_param", self.id_field)
        
        if not endpoint:
            self.logger.warn("Skipping endpoint with missing URL")
            return
        
        self.logger.info(f"Testing endpoint {method} {endpoint} for mass assignment")
        
        # If the endpoint requires an ID parameter, try to get a valid ID
        if "{id}" in endpoint and id_param:
            # Try to get a valid ID from a list endpoint
            list_endpoint = endpoint_config.get("list_endpoint", endpoint.split("/{id}")[0])
            try:
                response = self._make_request(
                    method="GET",
                    endpoint=list_endpoint
                )
                
                if response.status_code == 200:
                    # Try to parse response and get an ID
                    try:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 0:
                            item_id = data[0].get(id_param)
                            if item_id:
                                endpoint = endpoint.replace("{id}", str(item_id))
                            else:
                                self.logger.warn(f"Could not find ID in response item: {data[0]}")
                                return
                        elif isinstance(data, dict) and "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
                            item_id = data["data"][0].get(id_param)
                            if item_id:
                                endpoint = endpoint.replace("{id}", str(item_id))
                            else:
                                self.logger.warn(f"Could not find ID in response item: {data['data'][0]}")
                                return
                        else:
                            self.logger.warn(f"Unexpected response format from list endpoint: {list_endpoint}")
                            return
                    except (ValueError, KeyError) as e:
                        self.logger.warn(f"Error parsing response from list endpoint: {str(e)}")
                        return
                else:
                    self.logger.warn(f"Failed to get data from list endpoint: {list_endpoint}, status code: {response.status_code}")
                    return
            except Exception as e:
                self.logger.error(f"Error accessing list endpoint: {str(e)}")
                return
        
        # Test each sensitive field
        for field in self.sensitive_fields:
            # Skip if the field is already in the base payload
            if field in base_payload:
                continue
            
            # Create payload with the sensitive field
            payload = base_payload.copy()
            payload[field] = self.test_values.get(field, True)
            
            try:
                response = self._make_request(
                    method=method,
                    endpoint=endpoint,
                    json_data=payload
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    # Try to verify if the field was actually set
                    if method in ["POST", "PUT", "PATCH"] and isinstance(endpoint_config, dict) and endpoint_config.get("verify_endpoint"):
                        verify_endpoint = endpoint_config.get("verify_endpoint")
                        if "{id}" in verify_endpoint:
                            # Try to get the ID from the response
                            try:
                                data = response.json()
                                item_id = data.get(id_param)
                                if item_id:
                                    verify_endpoint = verify_endpoint.replace("{id}", str(item_id))
                                else:
                                    self.logger.warn(f"Could not find ID in response: {data}")
                                    continue
                            except (ValueError, KeyError) as e:
                                self.logger.warn(f"Error parsing response: {str(e)}")
                                continue
                        
                        # Verify if the field was set
                        try:
                            verify_response = self._make_request(
                                method="GET",
                                endpoint=verify_endpoint
                            )
                            
                            if verify_response.status_code == 200:
                                try:
                                    verify_data = verify_response.json()
                                    if field in verify_data and verify_data[field] == payload[field]:
                                        # Field was successfully set
                                        self.add_finding(
                                            vulnerability="Mass Assignment",
                                            severity="HIGH",
                                            endpoint=endpoint,
                                            details=f"The API allows setting the sensitive field '{field}' via mass assignment, which could lead to privilege escalation.",
                                            evidence={
                                                "request": {
                                                    "method": method,
                                                    "endpoint": endpoint,
                                                    "payload": payload
                                                },
                                                "response": {
                                                    "status_code": response.status_code,
                                                    "body": response.text[:1000]  # Limit response size
                                                },
                                                "verification": {
                                                    "endpoint": verify_endpoint,
                                                    "status_code": verify_response.status_code,
                                                    "field_value": verify_data.get(field)
                                                }
                                            },
                                            remediation="Implement proper server-side filtering of request parameters to prevent setting of sensitive fields."
                                        )
                                except (ValueError, KeyError) as e:
                                    self.logger.warn(f"Error parsing verification response: {str(e)}")
                        except Exception as e:
                            self.logger.error(f"Error verifying field: {str(e)}")
                    else:
                        # Can't verify, but the request was successful
                        self.add_finding(
                            vulnerability="Potential Mass Assignment",
                            severity="MEDIUM",
                            endpoint=endpoint,
                            details=f"The API accepted a request with the sensitive field '{field}' without error, which might indicate a mass assignment vulnerability.",
                            evidence={
                                "request": {
                                    "method": method,
                                    "endpoint": endpoint,
                                    "payload": payload
                                },
                                "response": {
                                    "status_code": response.status_code,
                                    "body": response.text[:1000]  # Limit response size
                                }
                            },
                            remediation="Implement proper server-side filtering of request parameters to prevent setting of sensitive fields."
                        )
            
            except Exception as e:
                self.logger.error(f"Error testing field '{field}': {str(e)}")
            
            # Add delay between requests
            time.sleep(0.5)
    
    def _test_registration_mass_assignment(self) -> None:
        """Test for mass assignment vulnerabilities during user registration."""
        self.logger.info("Testing for mass assignment vulnerabilities during user registration")
        
        # Use the dynamically resolved registration endpoint
        register_endpoint = self.register_endpoint
        
        # Test registering with admin privileges
        timestamp = int(time.time())
        username = f"test_mass_reg_{timestamp}"
        email = f"{username}@example.com"
        password = f"Test@{timestamp}"
        
        # Create registration payload with admin privileges
        register_payload = {
            "username": username,
            "email": email,
            "password": password,
            "admin": True  # Attempting to set admin privileges
        }
        
        self.logger.info(f"Attempting to register user '{username}' with admin privileges")
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=register_endpoint,
                json_data=register_payload
            )
            
            # Check if registration was successful
            if response.status_code in [200, 201, 204]:
                self.logger.info(f"Successfully registered user '{username}'")
                
                # Verify if the admin privileges were actually set
                debug_endpoint = self.debug_endpoint
                
                try:
                    # Add a small delay to allow the server to process the registration
                    time.sleep(1.0)
                    
                    verify_response = self._make_request(
                        method="GET",
                        endpoint=debug_endpoint
                    )
                    
                    if verify_response.status_code == 200:
                        try:
                            verify_data = verify_response.json()
                            users = []
                            if isinstance(verify_data, dict) and "users" in verify_data:
                                users = verify_data["users"]
                            elif isinstance(verify_data, list):
                                users = verify_data
                            
                            # Find the newly registered user
                            for user in users:
                                if user.get("username") == username:
                                    # Check if admin privileges were set
                                    if user.get("admin") is True:
                                        # Admin privileges were successfully set - add finding
                                        self.add_finding(
                                            vulnerability="Mass Assignment During Registration",
                                            severity="CRITICAL",
                                            endpoint=register_endpoint,
                                            details=f"The API allows setting admin privileges during user registration via mass assignment.",
                                            evidence={
                                                "request": {
                                                    "method": "POST",
                                                    "endpoint": register_endpoint,
                                                    "payload": register_payload
                                                },
                                                "response": {
                                                    "status_code": response.status_code,
                                                    "body": response.text[:1000]  # Limit response size
                                                },
                                                "verification": {
                                                    "user": username,
                                                    "admin_status": user.get("admin")
                                                }
                                            },
                                            remediation="Implement proper server-side filtering of request parameters during registration to prevent setting of sensitive fields like 'admin'."
                                        )
                                        return
                                    else:
                                        self.logger.info(f"User '{username}' was registered but admin privileges were not set")
                                        
                                        # Now try to register another user with admin=false to see if we can control it
                                        self._test_registration_with_admin_false()
                                        return
                            
                            self.logger.warn(f"Could not find newly registered user '{username}' in the user list")
                        except (ValueError, KeyError) as e:
                            self.logger.warn(f"Error parsing verification response: {str(e)}")
                    else:
                        self.logger.warn(f"Failed to verify registration, status code: {verify_response.status_code}")
                except Exception as e:
                    self.logger.error(f"Error verifying registration: {str(e)}")
            else:
                self.logger.info(f"Registration with admin privileges was rejected with status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error attempting registration with admin privileges: {str(e)}")
    
    def _test_registration_with_admin_false(self) -> None:
        """Test registration with admin=false to verify control over the field."""
        timestamp = int(time.time())
        username = f"test_mass_reg_false_{timestamp}"
        email = f"{username}@example.com"
        password = f"Test@{timestamp}"
        
        # Create registration payload with admin=false
        register_payload = {
            "username": username,
            "email": email,
            "password": password,
            "admin": False  # Explicitly setting admin to false
        }
        
        self.logger.info(f"Attempting to register user '{username}' with admin=false")
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=register_payload
            )
            
            # Check if registration was successful
            if response.status_code in [200, 201, 204]:
                self.logger.info(f"Successfully registered user '{username}' with admin=false")
                
                # Verify if the admin field was respected
                try:
                    # Add a small delay to allow the server to process the registration
                    time.sleep(1.0)
                    
                    verify_response = self._make_request(
                        method="GET",
                        endpoint=self.debug_endpoint
                    )
                    
                    if verify_response.status_code == 200:
                        try:
                            verify_data = verify_response.json()
                            users = []
                            if isinstance(verify_data, dict) and "users" in verify_data:
                                users = verify_data["users"]
                            elif isinstance(verify_data, list):
                                users = verify_data
                            
                            # Find the newly registered user
                            for user in users:
                                if user.get("username") == username:
                                    # Check if admin=false was respected
                                    if user.get("admin") is False:
                                        # This confirms we have control over the admin field
                                        self.add_finding(
                                            vulnerability="Mass Assignment During Registration",
                                            severity="CRITICAL",
                                            endpoint=self.register_endpoint,
                                            details=f"The API allows controlling the 'admin' field during user registration. While we couldn't set it to true, we confirmed we can set it to false, indicating mass assignment vulnerability.",
                                            evidence={
                                                "request": {
                                                    "method": "POST",
                                                    "endpoint": self.register_endpoint,
                                                    "payload": register_payload
                                                },
                                                "response": {
                                                    "status_code": response.status_code,
                                                    "body": response.text[:1000]  # Limit response size
                                                },
                                                "verification": {
                                                    "user": username,
                                                    "admin_status": user.get("admin")
                                                }
                                            },
                                            remediation="Implement proper server-side filtering of request parameters during registration to prevent setting of sensitive fields like 'admin'."
                                        )
                                        return
                        except (ValueError, KeyError) as e:
                            self.logger.warn(f"Error parsing verification response: {str(e)}")
                    else:
                        self.logger.warn(f"Failed to verify registration, status code: {verify_response.status_code}")
                except Exception as e:
                    self.logger.error(f"Error verifying registration: {str(e)}")
            else:
                self.logger.info(f"Registration with admin=false was rejected with status code: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error attempting registration with admin=false: {str(e)}")
    
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
        self.create_endpoint = find_endpoint_by_purpose(endpoints, "create_user", self.create_endpoint)
        self.update_endpoint = find_endpoint_by_purpose(endpoints, "update_user", self.update_endpoint)
        self.get_endpoint = find_endpoint_by_purpose(endpoints, "get_user", self.get_endpoint)
    
    def _test_create_update_flow(self) -> None:
        """Test the create and update flow for mass assignment vulnerabilities."""
        self.logger.info("Testing create and update flow for mass assignment")
        
        # Step 1: Create a normal user
        user_id = None
        create_payload = self.create_user_payload.copy()
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.create_endpoint,
                json_data=create_payload
            )
            
            if response.status_code in [200, 201]:
                self.logger.info("Successfully created test user")
                
                # Try to get the user ID from the response
                try:
                    data = response.json()
                    user_id = data.get(self.id_field)
                    if not user_id:
                        # Try common variations
                        for field in ["id", "userId", "user_id", "_id"]:
                            if field in data:
                                user_id = data[field]
                                break
                    
                    if not user_id:
                        self.logger.warn(f"Could not find user ID in response: {data}")
                        return
                except (ValueError, KeyError) as e:
                    self.logger.warn(f"Error parsing user creation response: {str(e)}")
                    return
            else:
                self.logger.warn(f"Failed to create test user, status code: {response.status_code}")
                return
        except Exception as e:
            self.logger.error(f"Error creating test user: {str(e)}")
            return
        
        # Step 2: Try to update the user with sensitive fields
        if user_id:
            update_endpoint = self.update_endpoint.replace("{id}", str(user_id))
            
            for field in self.sensitive_fields:
                update_payload = {
                    field: self.test_values.get(field, True)
                }
                
                try:
                    response = self._make_request(
                        method="PUT",  # or PATCH
                        endpoint=update_endpoint,
                        json_data=update_payload
                    )
                    
                    # Check if the update was successful
                    if response.status_code in [200, 201, 204]:
                        # Step 3: Verify if the field was actually set
                        get_endpoint = self.get_endpoint.replace("{id}", str(user_id))
                        
                        try:
                            verify_response = self._make_request(
                                method="GET",
                                endpoint=get_endpoint
                            )
                            
                            if verify_response.status_code == 200:
                                try:
                                    verify_data = verify_response.json()
                                    if field in verify_data and verify_data[field] == update_payload[field]:
                                        # Field was successfully set
                                        self.add_finding(
                                            vulnerability="Mass Assignment",
                                            severity="HIGH",
                                            endpoint=update_endpoint,
                                            details=f"The API allows setting the sensitive field '{field}' via mass assignment, which could lead to privilege escalation.",
                                            evidence={
                                                "request": {
                                                    "method": "PUT",
                                                    "endpoint": update_endpoint,
                                                    "payload": update_payload
                                                },
                                                "response": {
                                                    "status_code": response.status_code,
                                                    "body": response.text[:1000]  # Limit response size
                                                },
                                                "verification": {
                                                    "endpoint": get_endpoint,
                                                    "status_code": verify_response.status_code,
                                                    "field_value": verify_data.get(field)
                                                }
                                            },
                                            remediation="Implement proper server-side filtering of request parameters to prevent setting of sensitive fields."
                                        )
                                except (ValueError, KeyError) as e:
                                    self.logger.warn(f"Error parsing verification response: {str(e)}")
                        except Exception as e:
                            self.logger.error(f"Error verifying field: {str(e)}")
                    
                except Exception as e:
                    self.logger.error(f"Error testing field '{field}': {str(e)}")
                
                # Add delay between requests
                time.sleep(0.5)
    
    def _test_role_change_vulnerability(self) -> None:
        """Test for vulnerabilities that allow changing user roles between admin and regular user."""
        self.logger.info("Testing for role change vulnerabilities (admin to regular user and vice versa)")
        
        # Step 1: Get existing accounts to find admin and regular users
        debug_endpoint = "/users/v1/_debug"  # Endpoint to retrieve user accounts
        admin_user = None
        regular_user = None
        
        try:
            response = self._make_request(
                method="GET",
                endpoint=debug_endpoint
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Handle different response formats
                    users = []
                    if isinstance(data, dict) and "users" in data:
                        users = data["users"]
                    elif isinstance(data, list):
                        users = data
                    
                    # Find an admin user and a regular user
                    for user in users:
                        # Check for common admin field names
                        is_admin = False
                        for field in ["admin", "is_admin", "isAdmin", "role"]:
                            if field in user and user[field] in [True, "admin", "administrator"]:
                                is_admin = True
                                break
                        
                        if is_admin and not admin_user:
                            admin_user = user
                        elif not is_admin and not regular_user:
                            regular_user = user
                        
                        if admin_user and regular_user:
                            break
                    
                    self.logger.info(f"Found admin user: {admin_user is not None}, regular user: {regular_user is not None}")
                except (ValueError, KeyError) as e:
                    self.logger.error(f"Error parsing user data: {str(e)}")
                    return
            else:
                self.logger.warn(f"Failed to get user accounts, status code: {response.status_code}")
                return
        except Exception as e:
            self.logger.error(f"Error accessing debug endpoint: {str(e)}")
            return
        
        # If we couldn't find both types of users, we can't proceed
        if not admin_user or not regular_user:
            self.logger.warn("Could not find both admin and regular users to test role change")
            return
        
        # Step 2: Test changing a regular user to admin
        self._test_change_user_role(regular_user, True)
        
        # Step 3: Test changing an admin user to regular
        self._test_change_user_role(admin_user, False)
    
    def _test_change_user_role(self, user: Dict[str, Any], make_admin: bool) -> None:
        """Test changing a user's role between admin and regular user.
        
        Args:
            user: The user to modify
            make_admin: True to make the user an admin, False to make the user regular
        """
        # Determine the username and current admin status
        username = None
        for field in ["username", "user", "name", "id"]:
            if field in user:
                username = user[field]
                break
        
        if not username:
            self.logger.warn("Could not determine username for role change test")
            return
        
        # Determine which admin field to use
        admin_field = None
        for field in ["admin", "is_admin", "isAdmin", "role"]:
            if field in user:
                admin_field = field
                break
        
        if not admin_field:
            self.logger.warn("Could not determine admin field for role change test")
            return
        
        # Prepare the update endpoint and payload
        # Use a dynamic endpoint if available, otherwise fall back to a default pattern
        update_endpoint = self.update_endpoint.replace("{id}", str(username)) if "{id}" in self.update_endpoint else f"/users/v1/{username}"
        
        # Create payload based on the admin field type
        update_payload = {}
        if admin_field == "role":
            update_payload[admin_field] = "admin" if make_admin else "user"
        else:
            update_payload[admin_field] = make_admin
        
        self.logger.info(f"Attempting to {'make admin' if make_admin else 'revoke admin'} for user '{username}'")
        
        # Try different HTTP methods
        for method in ["PUT", "PATCH", "POST"]:
            try:
                response = self._make_request(
                    method=method,
                    endpoint=update_endpoint,
                    json_data=update_payload
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    self.logger.info(f"Successfully sent {method} request to change role for user '{username}'")
                    
                    # Verify the role change
                    try:
                        verify_response = self._make_request(
                            method="GET",
                            endpoint=self.debug_endpoint
                        )
                        
                        if verify_response.status_code == 200:
                            try:
                                verify_data = verify_response.json()
                                users = []
                                if isinstance(verify_data, dict) and "users" in verify_data:
                                    users = verify_data["users"]
                                elif isinstance(verify_data, list):
                                    users = verify_data
                                
                                # Find the user and check if the role was changed
                                for u in users:
                                    user_match = False
                                    for field in ["username", "user", "name", "id"]:
                                        if field in u and u[field] == username:
                                            user_match = True
                                            break
                                    
                                    if user_match:
                                        role_changed = False
                                        if admin_field in u:
                                            if admin_field == "role":
                                                role_changed = (u[admin_field] == "admin") == make_admin
                                            else:
                                                role_changed = u[admin_field] == make_admin
                                        
                                        if role_changed:
                                            # Role was successfully changed - add finding
                                            self.add_finding(
                                                vulnerability="Role Change via Mass Assignment",
                                                severity="CRITICAL",
                                                endpoint=update_endpoint,
                                                details=f"The API allows {'elevating privileges' if make_admin else 'demoting privileges'} by directly modifying the '{admin_field}' field.",
                                                evidence={
                                                    "request": {
                                                        "method": method,
                                                        "endpoint": update_endpoint,
                                                        "payload": update_payload
                                                    },
                                                    "response": {
                                                        "status_code": response.status_code,
                                                        "body": response.text[:1000]  # Limit response size
                                                    },
                                                    "verification": {
                                                        "original_value": not make_admin if admin_field == "role" else make_admin,
                                                        "new_value": u[admin_field]
                                                    }
                                                },
                                                remediation="Implement proper authorization checks and server-side filtering to prevent unauthorized role changes."
                                            )
                                            return  # Found the vulnerability, no need to try other methods
                            except (ValueError, KeyError) as e:
                                self.logger.warn(f"Error parsing verification response: {str(e)}")
                        else:
                            self.logger.warn(f"Failed to verify role change, status code: {verify_response.status_code}")
                    except Exception as e:
                        self.logger.error(f"Error verifying role change: {str(e)}")
                else:
                    self.logger.info(f"{method} request to change role was rejected with status code: {response.status_code}")
            except Exception as e:
                self.logger.error(f"Error attempting to change role with {method}: {str(e)}")
            
            # Add delay between requests
            time.sleep(0.5)
    

