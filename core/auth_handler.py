"""
Authentication Handler for Scanner API

This module provides utilities for handling authentication across different scanners,
including intelligent token handling and authentication status detection.
"""

import logging
import json
import re
import time
from typing import Dict, List, Any, Optional, Tuple, Union
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

class AuthHandler:
    """
    Handles authentication logic across different scanners, including
    intelligent detection of authentication requirements based on response status codes.
    """
    
    def __init__(self, base_url: str, auth_config: Dict[str, Any]):
        """
        Initialize the authentication handler.
        
        Args:
            base_url: The base URL of the API
            auth_config: Authentication configuration from the scanner config
        """
        self.base_url = base_url.rstrip('/')
        self.auth_config = auth_config
        self.token = None
        self.token_type = "Bearer"
        self.auth_required_status_codes = [401, 403, 404]  # Status codes that might indicate auth is required
        self.auth_success_status_codes = [200, 201, 204]   # Status codes indicating successful auth
        
        # Extract auth config
        self.auth_type = auth_config.get("type", "none").lower()
        self.login_endpoint = auth_config.get("login_endpoint", "")
        self.username_field = auth_config.get("username_field", "username")
        self.password_field = auth_config.get("password_field", "password")
        self.token_field = auth_config.get("token_field", "token")
        self.credentials = auth_config.get("credentials", {})
        
        # Headers
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Session for requests
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get_auth_token(self) -> Optional[str]:
        """
        Get the authentication token.
        
        Returns:
            The authentication token or None if not available
        """
        if self.token:
            return self.token
            
        if self.auth_type == "none":
            logger.info("No authentication required")
            return None
            
        if not self.login_endpoint:
            logger.warning("No login endpoint specified, cannot authenticate")
            return None
            
        if not self.credentials:
            logger.warning("No credentials specified, cannot authenticate")
            return None
            
        # Attempt to get token
        try:
            logger.info(f"Attempting to get authentication token from {self.login_endpoint}")
            
            # Construct login URL
            login_url = f"{self.base_url}/{self.login_endpoint.lstrip('/')}"
            
            # Prepare credentials
            username = self.credentials.get("username", self.credentials.get("email", ""))
            password = self.credentials.get("password", "")
            
            if not username or not password:
                logger.warning("Username or password not specified, cannot authenticate")
                return None
                
            # Prepare login payload
            payload = {
                self.username_field: username,
                self.password_field: password
            }
            
            # Make login request
            response = self.session.post(
                login_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )
            
            # Check response
            if response.status_code in self.auth_success_status_codes:
                try:
                    response_json = response.json()
                    
                    # Extract token
                    if self.token_field in response_json:
                        self.token = response_json[self.token_field]
                    else:
                        # Try to find token in nested objects
                        for key, value in response_json.items():
                            if isinstance(value, dict) and self.token_field in value:
                                self.token = value[self.token_field]
                                break
                                
                    if self.token:
                        logger.info("Successfully obtained authentication token")
                        return self.token
                    else:
                        logger.warning(f"Token field '{self.token_field}' not found in response")
                        logger.debug(f"Response: {response.text}")
                except ValueError:
                    logger.warning("Failed to parse JSON response from login endpoint")
                    logger.debug(f"Response: {response.text}")
            else:
                logger.warning(f"Failed to authenticate: {response.status_code} {response.reason}")
                logger.debug(f"Response: {response.text}")
                
        except RequestException as e:
            logger.warning(f"Error during authentication: {e}")
            
        return None
    
    def get_auth_header(self) -> Dict[str, str]:
        """
        Get the authentication header.
        
        Returns:
            The authentication header or an empty dict if not available
        """
        token = self.get_auth_token()
        if not token:
            return {}
            
        if self.auth_type == "bearer":
            return {"Authorization": f"Bearer {token}"}
        elif self.auth_type == "token":
            return {"Authorization": f"Token {token}"}
        elif self.auth_type == "apikey":
            return {"X-API-Key": token}
        else:
            return {"Authorization": token}
    
    def is_auth_required(self, response: requests.Response) -> bool:
        """
        Determine if authentication is required based on the response.
        
        Args:
            response: The HTTP response
            
        Returns:
            True if authentication is required, False otherwise
        """
        # Check status code
        if response.status_code in self.auth_required_status_codes:
            # Check response body for auth-related messages
            try:
                response_json = response.json()
                error_message = response_json.get("message", "").lower()
                error_type = response_json.get("type", "").lower()
                error_description = response_json.get("description", "").lower()
                
                auth_keywords = ["unauthorized", "unauthenticated", "authentication required", 
                                "not authenticated", "login required", "auth", "token"]
                
                for keyword in auth_keywords:
                    if (keyword in error_message or 
                        keyword in error_type or 
                        keyword in error_description):
                        return True
                        
            except (ValueError, AttributeError):
                # If we can't parse JSON, check the text
                response_text = response.text.lower()
                auth_keywords = ["unauthorized", "unauthenticated", "authentication required", 
                                "not authenticated", "login required", "auth", "token"]
                                
                for keyword in auth_keywords:
                    if keyword in response_text:
                        return True
        
        # Special case for 404 - might be a protected resource
        if response.status_code == 404:
            # Try to determine if this is a real 404 or just a protected resource
            # This is a heuristic and might need adjustment based on the API
            try:
                response_json = response.json()
                # If the response is JSON, it might be a protected resource
                # Real 404s often return HTML or plain text
                if isinstance(response_json, dict):
                    return True
            except (ValueError, AttributeError):
                pass
                
        return False
    
    def handle_auth_for_request(self, 
                               method: str, 
                               endpoint: str, 
                               data: Optional[Dict[str, Any]] = None,
                               params: Optional[Dict[str, Any]] = None,
                               headers: Optional[Dict[str, str]] = None,
                               retry_auth: bool = True) -> Tuple[requests.Response, bool]:
        """
        Handle authentication for a request, retrying with auth if needed.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request data
            params: Query parameters
            headers: Request headers
            retry_auth: Whether to retry with authentication if initial request fails
            
        Returns:
            Tuple of (response, auth_used) where auth_used is True if authentication was used
        """
        # Prepare request
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        request_headers = self.headers.copy()
        if headers:
            request_headers.update(headers)
            
        # First try without authentication
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    headers=request_headers,
                    timeout=10
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    json=data,
                    params=params,
                    headers=request_headers,
                    timeout=10
                )
            elif method.upper() == "PUT":
                response = self.session.put(
                    url,
                    json=data,
                    params=params,
                    headers=request_headers,
                    timeout=10
                )
            elif method.upper() == "DELETE":
                response = self.session.delete(
                    url,
                    json=data,
                    params=params,
                    headers=request_headers,
                    timeout=10
                )
            else:
                logger.warning(f"Unsupported HTTP method: {method}")
                return None, False
                
            # Check if authentication is required
            if retry_auth and self.is_auth_required(response):
                logger.info(f"Authentication required for {endpoint}, retrying with auth")
                
                # Get auth header
                auth_header = self.get_auth_header()
                if not auth_header:
                    logger.warning("Failed to get authentication header")
                    return response, False
                    
                # Update headers with auth
                request_headers.update(auth_header)
                
                # Retry with authentication
                if method.upper() == "GET":
                    response = self.session.get(
                        url,
                        params=params,
                        headers=request_headers,
                        timeout=10
                    )
                elif method.upper() == "POST":
                    response = self.session.post(
                        url,
                        json=data,
                        params=params,
                        headers=request_headers,
                        timeout=10
                    )
                elif method.upper() == "PUT":
                    response = self.session.put(
                        url,
                        json=data,
                        params=params,
                        headers=request_headers,
                        timeout=10
                    )
                elif method.upper() == "DELETE":
                    response = self.session.delete(
                        url,
                        json=data,
                        params=params,
                        headers=request_headers,
                        timeout=10
                    )
                    
                return response, True
                
            return response, False
            
        except RequestException as e:
            logger.warning(f"Error during request: {e}")
            return None, False
    
    def test_endpoint_auth_requirements(self, endpoint: str) -> Dict[str, Any]:
        """
        Test an endpoint to determine its authentication requirements.
        
        Args:
            endpoint: The endpoint to test
            
        Returns:
            A dictionary with authentication requirement details
        """
        results = {
            "endpoint": endpoint,
            "auth_required": False,
            "auth_type": None,
            "status_without_auth": None,
            "status_with_auth": None,
            "supports_bearer_token": False,
            "supports_api_key": False
        }
        
        # Test without auth
        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            response = self.session.get(
                url,
                headers=self.headers,
                timeout=10
            )
            
            results["status_without_auth"] = response.status_code
            
            # Check if auth is required
            auth_required = self.is_auth_required(response)
            results["auth_required"] = auth_required
            
            if auth_required:
                # Test with bearer token
                token = self.get_auth_token()
                if token:
                    bearer_headers = self.headers.copy()
                    bearer_headers["Authorization"] = f"Bearer {token}"
                    
                    bearer_response = self.session.get(
                        url,
                        headers=bearer_headers,
                        timeout=10
                    )
                    
                    results["status_with_auth"] = bearer_response.status_code
                    results["supports_bearer_token"] = bearer_response.status_code in self.auth_success_status_codes
                    
                    if results["supports_bearer_token"]:
                        results["auth_type"] = "bearer"
                
        except RequestException as e:
            logger.warning(f"Error testing endpoint auth requirements: {e}")
            
        return results


def create_auth_handler(base_url: str, auth_config: Dict[str, Any]) -> AuthHandler:
    """
    Create an authentication handler.
    
    Args:
        base_url: The base URL of the API
        auth_config: Authentication configuration from the scanner config
        
    Returns:
        An AuthHandler instance
    """
    return AuthHandler(base_url, auth_config)
