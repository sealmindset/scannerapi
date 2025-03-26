"""
Base scanner class for the API Security Scanner.

This module provides the base class for all vulnerability scanner modules.
"""

import json
import time
import os
import uuid
import datetime
import random
import string
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Tuple

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

from core.logger import get_logger
from core.exceptions import (
    ScannerExecutionError,
    ScannerConnectionError,
    ScannerAuthenticationError,
    ScannerTimeoutError,
    ScannerRateLimitError
)
from core.auth_handler import create_auth_handler, AuthHandler

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


class BaseScanner(ABC):
    """Base class for all vulnerability scanner modules."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the base scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        self.target = target
        self.config = config
        self.base_url = target.get("base_url", "")
        self.auth = target.get("auth", {"type": "none"})
        self.headers = target.get("headers", {})
        self.timeout = target.get("timeout", 30)
        self.verify_ssl = target.get("verify_ssl", True)
        self.findings = []
        self.logger = get_logger(self.__class__.__name__)
        
        # Simulation mode has been completely removed
        # All scanners now use real requests and responses in production environments
        
        # Option to disable fallback endpoints
        self.disable_fallback_endpoints = target.get("disable_fallback_endpoints", False)
        
        if self.disable_fallback_endpoints:
            self.logger.info("Fallback endpoints disabled - only testing endpoints from OpenAPI specification")
        
        # Set up session with common configuration
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Configure authentication
        self._setup_auth()
    
    def _setup_auth(self) -> None:
        """Set up authentication for API requests."""
        # Create the auth handler
        self.auth_handler = create_auth_handler(self.base_url, self.auth)
        
        # Set up the session with initial auth headers if available
        auth_headers = self.auth_handler.get_auth_header()
        if auth_headers:
            self.session.headers.update(auth_headers)
            self.logger.debug(f"Using authentication headers: {auth_headers}")
        else:
            self.logger.debug("No initial authentication headers configured")
            
        # Log the authentication type
        auth_type = self.auth.get("type", "none")
        if auth_type == "basic":
            username = self.auth.get("username", "")
            self.logger.debug(f"Using Basic authentication for {username}")
        elif auth_type == "bearer":
            self.logger.debug("Using Bearer token authentication")
        elif auth_type == "api_key":
            header_name = self.auth.get("header_name", "X-API-Key")
            self.logger.debug(f"Using API Key authentication with header {header_name}")
        elif auth_type == "none":
            self.logger.debug("No authentication configured")
        else:
            self.logger.warn(f"Unsupported authentication type: {auth_type}")
            
    def _get_full_url(self, endpoint: str) -> str:
        """
        Get the full URL for an endpoint.
        
        Args:
            endpoint: The endpoint path
            
        Returns:
            The full URL
        """
        base_url = self.base_url.rstrip('/')
        endpoint = endpoint.lstrip('/')
        return f"{base_url}/{endpoint}"
    
    def get_or_create_test_account(self, endpoint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get a cached test account or create a new one if none exists.
        
        This helper method can be used by all scanners to get or create test accounts,
        which improves efficiency and reliability when testing APIs that have rate
        limiting or other restrictions.
        
        Args:
            endpoint: Optional endpoint for which the account was created
            
        Returns:
            A dictionary containing account credentials if successful, None otherwise
        """
        # Check if we have common fields configured
        if not hasattr(self, 'username_field') or not hasattr(self, 'password_field'):
            # Get common fields from config
            self.register_endpoint = self.config.get("register_endpoint", "users")
            self.login_endpoint = self.config.get("login_endpoint", "login")
            self.username_field = self.config.get("username_field", "username")
            self.email_field = self.config.get("email_field", "email")
            self.password_field = self.config.get("password_field", "password")
            self.additional_fields = self.config.get("additional_fields", {})
            
            # Initialize created accounts list
            if not hasattr(self, 'created_accounts'):
                self.created_accounts = []
        
        # Use the provided endpoint or the register endpoint
        target_endpoint = endpoint or getattr(self, 'register_endpoint', None)
        if not target_endpoint:
            self.logger.warning("No registration endpoint configured, cannot create test account")
            return None
            
        # First check if we have a cached account for this endpoint
        cached_account = account_cache.get_account(target_endpoint)
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
        
        payload = {
            self.username_field: username,
            self.email_field: email,
            self.password_field: password
        }
        
        # Add additional fields
        payload.update(self.additional_fields)
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=target_endpoint,
                json_data=payload
            )
            
            if response.status_code < 400:  # Any 2xx or 3xx status code
                account_data = {
                    "username": username,
                    "email": email,
                    "password": password,
                    "endpoint": target_endpoint,
                    "created_by": self.__class__.__name__,
                    "response_code": response.status_code
                }
                
                # Add to global account cache
                account_cache.add_account(account_data)
                
                # Add to local created accounts list
                if hasattr(self, 'created_accounts'):
                    self.created_accounts.append(account_data)
                
                self.logger.info(f"Successfully created test account: {username}")
                return account_data
            else:
                self.logger.warning(f"Failed to create test account: {username}, status code: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error creating test account: {str(e)}")
            return None
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Any = None,
        json_data: Any = None,
        params: Dict = None,
        headers: Dict = None,
        timeout: int = None,
        verify: bool = None,
        allow_redirects: bool = True,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        capture_for_evidence: bool = False,
        try_auth_if_needed: bool = True
    ) -> requests.Response:
        """
        Make an HTTP request to the target API.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint (will be appended to base_url)
            data: Request data
            json_data: JSON request data
            params: Query parameters
            headers: Additional headers
            timeout: Request timeout
            verify: Verify SSL certificates
            allow_redirects: Follow redirects
            max_retries: Maximum number of retries
            retry_delay: Delay between retries
            
        Returns:
            Response object
            
        Raises:
            ScannerConnectionError: If connection fails
            ScannerTimeoutError: If request times out
            ScannerAuthenticationError: If authentication fails
            ScannerRateLimitError: If rate limit is exceeded
            ScannerExecutionError: For other request errors
        """
        # Simulation mode has been removed to ensure only real requests are made
        # All scanners will now use real requests and responses in production environments
            
        # Use default values if not specified
        timeout = timeout if timeout is not None else self.timeout
        verify = verify if verify is not None else self.verify_ssl
        
        # Build URL
        url = f"{self.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Merge headers
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Log request details
        self.logger.debug(
            f"Making {method} request to {url}",
            extra={
                "url": url,
                "method": method,
                "headers": request_headers,
                "params": params,
                "data": data,
                "json": json_data
            }
        )
        
        # Store request details for evidence if needed
        request_details = {
            "method": method,
            "url": url,
            "headers": dict(request_headers) if request_headers else {},
            "params": params,
            "data": data,
            "json": json_data
        } if capture_for_evidence else None
        
        # If we should try authentication intelligently
        if try_auth_if_needed:
            # Use the auth handler to make the request with intelligent auth handling
            response, auth_used = self.auth_handler.handle_auth_for_request(
                method=method,
                endpoint=endpoint,
                data=json_data if json_data else data,
                params=params,
                headers=request_headers,
                retry_auth=True
            )
            
            if response:
                if auth_used:
                    self.logger.debug(f"Request to {endpoint} used authentication after detecting it was required")
                
                # Store response details for evidence if needed
                if capture_for_evidence:
                    response_details = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "content_length": len(response.content),
                        "elapsed": response.elapsed.total_seconds(),
                        "body": response.text[:10000] if hasattr(response, 'text') else "<binary content>"
                    }
                    
                    # Return both the response and the captured details
                    response._request_details = request_details
                    response._response_details = response_details
                
                return response
        
        # Fall back to regular request handling if auth handler didn't work or we're not using it
        retries = 0
        while retries <= max_retries:
            try:
                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                    allow_redirects=allow_redirects
                )
                
                # Log response details
                self.logger.debug(
                    f"Received response: {response.status_code}",
                    extra={
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "content_length": len(response.content),
                        "elapsed": response.elapsed.total_seconds()
                    }
                )
                
                # Store response details for evidence if needed
                if capture_for_evidence:
                    response_details = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "content_length": len(response.content),
                        "elapsed": response.elapsed.total_seconds(),
                        "body": response.text[:10000] if hasattr(response, 'text') else "<binary content>"
                    }
                    
                    # Return both the response and the captured details
                    response._request_details = request_details
                    response._response_details = response_details
                
                # Handle common status codes
                if response.status_code == 401:
                    raise ScannerAuthenticationError(f"Authentication failed: {response.text}")
                
                elif response.status_code == 429:
                    if retries < max_retries:
                        retry_after = response.headers.get("Retry-After")
                        if retry_after and retry_after.isdigit():
                            wait_time = int(retry_after)
                        else:
                            wait_time = retry_delay * (2 ** retries)  # Exponential backoff
                        
                        self.logger.warn(f"Rate limit exceeded, retrying in {wait_time} seconds")
                        time.sleep(wait_time)
                        retries += 1
                        continue
                    else:
                        raise ScannerRateLimitError(f"Rate limit exceeded: {response.text}")
                
                return response
                
            except ConnectionError as e:
                if retries < max_retries:
                    wait_time = retry_delay * (2 ** retries)
                    self.logger.warn(f"Connection error, retrying in {wait_time} seconds: {str(e)}")
                    time.sleep(wait_time)
                    retries += 1
                    continue
                else:
                    raise ScannerConnectionError(f"Connection failed: {str(e)}")
                    
            except Timeout as e:
                if retries < max_retries:
                    wait_time = retry_delay * (2 ** retries)
                    self.logger.warn(f"Request timed out, retrying in {wait_time} seconds: {str(e)}")
                    time.sleep(wait_time)
                    retries += 1
                    continue
                else:
                    raise ScannerTimeoutError(f"Request timed out: {str(e)}")
                    
            except RequestException as e:
                if retries < max_retries:
                    wait_time = retry_delay * (2 ** retries)
                    self.logger.warn(f"Request error, retrying in {wait_time} seconds: {str(e)}")
                    time.sleep(wait_time)
                    retries += 1
                    continue
                else:
                    raise ScannerExecutionError(f"Request failed: {str(e)}")
    
    def add_finding(
        self,
        vulnerability: str,
        severity: str,
        endpoint: str,
        details: str,
        evidence: Any = None,
        remediation: str = None,
        request_data: Dict[str, Any] = None,
        response_data: Dict[str, Any] = None
    ) -> None:
        """
        Add a vulnerability finding.
        
        Args:
            vulnerability: Vulnerability name/type
            severity: Severity level (HIGH, MEDIUM, LOW, INFO)
            endpoint: Affected endpoint
            details: Detailed description of the vulnerability
            evidence: Evidence of the vulnerability (e.g., response data)
            remediation: Recommended remediation steps
        """
        # Generate a unique finding ID if not already in evidence
        finding_id = evidence.get("finding_id", str(uuid.uuid4())[:8]) if evidence else str(uuid.uuid4())[:8]
        
        # Save evidence to file if request and response data are provided
        evidence_file = None
        if request_data and response_data:
            evidence_file = self.save_evidence_to_file(finding_id, request_data, response_data)
            
            # Add evidence file to evidence if it's not already there
            if evidence and isinstance(evidence, dict):
                evidence["evidence_file"] = evidence.get("evidence_file", evidence_file)
            elif evidence is None:
                evidence = {"evidence_file": evidence_file}
        
        finding = {
            "vulnerability": vulnerability,
            "severity": severity,
            "endpoint": endpoint,
            "details": details,
            "timestamp": time.time(),
            "evidence": evidence,
            "remediation": remediation,
            "finding_id": finding_id
        }
        
        self.findings.append(finding)
        
        self.logger.info(
            f"Found {severity} severity vulnerability: {vulnerability} at {endpoint}",
            extra={"finding": finding}
        )
    
    @abstractmethod
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        pass
    
    def save_evidence_to_file(self, finding_id: str, request_data: Dict[str, Any], response_data: Dict[str, Any]) -> str:
        """
        Save request and response data to a JSON file as evidence.
        
        Args:
            finding_id: Unique identifier for the finding
            request_data: Request headers and body
            response_data: Response headers and body
            
        Returns:
            str: Path to the saved evidence file
        """
        # Create results directory if it doesn't exist
        results_dir = os.path.join(os.getcwd(), "results")
        os.makedirs(results_dir, exist_ok=True)
        
        # Generate timestamp for filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        
        # Generate filename
        scanner_name = self.__class__.__name__.lower()
        if scanner_name == "scanner" and "regex_dos" in self.__module__:
            # Special case for regex_dos scanner
            filename = f"regex_dos_{finding_id}_{timestamp}.json"
        else:
            # All other scanners
            filename = f"results_{timestamp}.json"
        
        filepath = os.path.join(results_dir, filename)
        
        # Prepare evidence data
        evidence_data = {
            "finding_id": finding_id,
            "scanner": self.__class__.__name__,
            "timestamp": timestamp,
            "request": request_data,
            "response": response_data
        }
        
        # Save to file
        with open(filepath, "w") as f:
            json.dump(evidence_data, f, indent=2)
        
        self.logger.info(f"Evidence saved to {filepath}")
        return filepath
    
    def cleanup(self) -> None:
        """Clean up resources after scanning."""
        self.session.close()
        self.logger.debug("Scanner cleanup completed")
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        try:
            self.cleanup()
        except:
            pass
