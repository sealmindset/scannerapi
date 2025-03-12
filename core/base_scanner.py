"""
Base scanner class for the API Security Scanner.

This module provides the base class for all vulnerability scanner modules.
"""

import json
import time
import os
import uuid
import datetime
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union

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
        
        # Support for simulation mode when the target server is not available
        self.simulate_server = target.get("simulate_server", False)
        self.simulate_vulnerabilities = config.get("simulate_vulnerabilities", False)
        
        if self.simulate_server:
            self.logger.info("Server simulation mode enabled - API responses will be simulated")
        if self.simulate_vulnerabilities:
            self.logger.info("Vulnerability simulation mode enabled - vulnerabilities will be simulated")
        
        # Set up session with common configuration
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        
        # Configure authentication
        self._setup_auth()
    
    def _setup_auth(self) -> None:
        """Set up authentication for API requests."""
        auth_type = self.auth.get("type", "none")
        
        if auth_type == "basic":
            username = self.auth.get("username", "")
            password = self.auth.get("password", "")
            self.session.auth = (username, password)
            self.logger.debug(f"Using Basic authentication for {username}")
        
        elif auth_type == "bearer":
            token = self.auth.get("token", "")
            self.session.headers.update({"Authorization": f"Bearer {token}"})
            self.logger.debug("Using Bearer token authentication")
        
        elif auth_type == "api_key":
            header_name = self.auth.get("header_name", "X-API-Key")
            header_value = self.auth.get("header_value", "")
            self.session.headers.update({header_name: header_value})
            self.logger.debug(f"Using API Key authentication with header {header_name}")
        
        elif auth_type == "none":
            self.logger.debug("No authentication configured")
        
        else:
            self.logger.warn(f"Unsupported authentication type: {auth_type}")
    
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
        capture_for_evidence: bool = False
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
        
        # Make request with retries
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
