"""
RegexDOS Scanner Module.

This module tests for Self-Denial of Service vulnerabilities via Regular Expression (RegexDOS),
where an API can be overwhelmed by sending input that causes excessive backtracking in regex
pattern matching, potentially leading to high CPU usage, timeouts, or application crashes.
"""

import json
import time
import random
import string
import traceback
import uuid
from typing import Dict, List, Any, Optional, Tuple

import requests
from requests.exceptions import Timeout, ConnectionError, RequestException

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting RegexDOS vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Initialize endpoints with default values
        self.email_update_endpoint = config.get("email_update_endpoint", "/users/v1/{username}/email")
        self.login_endpoint = config.get("login_endpoint", "/users/v1/login")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using email update endpoint: {self.email_update_endpoint}")
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        
        # Test parameters
        self.timeout_threshold = config.get("timeout_threshold", 5)  # Seconds
        self.max_string_length = config.get("max_string_length", 10000)
        self.stop_on_first_finding = config.get("stop_on_first_finding", True)  # Stop after finding first vulnerability
        self.test_string_pattern = config.get("test_string_pattern", "a")
        self.test_username = config.get("test_username", "testuser")
        self.test_password = config.get("test_password", "Password123!")
        self.test_email = config.get("test_email", "test@example.com")
        
        # Field names in requests/responses
        self.username_field = config.get("username_field", "username")
        self.password_field = config.get("password_field", "password")
        self.email_field = config.get("email_field", "email")
        self.token_field = config.get("token_field", "auth_token")
        
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
        
        # Use the utility function to find endpoints by purpose
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        
        # Look for email update endpoint using the utility function first
        email_update = find_endpoint_by_purpose(endpoints, "email_update", None)
        if email_update:
            self.email_update_endpoint = email_update
            self.logger.info(f"Found email update endpoint by purpose: {self.email_update_endpoint}")
            return
        
        # Fallback: Look for email update endpoint based on path patterns
        for endpoint in endpoints:
            path = endpoint.get("path", "").lower()
            method = endpoint.get("method", "").upper()
            description = endpoint.get("description", "").lower()
            operation_id = endpoint.get("operationId", "").lower()
            
            # Check various indicators that this might be an email update endpoint
            is_email_endpoint = (
                ("email" in path and "username" in path and method == "PUT") or
                ("email" in path and method == "PUT") or
                ("email" in description and "update" in description) or
                ("update" in operation_id and "email" in operation_id)
            )
            
            if is_email_endpoint:
                self.email_update_endpoint = endpoint.get("path")
                self.logger.info(f"Found email update endpoint by pattern matching: {self.email_update_endpoint}")
                break
        
        self.logger.info(f"Final resolved endpoints: login={self.login_endpoint}, register={self.register_endpoint}, email_update={self.email_update_endpoint}")
    
    def _register_test_user(self) -> Tuple[str, str]:
        """
        Register a test user for the RegexDOS tests.
        
        Returns:
            Tuple[str, str]: A tuple containing the username and password if registration was successful
            
        Raises:
            Exception: If registration fails
        """
        self.logger.info(f"Registering test user: {self.test_username}")
        
        # Generate unique username to avoid conflicts
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        username = f"{self.test_username}_{timestamp}_{random_suffix}"
        
        payload = {
            self.username_field: username,
            self.password_field: self.test_password,
            self.email_field: self.test_email
        }
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=payload
            )
            
            if response.status_code in [200, 201, 204]:
                self.logger.info(f"Successfully registered test user: {username}")
                self.test_username = username  # Update with the actual username used
                return username, self.test_password
            else:
                self.logger.warn(f"Failed to register test user, status code: {response.status_code}")
                raise Exception(f"User registration failed with status code: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error registering test user: {str(e)}")
            raise Exception(f"User registration failed: {str(e)}")
    
    def _login_test_user(self) -> Optional[str]:
        """
        Login as the test user to get an authentication token.
        
        Returns:
            Optional[str]: Authentication token if login was successful, None otherwise
        """
        self.logger.info(f"Logging in as test user: {self.test_username}")
        
        payload = {
            self.username_field: self.test_username,
            self.password_field: self.test_password
        }
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=payload
            )
            
            if response.status_code in [200, 201, 204]:
                try:
                    data = response.json()
                    token = None
                    
                    # Look for token in various fields
                    for field in [self.token_field, "token", "auth_token", "jwt", "access_token"]:
                        if field in data:
                            token = data[field]
                            break
                    
                    if token:
                        self.logger.info(f"Successfully logged in as test user: {self.test_username}")
                        return token
                    else:
                        self.logger.warn("Login successful but no token found in response")
                        return None
                except ValueError:
                    self.logger.warn("Login successful but response is not valid JSON")
                    return None
            else:
                self.logger.warn(f"Failed to login as test user, status code: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error logging in as test user: {str(e)}")
            return None
    
    def _test_regex_dos(self, auth_token: str) -> None:
        """
        Test for RegexDOS vulnerability by sending a long string to the email update endpoint.
        
        Args:
            auth_token: Authentication token for the test user
        """
        self.logger.info("Testing for RegexDOS vulnerability")
        self.logger.info(f"This scanner will run separately after all other scanners and will stop on first finding: {self.stop_on_first_finding}")
        
        # Prepare the endpoint with the actual username
        endpoint = self.email_update_endpoint.replace("{username}", self.test_username)
        
        # Set up authentication headers
        headers = {"Authorization": f"Bearer {auth_token}"}
        
        # Test with increasing string lengths to find the threshold
        # Start with the largest size first if stop_on_first_finding is enabled
        test_lengths = [self.max_string_length, 5000, 1000, 100] if self.stop_on_first_finding else [100, 1000, 5000, self.max_string_length]
        baseline_time = None
        vulnerability_found = False
        
        for length in test_lengths:
            if vulnerability_found:
                self.logger.info("Vulnerability found, stopping further tests as configured")
                break
                
            # Create a long string that will cause regex backtracking
            test_string = self.test_string_pattern * length + "!"
            
            payload = {
                self.email_field: test_string
            }
            
            self.logger.info(f"Testing with string length: {length}")
            
            try:
                start_time = time.time()
                
                # Set a timeout to avoid hanging indefinitely
                response = self._make_request(
                    method="PUT",
                    endpoint=endpoint,
                    json_data=payload,
                    headers=headers,
                    timeout=self.timeout_threshold * 2,  # Double the threshold to allow for measurement
                    capture_for_evidence=True  # Capture request/response for evidence
                )
                
                end_time = time.time()
                response_time = end_time - start_time
                
                self.logger.info(f"Response time: {response_time:.2f} seconds, Status code: {response.status_code}")
                
                # Set baseline time from the first request
                if baseline_time is None:
                    baseline_time = response_time
                
                # Check if response time is significantly longer than baseline
                if response_time > self.timeout_threshold or (baseline_time > 0 and response_time > baseline_time * 5):
                    # Extract request and response details captured by _make_request
                    request_data = getattr(response, '_request_details', {
                        "method": "PUT",
                        "url": f"{self.base_url}/{endpoint}",
                        "headers": headers,
                        "body": payload
                    })
                    
                    # Safely extract response data
                    response_data = getattr(response, '_response_details', {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": response.text[:10000] if hasattr(response, 'text') else "<binary content>"
                    })
                    
                    self.add_finding(
                        vulnerability="RegexDOS - Self-Denial of Service",
                        details=f"The API is vulnerable to RegexDOS attacks. A request with a {length}-character string took {response_time:.2f} seconds to process, which is significantly longer than the baseline time of {baseline_time:.2f} seconds.",
                        severity="HIGH",
                        endpoint=endpoint,
                        evidence={
                            "string_length": length,
                            "response_time": response_time,
                            "baseline_time": baseline_time,
                            "status_code": response.status_code
                        },
                        remediation="Implement proper input validation and use non-backtracking regex patterns or set appropriate timeout limits for regex operations. Consider using regex engines with backtracking protection or alternative validation methods.",
                        request_data=request_data,
                        response_data=response_data
                    )
                    vulnerability_found = True
                
            except Timeout:
                # Timeout exception indicates a potential vulnerability - this is a successful finding!
                self.logger.info(f"VULNERABILITY DETECTED: Request timed out after {self.timeout_threshold * 2} seconds with string length: {length}")
                self.logger.info("This timeout indicates a successful detection of a RegexDOS vulnerability")
                
                # Calculate the impact score based on string length and timeout
                impact_score = min(10, (length / 1000) * (self.timeout_threshold / 5) * 10)
                
                # Prepare request data for evidence
                request_data = {
                    "method": "PUT",
                    "url": f"{self.base_url}/{endpoint}",
                    "headers": headers,
                    "body": payload
                }
                
                # Prepare response data (in this case, a timeout occurred)
                response_data = {
                    "status": "timeout",
                    "timeout_value": self.timeout_threshold * 2,
                    "error": "Request timed out"
                }
                
                self.add_finding(
                    vulnerability="RegexDOS - Self-Denial of Service",
                    details=f"The API is vulnerable to RegexDOS attacks. A request with a {length}-character string caused a timeout after {self.timeout_threshold * 2} seconds. This indicates that the API's regex pattern is vulnerable to catastrophic backtracking, which can be exploited to cause denial of service.",
                    severity="CRITICAL",
                    endpoint=endpoint,
                    evidence={
                        "string_length": length,
                        "timeout": self.timeout_threshold * 2,
                        "baseline_time": baseline_time,
                        "impact_score": round(impact_score, 2),
                        "test_pattern": f"{self.test_string_pattern * min(10, length)}... (truncated)"
                    },
                    remediation="Implement proper input validation and use non-backtracking regex patterns or set appropriate timeout limits for regex operations. Consider using regex engines with backtracking protection or alternative validation methods. Specific recommendations:\n1. Use atomic grouping or possessive quantifiers if available\n2. Avoid nested repetition operators\n3. Implement request timeouts at the API level\n4. Consider using a regex validator library with DoS protection",
                    request_data=request_data,
                    response_data=response_data
                )
                vulnerability_found = True
                
                # We don't want to raise an exception here since this is an expected result
                # Just record the finding and continue
                return
                
            except (ConnectionError, RequestException) as e:
                # Connection error might indicate that the server crashed or became unresponsive - this is a successful finding!
                self.logger.info(f"VULNERABILITY DETECTED: Connection error with string length {length}: {str(e)}")
                self.logger.info("This connection error indicates a successful detection of a RegexDOS vulnerability that crashed the server")
                
                # Get the traceback for better error reporting
                tb = traceback.format_exc()
                self.logger.debug(f"Exception traceback: {tb}")
                
                # Calculate the impact score - connection errors are more severe than timeouts
                impact_score = min(10, (length / 1000) * (self.timeout_threshold / 3) * 10)
                
                # Prepare request data for evidence
                request_data = {
                    "method": "PUT",
                    "url": f"{self.base_url}/{endpoint}",
                    "headers": headers,
                    "body": payload
                }
                
                # Prepare response data (in this case, a connection error occurred)
                response_data = {
                    "status": "connection_error",
                    "error_type": e.__class__.__name__,
                    "error_message": str(e),
                    "traceback": traceback.format_exc()
                }
                
                self.add_finding(
                    vulnerability="RegexDOS - Server Crash",
                    details=f"The API is SEVERELY vulnerable to RegexDOS attacks. A request with a {length}-character string caused a connection error, indicating that the server crashed or became completely unresponsive. This is a critical vulnerability that can be easily exploited for denial of service attacks.",
                    severity="CRITICAL",
                    endpoint=endpoint,
                    evidence={
                        "string_length": length,
                        "error": str(e),
                        "error_type": e.__class__.__name__,
                        "baseline_time": baseline_time,
                        "impact_score": round(impact_score, 2),
                        "test_pattern": f"{self.test_string_pattern * min(10, length)}... (truncated)"
                    },
                    remediation="URGENT: Implement proper input validation and use non-backtracking regex patterns. This vulnerability allows an attacker to completely crash the service with a single request. Recommendations:\n1. Use atomic grouping or possessive quantifiers if available\n2. Avoid nested repetition operators\n3. Implement request timeouts at the API level\n4. Consider using a regex validator library with DoS protection\n5. Implement rate limiting and input size restrictions",
                    request_data=request_data,
                    response_data=response_data
                )
                vulnerability_found = True
                
                # We don't want to raise an exception here since this is an expected result
                # Just record the finding and continue
                return
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the RegexDOS scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting RegexDOS scanner")
        self.logger.info(f"This scanner will run separately after all other scanners and will stop on first finding: {self.stop_on_first_finding}")
        self.logger.info(f"Using timeout threshold of {self.timeout_threshold} seconds and max string length of {self.max_string_length}")
        
        try:
            # Register a test user if needed
            username = self.test_username
            password = self.test_password
            try:
                username, password = self._register_test_user()
                self.logger.info(f"Successfully registered test user: {username}")
            except Exception as e:
                self.logger.warn(f"Failed to register test user: {str(e)}, will attempt to use default credentials")
            
            # Login as the test user to get an authentication token
            auth_token = self._login_test_user()
            
            if not auth_token:
                self.logger.error("Failed to login as test user, skipping RegexDOS tests")
                self.add_finding(
                    vulnerability="RegexDOS Scanner Error",
                    details="The RegexDOS scanner failed to login as the test user. This may indicate an issue with the authentication system.",
                    severity="INFO",
                    endpoint=self.login_endpoint,
                    evidence={
                        "username": username
                    },
                    remediation="Check the login endpoint and authentication configuration."
                )
                return self.findings
            
            self.logger.info(f"Successfully logged in as test user: {username}")
            
            # Test for RegexDOS vulnerability
            self._test_regex_dos(auth_token)
            
            # If we didn't find any vulnerabilities but the test completed successfully
            if not self.findings:
                self.logger.info("No RegexDOS vulnerabilities found")
                self.add_finding(
                    vulnerability="RegexDOS - Not Vulnerable",
                    details=f"The API appears to be resistant to RegexDOS attacks. Tests with strings up to {self.max_string_length} characters did not trigger excessive processing times or timeouts.",
                    severity="INFO",
                    endpoint=self.email_update_endpoint.replace("{username}", username),
                    evidence={
                        "max_string_length_tested": self.max_string_length,
                        "timeout_threshold": self.timeout_threshold,
                        "test_username": username
                    },
                    remediation="No remediation required. Continue to monitor for regex performance issues during development."
                )
                
        except Timeout as e:
            # If we get a timeout, it's likely that we've triggered a RegexDOS
            # This is actually a positive finding, not an error
            self.logger.info(f"VULNERABILITY DETECTED: Timeout during RegexDOS testing: {str(e)}")
            self.logger.info("This timeout indicates a successful detection of a RegexDOS vulnerability")
            
            # Get the traceback for better error reporting
            tb = traceback.format_exc()
            self.logger.debug(f"Exception traceback: {tb}")
            
            # Calculate the impact score based on the timeout
            impact_score = min(10, (self.timeout_threshold / 2) * 10)
            
            # Determine if this is a scanner-level timeout or from _test_regex_dos
            is_scanner_level = tb and "_test_regex_dos" not in tb
            vulnerability_type = "Scanner-level" if is_scanner_level else "Request-level"
            
            self.add_finding(
                vulnerability="RegexDOS - Self-Denial of Service",
                details=f"The API is vulnerable to RegexDOS attacks. The {vulnerability_type.lower()} request caused a timeout, which indicates that the server became unresponsive due to excessive regex processing. This vulnerability can be exploited to cause denial of service.",
                severity="CRITICAL",
                endpoint=self.email_update_endpoint,
                evidence={
                    "error": str(e),
                    "error_type": e.__class__.__name__,
                    "timeout_threshold": self.timeout_threshold,
                    "impact_score": round(impact_score, 2),
                    "vulnerability_type": vulnerability_type
                },
                remediation="Implement proper input validation and use non-backtracking regex patterns or set appropriate timeout limits for regex operations. Consider using regex engines with backtracking protection or alternative validation methods. Specific recommendations:\n1. Use atomic grouping or possessive quantifiers if available\n2. Avoid nested repetition operators\n3. Implement request timeouts at the API level\n4. Consider using a regex validator library with DoS protection"
            )
                
        except (ConnectionError, RequestException) as e:
            # Connection errors might indicate that the server crashed
            # This is also a positive finding, not an error
            self.logger.info(f"VULNERABILITY DETECTED: Connection error during RegexDOS testing: {str(e)}")
            self.logger.info("This connection error indicates a successful detection of a RegexDOS vulnerability that crashed the server")
            
            # Get the traceback for better error reporting
            tb = traceback.format_exc()
            self.logger.debug(f"Exception traceback: {tb}")
            
            # Determine if this is a scanner-level error or from _test_regex_dos
            is_scanner_level = tb and "_test_regex_dos" not in tb
            vulnerability_type = "Scanner-level" if is_scanner_level else "Request-level"
            
            # Calculate the impact score - connection errors are more severe than timeouts
            impact_score = min(10, (self.timeout_threshold / 1.5) * 10)
            
            self.add_finding(
                vulnerability="RegexDOS - Server Crash",
                details=f"The API is SEVERELY vulnerable to RegexDOS attacks. The {vulnerability_type.lower()} request caused a connection error, which indicates that the server crashed or became completely unresponsive. This is a critical vulnerability that can be easily exploited for denial of service attacks.",
                severity="CRITICAL",
                endpoint=self.email_update_endpoint,
                evidence={
                    "error": str(e),
                    "error_type": e.__class__.__name__,
                    "impact_score": round(impact_score, 2),
                    "vulnerability_type": vulnerability_type
                },
                remediation="URGENT: Implement proper input validation and use non-backtracking regex patterns. This vulnerability allows an attacker to completely crash the service with a single request. Recommendations:\n1. Use atomic grouping or possessive quantifiers if available\n2. Avoid nested repetition operators\n3. Implement request timeouts at the API level\n4. Consider using a regex validator library with DoS protection\n5. Implement rate limiting and input size restrictions"
            )
            
        except Exception as e:
            self.logger.error(f"RegexDOS scanner error: {str(e)}")
            tb = traceback.format_exc()
            self.logger.debug(f"Exception traceback: {tb}")
            
            # Add an informational finding about the scanner error
            self.add_finding(
                vulnerability="RegexDOS Scanner Error",
                details=f"The RegexDOS scanner encountered an error: {str(e)}. This may indicate an issue with the scanner configuration or the API.",
                severity="INFO",
                endpoint="N/A",
                evidence={
                    "error": str(e),
                    "traceback": tb
                },
                remediation="Check the scanner configuration and ensure the API is accessible."
            )
            
        # Return findings
        return self.findings
    
    def cleanup(self) -> None:
        """
        Clean up resources used by the scanner.
        """
        self.logger.debug("Scanner cleanup completed")
