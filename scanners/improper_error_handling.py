"""
Improper Error Handling Scanner Module.

This module tests for vulnerabilities related to improper error handling,
where APIs reveal sensitive information such as stack traces, internal paths,
or technology stack details in error responses.
"""

import json
import time
import random
import string
import re
from typing import Dict, List, Any, Optional, Tuple

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose


class Scanner(BaseScanner):
    """Scanner for detecting improper error handling vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Initialize endpoints with default values
        self.login_endpoint = config.get("login_endpoint", "/auth/sign-in")
        self.register_endpoint = config.get("register_endpoint", "/auth/sign-up")
        self.admin_endpoints = config.get("admin_endpoints", ["/admin/users", "/admin/settings"])
        self.non_existent_endpoints = config.get("non_existent_endpoints", [
            "/admin/users", 
            "/admin/settings",
            "/api/v1/debug",
            "/api/internal/users",
            "/api/config"
        ])
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        
        # Field names in requests/responses
        self.username_field = config.get("username_field", "username")
        self.password_field = config.get("password_field", "password")
        self.email_field = config.get("email_field", "email")
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201, 204])
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        self.test_username = config.get("test_username", f"test_user_{timestamp}_{random_suffix}")
        self.test_email = config.get("test_email", f"{self.test_username}@example.com")
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        
        # Patterns to detect in error responses
        self.stack_trace_patterns = [
            r"at\s+[\w.<>]+\s+\([\w/\\.:]+\)",  # Common stack trace format
            r"File\s+\"[\w/\\.:]+\",\s+line\s+\d+",  # Python stack trace
            r"stack:",  # Generic stack indicator
            r"Stack trace:",  # Explicit stack trace header
            r"at .+\(.+\.js:\d+:\d+\)",  # JavaScript stack trace
            r"at .+\(.+\.py:\d+\)",  # Python stack trace in JS-like format
            r"[\w/\\.:]+\.(?:js|py|java|rb|php|cs|go):\d+",  # File references with line numbers
            r"Error:\s+[\w\s]+\n\s+at\s+",  # Express.js error format
            r"\"stack\":\s*\"[^\"]+\"",  # JSON stack trace field
            r"\"stack\":\s*\"Error:[^\"]+\"",  # Express.js JSON stack trace
        ]
        
        self.technology_patterns = [
            r"express",
            r"django",
            r"flask",
            r"laravel",
            r"spring",
            r"rails",
            r"node",
            r"apache",
            r"nginx",
            r"tomcat",
            r"iis",
            r"php",
            r"python",
            r"ruby",
            r"java",
            r"\.net",
            r"golang",
            r"postgresql",
            r"mysql",
            r"mongodb",
            r"sqlserver",
            r"oracle",
            r"express/lib/router",  # Express.js router module
            r"node_modules/express",  # Express.js node modules
            r"Layer\.handle",  # Express.js Layer handler
        ]
        
        self.path_patterns = [
            r"/[\w/\\.-]+\.(?:js|py|java|rb|php|cs|go)",  # Source code files
            r"/app/",  # Common application root
            r"/var/www/",  # Common web root
            r"/usr/local/",  # Common system path
            r"/home/\w+/",  # User home directories
            r"[A-Z]:\\",  # Windows paths
            r"/opt/",  # Common installation path
            r"/srv/",  # Common service path
            r"/node_modules/",  # Node.js modules
            r"/vendor/",  # Composer/PHP vendor directory
        ]
    
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
        
        # Find login and register endpoints
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        
        # Generate non-existent endpoints by appending random paths to the base URL
        # These should not exist in the API and will trigger 404 errors
        valid_paths = [endpoint.get("path", "") for endpoint in endpoints]
        self.non_existent_endpoints = [
            path for path in self.non_existent_endpoints if path not in valid_paths
        ]
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner to detect improper error handling vulnerabilities.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting improper error handling scanner")
        
        # Clear existing findings to ensure we start fresh
        self.findings = []
        
        # Store raw findings before consolidation
        self.raw_findings = []
        
        # Test non-existent endpoints for improper error handling
        self._test_non_existent_endpoints()
        
        # Test admin endpoints for improper error handling
        self._test_admin_endpoints_with_invalid_token()
        
        # Test login endpoint with invalid credentials
        self._test_login_with_invalid_credentials()
        
        # Test the specific Snorefox API vulnerability with Express.js stack traces
        self._test_snorefox_express_vulnerability()
        
        # Consolidate duplicate findings
        self._consolidate_findings()
        
        # Return findings
        return self.findings
        
    def _consolidate_findings(self) -> None:
        """
        Consolidate duplicate findings with the same error response pattern.
        """
        if not hasattr(self, 'raw_findings') or not self.raw_findings:
            return
            
        self.logger.info(f"Consolidating {len(self.raw_findings)} raw findings")
        
        # Group findings by their error response pattern
        grouped_findings = {}
        
        for finding in self.raw_findings:
            # Create a hash key based on the error response content
            # Extract the actual error pattern from the details
            details = finding.get('details', '')
            # Extract the part after the test name description
            if ". " in details:
                key = details.split(". ", 1)[1]  # Get the part after the first period and space
            else:
                key = details
            
            if key not in grouped_findings:
                grouped_findings[key] = {
                    'finding': finding,
                    'endpoints': [finding.get('endpoint')],
                    'test_names': [details.split(".")[0]] if ". " in details else ["Unknown test"]
                }
            else:
                grouped_findings[key]['endpoints'].append(finding.get('endpoint'))
                if ". " in details:
                    test_name = details.split(".")[0]
                    if test_name not in grouped_findings[key]['test_names']:
                        grouped_findings[key]['test_names'].append(test_name)
        
        # Clear existing findings
        self.findings = []
        
        # Add consolidated findings
        for key, group in grouped_findings.items():
            finding = group['finding']
            endpoints = sorted(set(group['endpoints']))
            test_names = group['test_names']
            
            # Create a consolidated endpoint string
            if len(endpoints) > 5:
                endpoint_str = f"{', '.join(endpoints[:5])} and {len(endpoints) - 5} more endpoints"
            else:
                endpoint_str = ", ".join(endpoints)
            
            # Create a consolidated test name string
            test_name_str = ", ".join(test_names)
            
            # Add the consolidated finding using the base scanner's add_finding method
            self.add_finding(
                vulnerability="Improper Error Handling",
                endpoint=endpoint_str,
                severity="Medium",
                details=f"Found in {len(endpoints)} endpoints when testing {test_name_str}. {key}",
                evidence=finding.get('evidence', {}),
                remediation=finding.get('remediation', "Configure proper error handling to return sanitized error messages without revealing internal implementation details, stack traces, or technology information.")
            )
            
        self.logger.info(f"Consolidated {len(self.raw_findings)} findings into {len(self.findings)} unique findings")
    
    def _test_non_existent_endpoints(self) -> None:
        """Test non-existent endpoints for improper error handling."""
        self.logger.info("Testing non-existent endpoints for improper error handling")
        
        for endpoint in self.non_existent_endpoints:
            self.logger.info(f"Testing non-existent endpoint: {endpoint}")
            
            # Make a GET request to the non-existent endpoint
            response = self._make_request(
                method="GET",
                endpoint=endpoint,
                try_auth_if_needed=False,
                capture_for_evidence=True
            )
            
            # Check for improper error handling in the response
            self._check_response_for_improper_error_handling(
                response, 
                endpoint, 
                "non-existent endpoint"
            )
    
    def _test_admin_endpoints_with_invalid_token(self) -> None:
        """Test admin endpoints with invalid JWT tokens for improper error handling."""
        self.logger.info("Testing admin endpoints with invalid tokens for improper error handling")
        
        # Create an invalid JWT token (algorithm=none attack)
        invalid_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNTg1MjM5MDIyfQ."
        
        for endpoint in self.admin_endpoints:
            self.logger.info(f"Testing admin endpoint with invalid token: {endpoint}")
            
            # Make a GET request to the admin endpoint with an invalid token
            response = self._make_request(
                method="GET",
                endpoint=endpoint,
                headers={"Authorization": f"Bearer {invalid_token}"},
                try_auth_if_needed=False,
                capture_for_evidence=True
            )
            
            # Check for improper error handling in the response
            self._check_response_for_improper_error_handling(
                response, 
                endpoint, 
                "admin endpoint with invalid token"
            )
    
    def _test_login_with_invalid_credentials(self) -> None:
        """Test login endpoint with invalid credentials for improper error handling."""
        self.logger.info("Testing login endpoint with invalid credentials for improper error handling")
        
        # Prepare invalid login data
        login_data = {
            self.username_field: f"nonexistent_user_{int(time.time())}",
            self.password_field: "invalid_password"
        }
        
        # Make a POST request to the login endpoint with invalid credentials
        response = self._make_request(
            method="POST",
            endpoint=self.login_endpoint,
            json_data=login_data,
            try_auth_if_needed=False,
            capture_for_evidence=True
        )
        
        # Check for improper error handling in the response
        self._check_response_for_improper_error_handling(
            response, 
            self.login_endpoint, 
            "login with invalid credentials"
        )
    
    def _test_snorefox_express_vulnerability(self) -> None:
        """Test for the specific Snorefox API vulnerability with Express.js stack traces."""
        self.logger.info("Testing for Snorefox Express.js stack trace vulnerability")
        
        # List of endpoints known to trigger Express.js stack traces
        test_endpoints = [
            "admin/users",
            "admin/settings",
            "api/v1/debug",
            "api/internal/users",
            "api/config"
        ]
        
        # Create an invalid JWT token (algorithm=none attack)
        invalid_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzQxOTQ3NTc1LCJleHAiOjE3NDIwMzM5NzV9."
        
        for endpoint in test_endpoints:
            self.logger.info(f"Testing endpoint for Express.js stack trace: {endpoint}")
            
            # Make a GET request with an invalid token
            response = self._make_request(
                method="GET",
                endpoint=endpoint,
                headers={"Authorization": f"Bearer {invalid_token}"},
                try_auth_if_needed=False,
                capture_for_evidence=True
            )
            
            # Check for improper error handling in the response
            self._check_response_for_improper_error_handling(
                response, 
                endpoint, 
                "Express.js stack trace vulnerability"
            )
            
            # Also try POST request
            response = self._make_request(
                method="POST",
                endpoint=endpoint,
                headers={"Authorization": f"Bearer {invalid_token}"},
                json_data={"test": "data"},
                try_auth_if_needed=False,
                capture_for_evidence=True
            )
            
            # Check for improper error handling in the response
            self._check_response_for_improper_error_handling(
                response, 
                endpoint, 
                "Express.js stack trace vulnerability (POST)"
            )
    
    def _check_response_for_improper_error_handling(
        self, 
        response: Any, 
        endpoint: str, 
        test_name: str
    ) -> None:
        """
        Check a response for signs of improper error handling.
        
        Args:
            response: The HTTP response to check
            endpoint: The endpoint that was tested
            test_name: The name of the test being performed
        """
        # Skip if response is None
        if response is None:
            return
        
        # Try to parse the response body as JSON
        try:
            response_text = response.text
            response_json = response.json() if hasattr(response, "json") else None
        except Exception:
            response_text = str(response)
            response_json = None
        
        # Check for stack traces in the response
        stack_trace_found = False
        for pattern in self.stack_trace_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                stack_trace_found = True
                break
        
        # Check for technology stack information in the response
        technology_found = False
        detected_technologies = []
        for pattern in self.technology_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                technology_found = True
                detected_technologies.extend(matches)
        
        # Check for internal paths in the response
        path_found = False
        detected_paths = []
        for pattern in self.path_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                path_found = True
                detected_paths.extend(matches)
        
        # If any improper error handling is detected, add a finding
        if stack_trace_found or technology_found or path_found:
            finding_details = []
            
            if stack_trace_found:
                finding_details.append("Stack trace information is exposed in error responses")
            
            if technology_found:
                technologies = ", ".join(set(detected_technologies))
                finding_details.append(f"Technology stack information is exposed: {technologies}")
            
            if path_found:
                paths = ", ".join(set(detected_paths))
                finding_details.append(f"Internal file paths are exposed: {paths}")
            
            details = ". ".join(finding_details)
            
            # Prepare comprehensive evidence for the report generator
            request_evidence = {
                "url": self._get_full_url(endpoint),
                "method": response.request.method if hasattr(response, "request") else "Unknown",
                "headers": dict(response.request.headers) if hasattr(response, "request") else {},
                "body": None  # Will be populated if available
            }
            
            # Try to capture request body if available
            if hasattr(response, "request") and hasattr(response.request, "body") and response.request.body:
                try:
                    body = response.request.body
                    if isinstance(body, bytes):
                        body = body.decode('utf-8')
                    
                    # Try to parse as JSON if it looks like JSON
                    if body.strip().startswith('{') and body.strip().endswith('}'):
                        request_evidence["body"] = json.loads(body)
                    else:
                        request_evidence["body"] = body
                except Exception as e:
                    self.logger.debug(f"Could not decode request body: {str(e)}")
                    request_evidence["body"] = str(body) if 'body' in locals() else None
            
            # Prepare response evidence
            response_evidence = {
                "status_code": response.status_code if hasattr(response, "status_code") else "Unknown",
                "headers": dict(response.headers) if hasattr(response, "headers") else {},
                "body": response_json if response_json else response_text,
                "time": time.time(),
                "size": len(response_text) if response_text else 0
            }
            
            # Add detailed evidence about the specific improper error handling issues found
            detailed_evidence = {
                "stack_trace_found": stack_trace_found,
                "technology_found": technology_found,
                "technologies_detected": list(set(detected_technologies)) if detected_technologies else [],
                "path_found": path_found,
                "paths_detected": list(set(detected_paths)) if detected_paths else [],
                "test_name": test_name,
                "timestamp": time.time(),
                "request": request_evidence,
                "response": response_evidence
            }
            
            # Store the finding in raw_findings instead of adding directly
            if hasattr(self, 'raw_findings'):
                self.raw_findings.append({
                    'vulnerability': "Improper Error Handling",
                    'endpoint': endpoint,
                    'severity': "Medium",
                    'details': f"The API reveals sensitive information in error responses when testing {test_name}. {details}",
                    'evidence': detailed_evidence,
                    'remediation': "Configure proper error handling to return sanitized error messages without revealing internal implementation details, stack traces, or technology information. Implement a global error handler that catches all exceptions and returns standardized error responses."
                })
            else:
                # Fallback to direct adding if raw_findings doesn't exist
                self.add_finding(
                    vulnerability="Improper Error Handling",
                    endpoint=endpoint,
                    severity="Medium",
                    details=f"The API reveals sensitive information in error responses when testing {test_name}. {details}",
                    evidence=detailed_evidence,
                    remediation="Configure proper error handling to return sanitized error messages without revealing internal implementation details, stack traces, or technology information. Implement a global error handler that catches all exceptions and returns standardized error responses."
                )
