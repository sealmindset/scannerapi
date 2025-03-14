"""
JWT Vulnerabilities Scanner Module.

This module tests for vulnerabilities related to JSON Web Tokens (JWT),
focusing on weak signing keys, algorithm confusion, and other JWT-specific issues.
"""

import json
import time
import random
import string
import base64
import hashlib
import hmac
import requests
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta

from core.base_scanner import BaseScanner
from core.openapi import find_endpoint_by_purpose
from core.account_cache import account_cache

# Try to import optional dependencies
HAS_JWT = False
HAS_JWCRYPTO = False
try:
    import jwt as pyjwt  # Using standard PyJWT library instead of deprecated python_jwt
    HAS_JWT = True
except ImportError:
    pass

try:
    import jwcrypto.jwk as jwk
    HAS_JWCRYPTO = True
except ImportError:
    pass


class Scanner(BaseScanner):
    """Scanner for detecting JWT-specific vulnerabilities."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize the scanner.
        
        Args:
            target: Target configuration
            config: Scanner-specific configuration
        """
        super().__init__(target, config)
        
        # Flag to simulate vulnerabilities in debug mode
        self.simulate_vulnerabilities = config.get("simulate_vulnerabilities", False)
        
        # Debug mode flag
        self.debug = config.get("debug", False)
        
        # If debug mode is enabled, enable simulation of vulnerabilities
        if self.debug:
            self.simulate_vulnerabilities = True
            self.logger.info("Debug mode enabled - simulating vulnerabilities")
        
        # Initialize endpoints with default values
        self.login_endpoint = config.get("login_endpoint", "/users/v1/login")
        self.refresh_token_endpoint = config.get("refresh_token_endpoint", "/users/v1/refresh")
        self.user_info_endpoint = config.get("user_info_endpoint", "/users/v1/me")
        self.debug_endpoint = config.get("debug_endpoint", "/users/v1/_debug")
        self.register_endpoint = config.get("register_endpoint", "/users/v1/register")
        
        # Ensure token_expiration_time is set (default to 30 days)
        self.token_expiration_time = config.get("token_expiration_time", 2592000)  # 30 days in seconds
        self.protected_endpoints = config.get("protected_endpoints", [
            "/users/v1/me",
            "/books/v1",
            "/admin"
        ])
        
        # Extract endpoints from OpenAPI spec if available
        self._extract_endpoints_from_openapi(target)
        
        # Log the resolved endpoints
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using user info endpoint: {self.user_info_endpoint}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        
        # Field names in requests/responses
        self.username_field = config.get("username_field", "username")
        self.password_field = config.get("password_field", "password")
        self.email_field = config.get("email_field", "email")
        self.access_token_field = config.get("access_token_field", "auth_token")
        self.refresh_token_field = config.get("refresh_token_field", "refresh_token")
        self.id_token_field = config.get("id_token_field", "id_token")
        self.additional_fields = config.get("additional_fields", {})
        
        # Success indicators
        self.success_status_codes = config.get("success_status_codes", [200, 201, 204])
        
        # Test user credentials
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        username = f"test_user_{timestamp}_{random_suffix}"
        # For Snorefox API, the username is actually the email
        self.test_username = config.get("test_username", f"{username}@example.com")
        self.test_email = self.test_username  # Set email to be the same as username
        self.test_password = config.get("test_password", f"Test@{timestamp}")
        self.test_email = f"{self.test_username}@example.com"
        
        # Common weak JWT signing keys to test
        self.weak_keys = config.get("weak_keys", [
            "",  # Empty key
            "secret",  # Default in many libraries
            "key",  # Simple key
            "password",  # Common password
            "1234567890",  # Numeric sequence
            "qwertyuiop",  # Keyboard sequence
            "jwt_secret",  # Descriptive name
            "your-256-bit-secret",  # Example from docs
            "your_secret_key",  # Example from docs
            "mysecretkey",  # Common pattern
            "secretkey",  # Common pattern
            "test",  # Testing key
            "testing",  # Testing key
            "development",  # Environment-specific
            "dev",  # Environment-specific
            "staging",  # Environment-specific
            "production",  # Environment-specific
            "prod",  # Environment-specific
            "api_secret",  # Common pattern
            "api_key",  # Common pattern
            "app_secret",  # Common pattern
            "app_key",  # Common pattern
            "jwt_token",  # Common pattern
            "jwt_key"  # Common pattern
        ])
        
        # Get token expiration time from config
        self.token_expiration_time = config.get("token_expiration_time", 3600)  # Default 1 hour
        
        # JWT algorithms to test
        self.jwt_algorithms = config.get("jwt_algorithms", [
            "none",  # None algorithm vulnerability
            "HS256",  # HMAC with SHA-256
            "HS384",  # HMAC with SHA-384
            "HS512"   # HMAC with SHA-512
        ])
        
    def _make_request(self, method: str, endpoint: str, json_data: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> requests.Response:
        """
        Make an HTTP request to the target API with proper authentication and capture detailed information.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint to call
            json_data: JSON data to send in the request body
            headers: HTTP headers to include in the request
            
        Returns:
            Response object with request and response details attached
        """
        url = self._get_full_url(endpoint)
        if headers is None:
            headers = {"Content-Type": "application/json", "Accept": "application/json"}
        else:
            # Ensure Content-Type and Accept headers are set
            if "Content-Type" not in headers:
                headers["Content-Type"] = "application/json"
            if "Accept" not in headers:
                headers["Accept"] = "application/json"
        
        # Store request details for evidence
        request_details = {
            "method": method,
            "url": url,
            "headers": dict(headers),
            "json_data": json_data
        }
        
        try:
            self.logger.debug(f"Making {method} request to {url}")
            response = requests.request(
                method=method,
                url=url,
                json=json_data,
                headers=headers,
                timeout=10,
                verify=False
            )
            
            # Store response details for evidence
            response_details = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": self._safely_get_response_body(response)
            }
            
            # Attach request and response details to the response object for later use
            response.request_details = request_details
            response.response_details = response_details
            
            return response
        except Exception as e:
            self.logger.error(f"Error making request to {url}: {str(e)}")
            # Return a dummy response object with an error status code
            response = requests.Response()
            response.status_code = 500
            # Attach request details even for failed requests
            response.request_details = request_details
            response.response_details = {
                "status_code": 500,
                "error": str(e)
            }
            return response
    
    def _safely_get_response_body(self, response: requests.Response) -> Any:
        """
        Safely extract the response body as JSON or text.
        
        Args:
            response: Response object to extract body from
            
        Returns:
            Response body as JSON or text
        """
        try:
            return response.json()
        except ValueError:
            # If not JSON, return text (truncated if too large)
            return response.text[:2000] if len(response.text) > 2000 else response.text
    
    def _get_full_url(self, endpoint: str) -> str:
        """
        Get the full URL for an endpoint.
        
        Args:
            endpoint: API endpoint path
            
        Returns:
            Full URL including base URL and endpoint
        """
        if endpoint.startswith("http"):
            return endpoint
        
        base_url = self.target.get("base_url", "")
        if not base_url:
            return endpoint
        
        # Handle both with and without trailing/leading slashes
        base_url = base_url.rstrip("/")
        endpoint = endpoint.lstrip("/")
        
        return f"{base_url}/{endpoint}"
    
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
        # For each endpoint, use the enhanced find_endpoint_by_purpose function
        # which now has improved scoring and pattern matching capabilities
        self.login_endpoint = find_endpoint_by_purpose(endpoints, "login", self.login_endpoint)
        self.refresh_token_endpoint = find_endpoint_by_purpose(endpoints, "refresh_token", self.refresh_token_endpoint)
        self.user_info_endpoint = find_endpoint_by_purpose(endpoints, "user_info", self.user_info_endpoint)
        self.debug_endpoint = find_endpoint_by_purpose(endpoints, "debug", self.debug_endpoint)
        self.register_endpoint = find_endpoint_by_purpose(endpoints, "register", self.register_endpoint)
        
        # Also look for validate token endpoints which are common in JWT implementations
        self.validate_token_endpoint = find_endpoint_by_purpose(endpoints, "validate", "/users/v1/validate")
        
        # Try to find protected endpoints that might use JWT for authorization
        # These are endpoints that typically require authentication
        protected_candidates = []
        for endpoint in endpoints:
            # Look for endpoints that might be protected based on path patterns
            path = endpoint.get("path", "")
            method = endpoint.get("method", "").upper()
            
            # Skip login, register, and public endpoints
            if (path == self.login_endpoint or 
                path == self.register_endpoint or 
                "/public/" in path.lower()):
                continue
                
            # Check for indicators of protected endpoints
            is_protected = False
            
            # Check for authorization in parameters
            if "parameters" in endpoint:
                for param in endpoint.get("parameters", []):
                    if param.get("name", "").lower() in ["authorization", "token", "jwt", "bearer"]:
                        is_protected = True
                        break
            
            # Check for security schemes
            if "security" in endpoint and endpoint["security"]:
                is_protected = True
            
            # Check path patterns that suggest protected resources
            protected_patterns = ["/api/", "/v1/", "/v2/", "/me", "/user/", "/admin/", "/account/", "/profile/"]
            if any(pattern in path.lower() for pattern in protected_patterns):
                # Higher likelihood if it's a GET, PUT, PATCH or DELETE method
                if method in ["GET", "PUT", "PATCH", "DELETE"]:
                    is_protected = True
            
            if is_protected:
                protected_candidates.append(path)
        
        # Update protected endpoints if we found candidates
        if protected_candidates:
            self.logger.info(f"Found {len(protected_candidates)} potentially protected endpoints")
            # Combine with any configured protected endpoints
            self.protected_endpoints = list(set(self.protected_endpoints + protected_candidates))
        
        self.logger.info(f"Using login endpoint: {self.login_endpoint}")
        self.logger.info(f"Using refresh token endpoint: {self.refresh_token_endpoint}")
        self.logger.info(f"Using user info endpoint: {self.user_info_endpoint}")
        self.logger.info(f"Using validate token endpoint: {self.validate_token_endpoint if hasattr(self, 'validate_token_endpoint') else 'Not found'}")
        self.logger.info(f"Using register endpoint: {self.register_endpoint}")
        self.logger.info(f"Protected endpoints: {len(self.protected_endpoints)}")
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Starting JWT vulnerabilities scanner")
        
        # Ensure target URL is properly set
        if 'url' not in self.target and 'base_url' in self.target:
            self.target['url'] = self.target['base_url']
            self.logger.info(f"Using base_url as target URL: {self.target['url']}")
        elif 'url' not in self.target:
            # For debug mode, use a default URL
            if self.debug:
                self.target['url'] = "http://localhost:8000"
                self.logger.info(f"Debug mode: Using default target URL: {self.target['url']}")
            else:
                self.logger.error("No target URL specified in configuration")
                return self.findings
                
        self.logger.info(f"Target base URL: {self.target['url']}")
        self.logger.info(f"Login endpoint: {self.login_endpoint}")
        self.logger.info(f"User info endpoint: {self.user_info_endpoint}")
        self.logger.info(f"Debug mode: {self.debug}")
        
        # Check if a token expiration time is configured
        if self.token_expiration_time > 86400 * 30:  # More than 30 days
            days = self.token_expiration_time / 86400
            self.logger.warning(f"Configured token expiration time is very long: {days:.1f} days")
            
            # Determine severity based on token lifetime
            severity = "MEDIUM"
            if days > 180:  # More than 180 days
                severity = "HIGH"
            if days > 300:  # More than 300 days
                severity = "CRITICAL"
                
            # Add finding for configured long-lived tokens
            self.add_finding(
                vulnerability="Configured Long-Lived JWT Tokens",
                details=f"The system is configured to issue JWT tokens with an extremely long lifetime of {days:.1f} days. This significantly increases the risk of token theft and misuse.",
                severity=severity,
                endpoint=self.login_endpoint,
                evidence={
                    "configured_expiration_days": days,
                    "recommended_maximum_days": 1
                },
                remediation="Configure shorter expiration times for JWT tokens (15-60 minutes is recommended). For longer sessions, implement refresh tokens with proper security controls."
            )
        
        # For testing purposes, let's create a sample JWT token if we're in debug mode
        # This allows us to test the JWT vulnerability detection without a real server
        if self.debug:
            self.logger.info("Debug mode enabled, creating a sample JWT token for testing")
            # Create a sample JWT token with a weak key
            try:
                # Try to import PyJWT
                try:
                    import jwt
                    self.logger.info("Using PyJWT library for token creation")
                except ImportError:
                    self.logger.error("PyJWT library not found, cannot create test token")
                    return self.findings
                
                # Create a payload with common fields
                payload = {
                    "sub": "1234567890",
                    "name": "Test User",
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 3600 * 24 * 30  # 30 days
                }
                
                # Sign with a weak key
                weak_key = "secret"
                self.logger.info(f"Creating token with weak key: '{weak_key}'")
                access_token = jwt.encode(payload, weak_key, algorithm="HS256")
                
                if isinstance(access_token, bytes):
                    access_token = access_token.decode('utf-8')
                
                self.logger.info(f"Created sample JWT token for testing: {access_token}")
                
                # Set the flag to enable simulated responses
                self.simulate_vulnerabilities = True
                self.logger.info("Enabled simulation of vulnerable responses")
                
                # Test the token against our vulnerability tests
                self._run_jwt_tests(access_token)
                
                # Print findings summary
                self.logger.info(f"Found {len(self.findings)} vulnerabilities")
                for i, finding in enumerate(self.findings):
                    self.logger.info(f"Finding {i+1}: {finding['vulnerability']} - {finding['severity']}")
                
                return self.findings
            except Exception as e:
                self.logger.error(f"Error creating sample JWT token: {str(e)}")
                import traceback
                self.logger.error(traceback.format_exc())
        
        # Register a test user if needed
        self._register_test_user()
        
        # Login and get tokens
        access_token, refresh_token, id_token = self._login()
        
        if not access_token:
            self.logger.warning("Failed to obtain access token, skipping JWT tests")
            return self.findings
        
        # Check if the token is a JWT
        if not self._is_jwt_token(access_token):
            self.logger.info("Access token is not a JWT, skipping JWT-specific tests")
            return self.findings
            
        # Run JWT vulnerability tests
        self._run_jwt_tests(access_token, refresh_token, id_token)
        
        return self.findings
        
    def _run_jwt_tests(self, access_token, refresh_token=None, id_token=None):
        """Run all JWT vulnerability tests on the provided tokens."""
        self.logger.info("Running JWT vulnerability tests")
        self.logger.info(f"Simulate vulnerabilities: {self.simulate_vulnerabilities}")
        
        # Log token details for debugging and analysis
        try:
            parts = access_token.split('.')
            if len(parts) >= 2:
                header_str = self._decode_jwt_part(parts[0])
                header = json.loads(header_str)
                payload_str = self._decode_jwt_part(parts[1])
                payload = json.loads(payload_str)
                
                self.logger.info(f"JWT Header: {json.dumps(header)}")
                self.logger.info(f"JWT Algorithm: {header.get('alg', 'unknown')}")
                
                # Log expiration information if available
                if 'exp' in payload:
                    exp_time = datetime.fromtimestamp(payload['exp'])
                    current_time = datetime.now()
                    time_diff = exp_time - current_time
                    self.logger.info(f"JWT Expiration: {exp_time} (in {time_diff.total_seconds()/3600:.1f} hours)")
                
                # Log other important claims
                important_claims = ['sub', 'iss', 'aud', 'roles', 'permissions', 'scope']
                for claim in important_claims:
                    if claim in payload:
                        self.logger.info(f"JWT Claim '{claim}': {payload[claim]}")
        except Exception as e:
            self.logger.error(f"Error parsing JWT token: {str(e)}")
        
        # If simulating vulnerabilities, add findings directly
        if self.simulate_vulnerabilities:
            self.logger.info("Simulating JWT vulnerabilities as requested")
            
            # Create sample tokens for evidence
            sample_token = self._create_sample_token()
            tampered_token = self._create_tampered_token(sample_token)
            
            # Create sample request and response data
            login_request = {
                "method": "POST",
                "url": self._get_full_url(self.login_endpoint),
                "headers": {"Content-Type": "application/json"},
                "json_data": {self.username_field: "test@example.com", self.password_field: "Test123!@#"}
            }
            
            login_response = {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": {self.access_token_field: sample_token, "user": {"id": 1, "email": "test@example.com"}}
            }
            
            check_request = {
                "method": "GET",
                "url": self._get_full_url(self.user_info_endpoint),
                "headers": {"Authorization": f"Bearer {sample_token}", "Content-Type": "application/json"}
            }
            
            check_response = {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": {"user": {"id": 1, "email": "test@example.com", "role": "user"}}
            }
            
            tampered_request = {
                "method": "GET",
                "url": self._get_full_url(self.user_info_endpoint),
                "headers": {"Authorization": f"Bearer {tampered_token}", "Content-Type": "application/json"}
            }
            
            tampered_response = {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": {"user": {"id": 1, "email": "test@example.com", "role": "admin"}}
            }
            
            # Simulate 'none' algorithm vulnerability
            self.add_finding(
                vulnerability="JWT 'none' Algorithm Vulnerability",
                severity="CRITICAL",
                endpoint=self.user_info_endpoint,
                details="The API accepts JWT tokens with the 'none' algorithm, allowing authentication bypass.",
                evidence={
                    "original_token": sample_token,
                    "tampered_token": tampered_token,
                    "decoded_payload": self._decode_token_payload(tampered_token),
                    "request": tampered_request,
                    "response": tampered_response
                },
                remediation="Ensure that the JWT library explicitly rejects tokens with the 'none' algorithm."
            )
            
            # Simulate weak signing key vulnerability
            self.add_finding(
                vulnerability="JWT Weak Signing Key",
                severity="CRITICAL",
                endpoint=self.login_endpoint,
                details="The API uses a weak signing key ('secret') for JWT tokens, allowing token forgery.",
                evidence={
                    "weak_key": "secret",
                    "token": sample_token,
                    "request": login_request,
                    "response": login_response
                },
                remediation="Use a strong, randomly generated signing key with at least 256 bits of entropy."
            )
            
            # Simulate missing signature validation
            self.add_finding(
                vulnerability="Missing JWT Signature Validation",
                severity="CRITICAL",
                endpoint=self.user_info_endpoint,
                details="The API does not properly validate JWT signatures, allowing attackers to modify token content without detection.",
                evidence={
                    "original_token": sample_token,
                    "tampered_token": tampered_token,
                    "decoded_payload": self._decode_token_payload(tampered_token),
                    "request": check_request,
                    "response": check_response
                },
                remediation="Ensure that the JWT library properly validates token signatures and rejects tokens with invalid signatures."
            )
            
            # Simulate expiration manipulation
            self.add_finding(
                vulnerability="JWT Expiration Manipulation",
                severity="CRITICAL",
                endpoint=self.user_info_endpoint,
                details="The API does not properly validate the integrity of JWT tokens, allowing attackers to modify the expiration time.",
                evidence={
                    "original_token": sample_token,
                    "tampered_token": self._create_token_with_extended_expiry(),
                    "request": check_request,
                    "response": check_response
                },
                remediation="Ensure that the JWT library properly validates token signatures and rejects tokens with invalid signatures."
            )
            
            # Simulate token tampering
            self.add_finding(
                vulnerability="JWT Token Tampering - None algorithm",
                severity="CRITICAL",
                endpoint=self.user_info_endpoint,
                details="The API does not properly validate the integrity of JWT tokens, allowing attackers to modify the payload using None algorithm to gain elevated privileges.",
                evidence={
                    "original_token": sample_token,
                    "tampered_token": self._create_admin_token(),
                    "decoded_payload": {"sub": "1234567890", "name": "Test User", "role": "admin", "iat": int(time.time()), "exp": int(time.time()) + 3600},
                    "request": tampered_request,
                    "response": tampered_response
                },
                remediation="Ensure that the JWT library properly validates token signatures and rejects tokens with invalid signatures or using the 'none' algorithm."
            )
            
            return
        
        # Test for JWT vulnerabilities
        self.logger.info("Testing for 'none' algorithm vulnerability")
        self._test_jwt_none_algorithm(access_token)
        
        self.logger.info("Testing for algorithm confusion vulnerability")
        self._test_jwt_algorithm_confusion(access_token)
        
        self.logger.info("Testing for weak signing key vulnerability")
        self._test_jwt_weak_signing_key(access_token)
        
        self.logger.info("Testing for missing signature validation")
        self._test_jwt_missing_signature_validation(access_token)
        
        self.logger.info("Testing for expiration manipulation vulnerability")
        self._test_jwt_expiration_manipulation(access_token)
        
        self.logger.info("Testing for token tampering vulnerability")
        self._test_jwt_token_tampering(access_token)
        
        self.logger.info("Checking for information disclosure in tokens")
        self._check_jwt_information_disclosure(access_token, id_token)
    
    def _register_test_user(self) -> None:
        """Register a test user for JWT testing or use a cached account."""
        # First check if we have a cached account
        cached_account = account_cache.get_account(self.register_endpoint)
        if cached_account:
            self.logger.info(f"Using cached account: {cached_account.get('username', cached_account.get('email'))}")
            self.test_username = cached_account.get('username')
            self.test_password = cached_account.get('password')
            self.test_email = cached_account.get('email')
            return
            
        # Try using the base scanner helper method
        account = self.get_or_create_test_account(self.register_endpoint)
        if account:
            self.logger.info(f"Using account from base scanner: {account.get('username')}")
            self.test_username = account.get('username')
            self.test_password = account.get('password')
            self.test_email = account.get('email')
            return
            
        # If no cached account and base method failed, create a new one
        self.logger.info(f"No cached account found, registering test user: {self.test_username}")
        
        # For Snorefox API, the username field is actually the email
        # Make sure we're using the email field correctly
        payload = {
            self.username_field: self.test_username,  # This is the email for Snorefox API
            self.password_field: self.test_password,
            self.email_field: self.test_username  # Ensure email field is set to the same value
        }
        
        # Add additional fields
        payload.update(self.additional_fields)
        
        # Log the payload for debugging
        self.logger.info(f"Registration payload: {json.dumps(payload)}")
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.register_endpoint,
                json_data=payload
            )
            
            # Log the response status and body for debugging
            response_body = response.text[:200] + "..." if len(response.text) > 200 else response.text
            self.logger.info(f"Registration response: {response.status_code} - {response_body}")
            
            if response.status_code in self.success_status_codes:
                self.logger.info(f"Successfully registered test user: {self.test_username}")
                
                # Add to account cache
                account_data = {
                    "username": self.test_username,
                    "email": self.test_username,  # For Snorefox API, email is the same as username
                    "password": self.test_password,
                    "endpoint": self.register_endpoint,
                    "created_by": self.__class__.__name__,
                    "response_code": response.status_code
                }
                account_cache.add_account(account_data)
                
                # Wait a moment for the user to be fully registered in the system
                time.sleep(0.5)
            else:
                self.logger.warning(f"Failed to register test user: {self.test_username}, status code: {response.status_code}")
                self.logger.warning(f"Response body: {response.text[:500]}")
                
                # Check for specific error messages that might help diagnose the issue
                if "already exists" in response.text.lower() or "already registered" in response.text.lower():
                    self.logger.info("User already exists, will attempt to login with these credentials")
        except Exception as e:
            self.logger.warning(f"Failed to register test user: {str(e)}")
    
    def _login(self) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Login and get authentication tokens.
        
        Returns:
            Tuple of (access_token, refresh_token, id_token)
        """
        self.logger.info(f"Logging in as user '{self.test_username}'")
        
        # For Snorefox API, ensure we're using the email as the username
        payload = {
            self.username_field: self.test_username,  # This should be the email for Snorefox API
            self.password_field: self.test_password
        }
        
        # Log the payload for debugging
        self.logger.info(f"Login payload: {json.dumps(payload)}")
        
        try:
            response = self._make_request(
                method="POST",
                endpoint=self.login_endpoint,
                json_data=payload
            )
            
            # Log the response status and partial body for debugging
            response_body = response.text[:200] + "..." if len(response.text) > 200 else response.text
            self.logger.info(f"Login response: {response.status_code} - {response_body}")
            
            if response.status_code in self.success_status_codes:
                try:
                    data = response.json()
                    # Log the full response data structure for debugging
                    self.logger.debug(f"Login response data structure: {json.dumps(data)}")
                    
                    # Try to extract tokens from the response
                    access_token = None
                    refresh_token = None
                    id_token = None
                    
                    # First try the configured field names
                    access_token = data.get(self.access_token_field)
                    refresh_token = data.get(self.refresh_token_field)
                    id_token = data.get(self.id_token_field)
                    
                    # If not found, try common field names for Snorefox API
                    if not access_token:
                        for field in ["token", "access_token", "accessToken", "jwt", "auth_token", "authToken"]:
                            if field in data:
                                access_token = data[field]
                                self.logger.info(f"Found access token in field: {field}")
                                break
                    
                    # Try to find tokens in nested structures common in APIs
                    if not access_token and isinstance(data, dict):
                        # Check for nested data structures like {"data": {"token": "..."}} or {"result": {"token": "..."}}
                        for outer_key in ["data", "result", "response", "user", "auth"]:
                            if outer_key in data and isinstance(data[outer_key], dict):
                                nested_data = data[outer_key]
                                for field in [self.access_token_field, "token", "access_token", "accessToken", "auth_token", "jwt"]:
                                    if field in nested_data:
                                        access_token = nested_data.get(field)
                                        self.logger.info(f"Found access token in nested field: {outer_key}.{field}")
                                        break
                        
                        # If still not found, do a more exhaustive search through all nested structures
                        if not access_token:
                            for key, value in data.items():
                                if isinstance(value, dict):
                                    for subkey, subvalue in value.items():
                                        if "token" in subkey.lower() and isinstance(subvalue, str) and len(subvalue) > 40:
                                            if "refresh" in subkey.lower():
                                                refresh_token = subvalue
                                                self.logger.info(f"Found refresh token in nested field: {key}.{subkey}")
                                            elif "id" in subkey.lower():
                                                id_token = subvalue
                                                self.logger.info(f"Found ID token in nested field: {key}.{subkey}")
                                            else:
                                                access_token = subvalue
                                                self.logger.info(f"Found access token in nested field: {key}.{subkey}")
                    
                    # As a last resort, look for any string that looks like a JWT token
                    if not access_token:
                        self._find_potential_token_in_response(data)
                    
                    if access_token:
                        self.logger.info(f"Successfully logged in as '{self.test_username}' and obtained tokens")
                        return access_token, refresh_token, id_token
                    else:
                        self.logger.warning(f"Login successful but no access token found in response")
                        # Log the full response for debugging
                        self.logger.debug(f"Full login response: {response.text}")
                        return None, None, None
                except ValueError as e:
                    self.logger.warning(f"Login successful but response is not valid JSON: {str(e)}")
                    return None, None, None
            else:
                self.logger.warning(f"Failed to login as '{self.test_username}', status code: {response.status_code}")
                self.logger.warning(f"Response body: {response.text[:500]}")
                return None, None, None
        except Exception as e:
            self.logger.error(f"Error logging in as '{self.test_username}': {str(e)}")
            return None, None, None
            
    def _find_potential_token_in_response(self, data: Any) -> Optional[str]:
        """Helper method to recursively search for potential tokens in the response data"""
        if isinstance(data, dict):
            for key, value in data.items():
                # Look for JWT token pattern (base64 segments separated by periods)
                if isinstance(value, str) and len(value) > 40 and '.' in value and value.count('.') >= 2:
                    self.logger.info(f"Found potential JWT token in field: {key}")
                    return value
                # Recursively search nested dictionaries
                elif isinstance(value, (dict, list)):
                    result = self._find_potential_token_in_response(value)
                    if result:
                        return result
        elif isinstance(data, list):
            for item in data:
                result = self._find_potential_token_in_response(item)
                if result:
                    return result
        return None
    
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
                    
            # If it has at least 2 typical JWT fields, consider it a JWT
            return found_fields >= 2
        except Exception:
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
    
    def _test_jwt_none_algorithm(self, token: str) -> None:
        """
        Test for the JWT 'none' algorithm vulnerability.
        
        Args:
            token: The token to test
        """
        self.logger.info("Testing for JWT 'none' algorithm vulnerability")
        
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            self.logger.info(f"Original token header: {json.dumps(header)}")
            
            # Create a new token with 'none' algorithm
            modified_header = header.copy()
            modified_header['alg'] = 'none'
            new_header = self._encode_jwt_part(modified_header)
            new_payload = self._encode_jwt_part(payload)
            
            # Create the modified token without a signature
            modified_token = f"{new_header}.{new_payload}."
            
            self.logger.info(f"Modified token with 'none' algorithm: {modified_token}")
            
            # Test the modified token
            response = self._make_authenticated_request(
                method="GET",
                endpoint=self.user_info_endpoint,
                token=modified_token
            )
            
            self.logger.info(f"Response status code for 'none' algorithm test: {response.status_code}")
            
            if response.status_code in self.success_status_codes:
                self.logger.warning("JWT 'none' algorithm vulnerability detected!")
                self.add_finding(
                    vulnerability="JWT 'none' Algorithm Vulnerability",
                    details="The API accepts JWT tokens with the 'none' algorithm, allowing attackers to forge valid tokens without knowing the signing key. This is a critical vulnerability that enables complete authentication bypass.",
                    severity="CRITICAL",
                    endpoint=self.user_info_endpoint,
                    evidence={
                        "original_token": token,
                        "modified_token": modified_token,
                        "response_code": response.status_code
                    },
                    remediation="Ensure that the JWT library explicitly rejects tokens with the 'none' algorithm. Always validate that tokens are signed with the expected algorithm and reject requests with invalid signatures."
                )
            else:
                self.logger.info("JWT 'none' algorithm vulnerability not detected")
        except Exception as e:
            self.logger.error(f"Error testing JWT 'none' algorithm vulnerability: {str(e)}")
    
    def _test_jwt_algorithm_confusion(self, token: str) -> None:
        """
        Test for JWT algorithm confusion attacks.
        
        Args:
            token: The token to test
        """
        self.logger.info("Testing for JWT algorithm confusion vulnerability")
        
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            original_alg = header.get('alg')
            
            # Skip if the original algorithm is not HMAC-based
            if not original_alg or not original_alg.startswith('HS'):
                self.logger.info(f"Original algorithm is {original_alg}, skipping algorithm confusion test")
                return
                
            # Try to change the algorithm to RS256 (asymmetric) while keeping the HMAC signature
            header['alg'] = 'RS256'
            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(payload)
            
            # Keep the original signature
            modified_token = f"{new_header}.{new_payload}.{parts[2]}"
            
            # Test the modified token
            response = self._make_authenticated_request(
                method="GET",
                endpoint=self.user_info_endpoint,
                token=modified_token
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.warning("JWT algorithm confusion vulnerability detected!")
                self.add_finding(
                    vulnerability="JWT Algorithm Confusion Vulnerability",
                    details="The API is vulnerable to JWT algorithm confusion attacks. It accepts tokens with the algorithm changed from HMAC to RSA while using the same signature.",
                    severity="CRITICAL",
                    endpoint=self.user_info_endpoint,
                    evidence={
                        "original_algorithm": original_alg,
                        "modified_algorithm": "RS256",
                        "response_code": response.status_code
                    },
                    remediation="Always validate that tokens are signed with the expected algorithm. Explicitly specify the expected algorithm when verifying tokens."
                )
            else:
                self.logger.info("JWT algorithm confusion vulnerability not detected")
        except Exception as e:
            self.logger.error(f"Error testing JWT algorithm confusion vulnerability: {str(e)}")
    
    def _test_jwt_weak_signing_key(self, token: str) -> None:
        """
        Test for weak JWT signing keys using multiple methods including PyJWT and jwcrypto.
        
        Args:
            token: The token to test
        """
        self.logger.info("Testing for JWT authentication bypass via weak signing key")
        self.logger.info(f"Testing token: {token[:20]}...")
        
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Get the algorithm
            alg = header.get('alg')
            
            # Skip if the algorithm is not HMAC-based
            if not alg or not alg.startswith('HS'):
                self.logger.info(f"Algorithm is {alg}, skipping weak signing key test")
                return
            
            # Method 1: Traditional HMAC verification approach
            weak_keys_found = []
            for key in self.weak_keys:
                try:
                    # Create a new signature with the weak key
                    message = f"{parts[0]}.{parts[1]}"
                    
                    # Select the appropriate hash function based on the algorithm
                    hash_func = None
                    if alg == 'HS256':
                        hash_func = hashlib.sha256
                    elif alg == 'HS384':
                        hash_func = hashlib.sha384
                    elif alg == 'HS512':
                        hash_func = hashlib.sha512
                    else:
                        continue
                        
                    # Create the signature
                    signature = hmac.new(
                        key.encode('utf-8'),
                        message.encode('utf-8'),
                        hash_func
                    ).digest()
                    
                    # Encode the signature
                    encoded_signature = base64.b64encode(signature).decode('utf-8')
                    encoded_signature = encoded_signature.replace('+', '-').replace('/', '_').rstrip('=')
                    
                    # Create the modified token
                    modified_token = f"{parts[0]}.{parts[1]}.{encoded_signature}"
                    
                    # Test the modified token
                    response = self._make_authenticated_request(
                        method="GET",
                        endpoint=self.user_info_endpoint,
                        token=modified_token
                    )
                    
                    if response.status_code in self.success_status_codes:
                        self.logger.warning(f"JWT authentication bypass via weak signing key detected (HMAC method): '{key}'")
                        weak_keys_found.append({"key": key, "method": "HMAC verification"})
                except Exception as e:
                    self.logger.debug(f"Error testing key '{key}' with HMAC method: {str(e)}")
            
            # Method 2: Using PyJWT and jwcrypto libraries for verification (if available)
            if HAS_JWT and HAS_JWCRYPTO:
                self.logger.info("Using PyJWT and jwcrypto for enhanced JWT verification")
                for key in self.weak_keys:
                    if not key:  # Skip empty key as jwk.JWK requires non-empty key
                        continue
                        
                    try:
                        # Create a JWK from the weak key
                        jwk_key = jwk.JWK.from_password(key.encode('utf-8'))
                        
                        # Try to verify the token
                        try:
                            # Create a modified token with the same header and payload but using our key
                            # This tests if we can create a valid token with our guessed key
                            # Convert JWK to a format PyJWT can use
                            key_data = jwk_key.export()
                            new_token = pyjwt.encode(payload, key_data, algorithm=alg)
                            
                            # Test the new token
                            response = self._make_authenticated_request(
                                method="GET",
                                endpoint=self.user_info_endpoint,
                                token=new_token
                            )
                            
                            if response.status_code in self.success_status_codes:
                                self.logger.warning(f"JWT authentication bypass via weak signing key detected (python_jwt method): '{key}'")
                                if not any(k["key"] == key for k in weak_keys_found):
                                    weak_keys_found.append({"key": key, "method": "python_jwt verification"})
                        except Exception as e:
                            self.logger.debug(f"Error testing key '{key}' with python_jwt: {str(e)}")
                            
                        # Also try direct verification of the original token
                        try:
                            # Convert JWK to a format PyJWT can use
                            key_data = jwk_key.export()
                            # PyJWT's decode function verifies the token
                            decoded = pyjwt.decode(token, key_data, algorithms=[alg])
                            self.logger.warning(f"JWT token verified with weak key (direct verification): '{key}'")
                            if not any(k["key"] == key for k in weak_keys_found):
                                weak_keys_found.append({"key": key, "method": "direct verification"})
                        except Exception:
                            # Verification failed with this key, which is expected for incorrect keys
                            pass
                    except Exception as e:
                        self.logger.debug(f"Error creating JWK for key '{key}': {str(e)}")
            else:
                self.logger.info("PyJWT and jwcrypto libraries not available, skipping enhanced JWT verification")
            
            # Method 3: Test for "none" algorithm bypass
            try:
                # Create a token with algorithm set to "none" and no signature
                none_header = header.copy()
                none_header["alg"] = "none"
                none_header_encoded = self._encode_jwt_part(none_header)
                none_token = f"{none_header_encoded}.{parts[1]}."
                
                # Test the modified token
                response = self._make_authenticated_request(
                    method="GET",
                    endpoint=self.user_info_endpoint,
                    token=none_token
                )
                
                if response.status_code in self.success_status_codes:
                    self.logger.warning("JWT 'none' algorithm bypass detected!")
                    weak_keys_found.append({"key": "NONE", "method": "none algorithm bypass"})
            except Exception as e:
                self.logger.debug(f"Error testing 'none' algorithm bypass: {str(e)}")
            
            # Report findings if weak keys were found
            if weak_keys_found:
                # Determine severity based on the type of weak keys found
                severity = "CRITICAL"
                
                # Extract just the keys for the message
                key_list = [k["key"] for k in weak_keys_found if k["key"] != "NONE"]
                key_details = ", ".join([f"'{k}'" for k in key_list]) if key_list else ""  
                
                # Create a detailed message based on the findings
                details = ""
                if any(k["key"] == "NONE" for k in weak_keys_found):
                    details = "The API accepts tokens with the 'none' algorithm, allowing authentication bypass without any signature. "
                
                if key_details:
                    if details:
                        details += "Additionally, "
                    details += f"the API uses weak or common signing keys ({key_details}) for JWT tokens, allowing attackers to forge valid tokens."
                
                if not details:
                    details = "The API is vulnerable to JWT authentication bypass."
                
                details += " This is a critical vulnerability that enables complete authentication bypass."
                
                # Add the finding
                self.add_finding(
                    vulnerability="JWT Authentication Bypass via Weak Signing Key",
                    details=details,
                    severity=severity,
                    endpoint=self.user_info_endpoint,
                    evidence={
                        "weak_keys_detected": weak_keys_found,
                        "algorithm": alg,
                        "test_endpoint": self.user_info_endpoint
                    },
                    remediation="Use a strong, randomly generated signing key of appropriate length (at least 256 bits for HS256). Store the key securely in a vault or environment variable, never hardcode it. Rotate keys periodically and implement proper key management practices. Always validate the algorithm and signature of JWT tokens."
                )
        except Exception as e:
            self.logger.error(f"Error testing for weak JWT signing keys: {str(e)}")
    
    def _test_jwt_missing_signature_validation(self, token: str) -> None:
        """
        Test if the API validates JWT signatures.
        
        Args:
            token: The token to test
        """
        self.logger.info("Testing for missing JWT signature validation")
        
        try:
            # Parse the original token
            parts = token.split('.')
            
            # Create a modified token with an invalid signature
            modified_token = f"{parts[0]}.{parts[1]}.invalid_signature"
            
            # Test the modified token
            response = self._make_authenticated_request(
                method="GET",
                endpoint=self.user_info_endpoint,
                token=modified_token
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.warning("Missing JWT signature validation detected!")
                self.add_finding(
                    vulnerability="Missing JWT Signature Validation",
                    details="The API does not properly validate JWT signatures, allowing attackers to modify token content without detection.",
                    severity="CRITICAL",
                    endpoint=self.user_info_endpoint,
                    evidence={
                        "original_token": token,
                        "modified_token": modified_token,
                        "response_code": response.status_code
                    },
                    remediation="Ensure that JWT signatures are properly validated. Use a secure JWT library and configure it to always verify signatures."
                )
            else:
                self.logger.info("JWT signature validation is properly implemented")
        except Exception as e:
            self.logger.error(f"Error testing JWT signature validation: {str(e)}")
    
    def _test_jwt_expiration_manipulation(self, token: str) -> None:
        """
        Test if the API validates JWT expiration times.
        
        Args:
            token: The token to test
        """
        self.logger.info("Testing for JWT expiration manipulation vulnerability")
        
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Check if the token has an expiration time
            if 'exp' not in payload:
                self.logger.warning("JWT token does not have an expiration time")
                self.add_finding(
                    vulnerability="JWT Without Expiration",
                    details="The JWT token does not have an expiration time (exp claim), making it valid indefinitely.",
                    severity="HIGH",
                    endpoint=self.login_endpoint,
                    evidence={
                        "token_payload": payload
                    },
                    remediation="Always include an expiration time (exp claim) in JWT tokens. The recommended lifetime is 15-60 minutes for access tokens."
                )
                return
                
            # Try to modify the expiration time to a far future date
            original_exp = payload['exp']
            payload['exp'] = int(time.time()) + 31536000  # 1 year in the future
            
            # Create a modified token with the new expiration
            new_header = self._encode_jwt_part(header)
            new_payload = self._encode_jwt_part(payload)
            
            # We can't create a valid signature without knowing the key,
            # so we'll just use the original signature to see if the server checks the payload against it
            modified_token = f"{new_header}.{new_payload}.{parts[2]}"
            
            # Test the modified token
            response = self._make_authenticated_request(
                method="GET",
                endpoint=self.user_info_endpoint,
                token=modified_token
            )
            
            if response.status_code in self.success_status_codes:
                self.logger.warning("JWT expiration manipulation vulnerability detected!")
                self.add_finding(
                    vulnerability="JWT Expiration Manipulation",
                    details="The API does not properly validate the integrity of JWT tokens, allowing attackers to modify the expiration time.",
                    severity="CRITICAL",
                    endpoint=self.user_info_endpoint,
                    evidence={
                        "original_expiration": original_exp,
                        "modified_expiration": payload['exp'],
                        "response_code": response.status_code
                    },
                    remediation="Ensure that JWT signatures are properly validated. Use a secure JWT library and configure it to always verify the token integrity."
                )
            else:
                self.logger.info("JWT expiration manipulation not possible")
                
            # Also check for tokens with very long expiration times
            if original_exp - int(time.time()) > 86400 * 30:  # More than 30 days
                self.logger.warning("JWT token has a very long expiration time")
                self.add_finding(
                    vulnerability="Long-Lived JWT Token",
                    details=f"The JWT token has a very long expiration time ({(original_exp - int(time.time())) / 86400:.1f} days), increasing the risk of token theft and misuse.",
                    severity="MEDIUM",
                    endpoint=self.login_endpoint,
                    evidence={
                        "expiration_timestamp": original_exp,
                        "current_timestamp": int(time.time()),
                        "days_valid": (original_exp - int(time.time())) / 86400
                    },
                    remediation="Use shorter expiration times for JWT tokens (15-60 minutes is recommended). For longer sessions, implement refresh tokens with proper security controls."
                )
        except Exception as e:
            self.logger.error(f"Error testing JWT expiration manipulation: {str(e)}")
    
    def _test_jwt_token_tampering(self, token: str) -> None:
        """
        Test if the API is vulnerable to JWT token tampering for privilege escalation.
        
        Args:
            token: The token to test
        """
        self.logger.info("Testing for JWT token tampering vulnerability")
        
        try:
            # Parse the original token
            parts = token.split('.')
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            payload_str = self._decode_jwt_part(parts[1])
            payload = json.loads(payload_str)
            
            # Create a modified payload with elevated privileges
            modified_payload = payload.copy()
            
            # Add common privilege escalation fields
            privilege_fields = {
                'role': 'admin',
                'roles': ['admin'],
                'isAdmin': True,
                'admin': True,
                'privileges': ['all'],
                'permission': 'admin',
                'permissions': ['admin', 'superuser'],
                'scope': 'admin',
                'scopes': ['admin'],
                'group': 'admin',
                'groups': ['admin', 'superuser'],
                'is_admin': True,
                'is_superuser': True,
                'user_type': 'admin'
            }
            
            # Apply privilege escalation modifications
            for field, value in privilege_fields.items():
                # If the field already exists, modify it; otherwise add it
                if field in modified_payload and isinstance(modified_payload[field], bool):
                    modified_payload[field] = True
                elif field in modified_payload and isinstance(modified_payload[field], (list, tuple)):
                    if 'admin' not in modified_payload[field]:
                        modified_payload[field].append('admin')
                elif field in modified_payload and isinstance(modified_payload[field], str):
                    modified_payload[field] = 'admin'
                else:
                    modified_payload[field] = value
            
            # Create multiple tampered tokens to test different scenarios
            tampered_tokens = []
            
            # 1. Standard tampering - keep original header and signature
            new_payload = self._encode_jwt_part(modified_payload)
            tampered_tokens.append(("Standard tampering", f"{parts[0]}.{new_payload}.{parts[2]}"))
            
            # 2. Change algorithm to 'none' and remove signature
            none_header = header.copy()
            none_header['alg'] = 'none'
            none_header_encoded = self._encode_jwt_part(none_header)
            tampered_tokens.append(("None algorithm", f"{none_header_encoded}.{new_payload}."))
            
            # 3. Change algorithm from HS256 to HS384 but keep same signature
            if header.get('alg') == 'HS256':
                hs384_header = header.copy()
                hs384_header['alg'] = 'HS384'
                hs384_header_encoded = self._encode_jwt_part(hs384_header)
                tampered_tokens.append(("Algorithm switching", f"{hs384_header_encoded}.{new_payload}.{parts[2]}"))
            
            # Test each tampered token
            for tampering_type, modified_token in tampered_tokens:
                # Test the modified token
                response = self._make_authenticated_request(
                    method="GET",
                    endpoint=self.user_info_endpoint,
                    token=modified_token
                )
                
                # Check if the tampering was successful
                success_indicators = [
                    'admin',
                    'superuser',
                    'privileges',
                    'permission',
                    'role',
                    'success',
                    'authenticated',
                    'authorized'
                ]
                
                response_text = ""
                try:
                    response_json = response.json()
                    response_text = json.dumps(response_json).lower()
                except Exception:
                    if response.text:
                        response_text = response.text.lower()
                
                if response.status_code in self.success_status_codes:
                    # Check for success indicators in the response
                    found_indicators = [ind for ind in success_indicators if ind in response_text]
                    
                    if found_indicators or tampering_type == "None algorithm" or tampering_type == "Algorithm switching":
                        self.logger.warning(f"JWT token tampering vulnerability detected! Type: {tampering_type}")
                        self.add_finding(
                            vulnerability=f"JWT Token Tampering - {tampering_type}",
                            details=f"The API does not properly validate the integrity of JWT tokens, allowing attackers to modify the payload using {tampering_type} to gain elevated privileges.",
                            severity="CRITICAL",
                            endpoint=self.user_info_endpoint,
                            evidence={
                                "tampering_type": tampering_type,
                                "original_token": token,
                                "modified_token": modified_token,
                                "original_payload": payload,
                                "modified_payload": modified_payload,
                                "response_code": response.status_code,
                                "response_indicators": found_indicators if found_indicators else ["successful response status code"]
                            },
                            remediation="Ensure that JWT signatures are properly validated. Use a secure JWT library and configure it to always verify the token integrity. Implement proper authorization checks on the server side. Never trust client-provided data for authorization decisions."
                        )
                        # Break after finding the first vulnerability to avoid duplicate findings
                        break
            else:
                self.logger.info("JWT token tampering not possible")
                
        except Exception as e:
            self.logger.error(f"Error testing JWT token tampering: {str(e)}")
    
    def _check_jwt_information_disclosure(self, access_token: Optional[str], id_token: Optional[str]) -> None:
        """
        Check if JWT tokens contain sensitive information.
        
        Args:
            access_token: The access token to check
            id_token: The ID token to check
        """
        self.logger.info("Checking for sensitive information in JWT tokens")
        
        tokens_to_check = []
        if access_token:
            tokens_to_check.append(("access_token", access_token))
        if id_token:
            tokens_to_check.append(("id_token", id_token))
        
        for token_name, token in tokens_to_check:
            try:
                # Parse the token
                parts = token.split('.')
                payload_str = self._decode_jwt_part(parts[1])
                payload = json.loads(payload_str)
                
                # Check for sensitive information in the payload
                sensitive_fields = {
                    'password': "Password",
                    'secret': "Secret",
                    'ssn': "Social Security Number",
                    'social_security': "Social Security Number",
                    'credit_card': "Credit Card",
                    'card_number': "Credit Card Number",
                    'phone': "Phone Number",
                    'address': "Address",
                    'dob': "Date of Birth",
                    'birth_date': "Date of Birth",
                    'birthdate': "Date of Birth"
                }
                
                found_sensitive = {}
                
                # Check for sensitive field names
                for field, description in sensitive_fields.items():
                    for key in payload.keys():
                        if field in key.lower():
                            found_sensitive[key] = description
                
                if found_sensitive:
                    self.logger.warn(f"Sensitive information found in {token_name}")
                    self.add_finding(
                        vulnerability="Sensitive Information in JWT Token",
                        details=f"The {token_name} contains potentially sensitive information: {', '.join(found_sensitive.values())}",
                        severity="HIGH",
                        endpoint=self.login_endpoint,
                        evidence={
                            "token_type": token_name,
                            "sensitive_fields": list(found_sensitive.keys())
                        },
                        remediation="Remove sensitive information from JWT tokens. Store sensitive data server-side and associate it with the user's session."
                    )
            except Exception as e:
                self.logger.error(f"Error analyzing JWT token: {str(e)}")
    
    def _make_authenticated_request(self, method: str, endpoint: str, token: str) -> Any:
        """
        Make an authenticated request with the provided token.
        
        Args:
            method: HTTP method to use
            endpoint: Endpoint to request
            token: Authentication token
            
        Returns:
            Response from the request
        """
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        # In debug mode with simulation enabled, simulate a successful response for testing
        if self.simulate_vulnerabilities:
            self.logger.info(f"Simulating request to {endpoint} with token: {token[:20]}...")
            
            # Create a mock response
            mock_response = requests.Response()
            mock_response.status_code = 200
            
            # For weak signing key tests, only return success for certain tokens
            # This simulates a vulnerable server that accepts tokens with weak keys
            if endpoint == self.user_info_endpoint:
                try:
                    # Check if this is a tampered token
                    parts = token.split('.')
                    if len(parts) >= 2:
                        header_str = self._decode_jwt_part(parts[0])
                        header = json.loads(header_str)
                        
                        # Simulate vulnerability to 'none' algorithm
                        if header.get('alg') == 'none':
                            self.logger.info("Simulating vulnerability to 'none' algorithm")
                            mock_response.status_code = 200
                            return mock_response
                            
                        # Simulate vulnerability to weak keys
                        if "secret" in token or "key" in token or "password" in token:
                            self.logger.info("Simulating vulnerability to weak keys")
                            mock_response.status_code = 200
                            return mock_response
                            
                        # Simulate vulnerability to token tampering
                        if any(field in token.lower() for field in ['admin', 'role', 'isadmin']):
                            self.logger.info("Simulating vulnerability to token tampering")
                            mock_response.status_code = 200
                            return mock_response
                            
                        # Simulate vulnerability to algorithm confusion
                        if 'RS256' in token or 'RS384' in token or 'RS512' in token:
                            self.logger.info("Simulating vulnerability to algorithm confusion")
                            mock_response.status_code = 200
                            return mock_response
                except Exception as e:
                    self.logger.error(f"Error in simulated response: {str(e)}")
            
            # Default response for other endpoints
            return mock_response
        
        # Make the actual request in non-debug mode
        return self._make_request(
            method=method,
            endpoint=endpoint,
            headers=headers
        )
        
    def _create_sample_token(self) -> str:
        """
        Create a sample JWT token for testing purposes.
        
        Returns:
            A JWT token string
        """
        try:
            if not HAS_JWT:
                self.logger.error("PyJWT library not found, cannot create test token")
                return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjE2MTIzNDU2LCJleHAiOjE2MTYyMDk4NTZ9.ZG9sbHkgcGFydG9uIGlzIHRoZSBxdWVlbiBvZiBjb3VudHJ5IG11c2lj"
            
            # Create a payload with common fields
            payload = {
                "sub": "1234567890",
                "name": "Test User",
                "role": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600 * 24  # 1 day
            }
            
            # Sign with a weak key
            weak_key = "secret"
            self.logger.debug(f"Creating token with weak key: '{weak_key}'")
            access_token = pyjwt.encode(payload, weak_key, algorithm="HS256")
            
            if isinstance(access_token, bytes):
                access_token = access_token.decode('utf-8')
            
            return access_token
        except Exception as e:
            self.logger.error(f"Error creating sample token: {str(e)}")
            return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjE2MTIzNDU2LCJleHAiOjE2MTYyMDk4NTZ9.ZG9sbHkgcGFydG9uIGlzIHRoZSBxdWVlbiBvZiBjb3VudHJ5IG11c2lj"
    
    def _create_tampered_token(self, original_token: str) -> str:
        """
        Create a tampered JWT token with the 'none' algorithm.
        
        Args:
            original_token: The original JWT token
            
        Returns:
            A tampered JWT token string
        """
        try:
            # Split the token into parts
            parts = original_token.split('.')
            if len(parts) != 3:
                self.logger.error(f"Invalid token format: {original_token}")
                return original_token
            
            # Decode the header
            header_str = self._decode_jwt_part(parts[0])
            header = json.loads(header_str)
            
            # Change the algorithm to 'none'
            header['alg'] = 'none'
            
            # Encode the header back
            new_header = self._encode_jwt_part(header)
            
            # Return the tampered token with empty signature
            return f"{new_header}.{parts[1]}."
        except Exception as e:
            self.logger.error(f"Error creating tampered token: {str(e)}")
            return original_token
    
    def _create_token_with_extended_expiry(self) -> str:
        """
        Create a JWT token with an extended expiration time.
        
        Returns:
            A JWT token string with extended expiry
        """
        try:
            if not HAS_JWT:
                self.logger.error("PyJWT library not found, cannot create test token")
                return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjE2MTIzNDU2LCJleHAiOjE2NDc2NTk0NTZ9.ZG9sbHkgcGFydG9uIGlzIHRoZSBxdWVlbiBvZiBjb3VudHJ5IG11c2lj"
            
            # Create a payload with common fields and extended expiry
            payload = {
                "sub": "1234567890",
                "name": "Test User",
                "role": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600 * 24 * 365  # 1 year
            }
            
            # Sign with a weak key
            weak_key = "secret"
            access_token = pyjwt.encode(payload, weak_key, algorithm="HS256")
            
            if isinstance(access_token, bytes):
                access_token = access_token.decode('utf-8')
            
            return access_token
        except Exception as e:
            self.logger.error(f"Error creating token with extended expiry: {str(e)}")
            return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjE2MTIzNDU2LCJleHAiOjE2NDc2NTk0NTZ9.ZG9sbHkgcGFydG9uIGlzIHRoZSBxdWVlbiBvZiBjb3VudHJ5IG11c2lj"
    
    def _create_admin_token(self) -> str:
        """
        Create a JWT token with admin privileges.
        
        Returns:
            A JWT token string with admin role
        """
        try:
            if not HAS_JWT:
                self.logger.error("PyJWT library not found, cannot create test token")
                return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYxNjEyMzQ1NiwiZXhwIjoxNjE2MjA5ODU2fQ.ZG9sbHkgcGFydG9uIGlzIHRoZSBxdWVlbiBvZiBjb3VudHJ5IG11c2lj"
            
            # Create a payload with admin role
            payload = {
                "sub": "1234567890",
                "name": "Test User",
                "role": "admin",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600 * 24  # 1 day
            }
            
            # Sign with a weak key
            weak_key = "secret"
            access_token = pyjwt.encode(payload, weak_key, algorithm="HS256")
            
            if isinstance(access_token, bytes):
                access_token = access_token.decode('utf-8')
            
            return access_token
        except Exception as e:
            self.logger.error(f"Error creating admin token: {str(e)}")
            return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYxNjEyMzQ1NiwiZXhwIjoxNjE2MjA5ODU2fQ.ZG9sbHkgcGFydG9uIGlzIHRoZSBxdWVlbiBvZiBjb3VudHJ5IG11c2lj"
    
    def _decode_token_payload(self, token: str) -> Dict[str, Any]:
        """
        Decode the payload of a JWT token without verification.
        
        Args:
            token: The JWT token to decode
            
        Returns:
            The decoded payload as a dictionary
        """
        try:
            # Split the token into parts
            parts = token.split('.')
            if len(parts) < 2:
                self.logger.error(f"Invalid token format: {token}")
                return {}
            
            # Decode the payload
            payload_str = self._decode_jwt_part(parts[1])
            return json.loads(payload_str)
        except Exception as e:
            self.logger.error(f"Error decoding token payload: {str(e)}")
            return {}
