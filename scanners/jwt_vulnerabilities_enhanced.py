"""
Enhanced JWT Vulnerabilities Scanner

This scanner detects JWT-related vulnerabilities in APIs, with enhanced capabilities
to handle different API structures and authentication requirements.
"""

import json
import base64
import time
from typing import Dict, List, Any, Optional, Union

import jwt
from jwt.exceptions import PyJWTError

from core.base_scanner import BaseScanner
from core.exceptions import ScannerExecutionError
from core.openapi import find_endpoint_by_purpose


class JWTVulnerabilitiesEnhancedScanner(BaseScanner):
    """Scanner for detecting JWT-related vulnerabilities with enhanced authentication handling."""
    
    def __init__(self, target: Dict[str, Any], config: Dict[str, Any]):
        """Initialize the JWT vulnerabilities scanner."""
        super().__init__(target, config)
        self.endpoints = target.get("endpoints", {})
        self.auth_endpoints = []
        self.protected_endpoints = []
        self.jwt_token = None
        self.jwt_header = {}
        self.jwt_payload = {}
        
        # JWT testing config
        self.test_none_algorithm = config.get("test_none_algorithm", True)
        self.test_weak_keys = config.get("test_weak_keys", True)
        self.test_missing_signature = config.get("test_missing_signature", True)
        self.test_token_replay = config.get("test_token_replay", True)
        self.test_expiration = config.get("test_expiration", True)
        self.test_kid_injection = config.get("test_kid_injection", True)
        
        # Common weak keys to test
        self.weak_keys = [
            "secret",
            "key",
            "private",
            "SECRET",
            "SECRET_KEY",
            "jwt_secret",
            "JWT_SECRET",
            "api_secret",
            "API_SECRET",
            "password",
            "PASSWORD",
            "123456",
            "qwerty",
            "admin",
            "welcome",
            "123456789",
            "test",
            "password123",
            "12345",
            "1234567890"
        ]
        
        # Common JWT header fields
        self.common_jwt_headers = {
            "alg": ["HS256", "RS256", "ES256", "none"],
            "typ": ["JWT"],
            "kid": ["1", "key1", "key-1"]
        }
    
    def _find_auth_endpoints(self) -> None:
        """Find authentication-related endpoints in the API."""
        # Look for login/token endpoints
        login_patterns = [
            "/login", "/auth/login", "/api/login", "/api/auth/login",
            "/signin", "/auth/signin", "/api/signin", "/api/auth/signin",
            "/sign-in", "/auth/sign-in", "/api/sign-in", "/api/auth/sign-in",
            "/token", "/auth/token", "/api/token", "/api/auth/token",
            "/oauth/token", "/oauth2/token", "/api/oauth/token", "/api/oauth2/token"
        ]
        
        # Look for JWT verification endpoints
        verify_patterns = [
            "/verify", "/auth/verify", "/api/verify", "/api/auth/verify",
            "/validate", "/auth/validate", "/api/validate", "/api/auth/validate",
            "/check", "/auth/check", "/api/check", "/api/auth/check",
            "/refresh", "/auth/refresh", "/api/refresh", "/api/auth/refresh"
        ]
        
        # Look for protected endpoints that might require JWT
        protected_patterns = [
            "/users/me", "/user/me", "/api/users/me", "/api/user/me",
            "/profile", "/api/profile", "/account", "/api/account",
            "/dashboard", "/api/dashboard", "/admin", "/api/admin"
        ]
        
        # Find endpoints from OpenAPI spec if available
        if self.endpoints:
            # Find login endpoints
            login_endpoint = find_endpoint_by_purpose(self.endpoints, "login")
            if login_endpoint:
                self.auth_endpoints.append(login_endpoint)
                
            # Find token endpoints
            token_endpoint = find_endpoint_by_purpose(self.endpoints, "token")
            if token_endpoint:
                self.auth_endpoints.append(token_endpoint)
                
            # Find verify endpoints
            verify_endpoint = find_endpoint_by_purpose(self.endpoints, "verify")
            if verify_endpoint:
                self.auth_endpoints.append(verify_endpoint)
                
            # Find refresh endpoints
            refresh_endpoint = find_endpoint_by_purpose(self.endpoints, "refresh")
            if refresh_endpoint:
                self.auth_endpoints.append(refresh_endpoint)
                
            # Find protected endpoints
            for endpoint in self.endpoints:
                path = endpoint.get("path", "")
                method = endpoint.get("method", "").upper()
                security = endpoint.get("security", [])
                
                # Check if endpoint has security requirements
                if security:
                    self.protected_endpoints.append(endpoint)
                    continue
                    
                # Check if endpoint path matches protected patterns
                for pattern in protected_patterns:
                    if pattern in path:
                        self.protected_endpoints.append(endpoint)
                        break
        
        # If no endpoints found from OpenAPI spec, try common patterns
        if not self.auth_endpoints:
            # Try to discover auth endpoints by making requests
            self.logger.info("No auth endpoints found in OpenAPI spec, trying common patterns")
            
            # Try login patterns
            for pattern in login_patterns:
                try:
                    response = self._make_request("GET", pattern, try_auth_if_needed=False)
                    # If we get a response that's not a 404, it might be an auth endpoint
                    if response.status_code != 404:
                        self.logger.info(f"Potential auth endpoint found: {pattern}")
                        self.auth_endpoints.append({"path": pattern, "method": "POST"})
                except Exception as e:
                    self.logger.debug(f"Error checking {pattern}: {str(e)}")
            
            # Try verify patterns
            for pattern in verify_patterns:
                try:
                    response = self._make_request("GET", pattern, try_auth_if_needed=False)
                    # If we get a response that's not a 404, it might be an auth endpoint
                    if response.status_code != 404:
                        self.logger.info(f"Potential JWT verification endpoint found: {pattern}")
                        self.auth_endpoints.append({"path": pattern, "method": "GET"})
                except Exception as e:
                    self.logger.debug(f"Error checking {pattern}: {str(e)}")
        
        # If no protected endpoints found from OpenAPI spec, try common patterns
        if not self.protected_endpoints:
            # Try to discover protected endpoints by making requests
            self.logger.info("No protected endpoints found in OpenAPI spec, trying common patterns")
            
            # Try protected patterns
            for pattern in protected_patterns:
                try:
                    response = self._make_request("GET", pattern, try_auth_if_needed=False)
                    # If we get a 401/403, it's likely a protected endpoint
                    if response.status_code in [401, 403]:
                        self.logger.info(f"Potential protected endpoint found: {pattern}")
                        self.protected_endpoints.append({"path": pattern, "method": "GET"})
                except Exception as e:
                    self.logger.debug(f"Error checking {pattern}: {str(e)}")
    
    def _get_valid_jwt_token(self) -> Optional[str]:
        """
        Get a valid JWT token from the API.
        
        Returns:
            JWT token string or None if not found
        """
        # Check if we already have a token from the auth handler
        auth_header = self.auth_handler.get_auth_header()
        if auth_header and "Authorization" in auth_header:
            auth_value = auth_header["Authorization"]
            if auth_value.startswith("Bearer "):
                token = auth_value.split(" ")[1]
                self.logger.info("Using JWT token from auth handler")
                return token
        
        # Try to get a token from login endpoints
        for endpoint in self.auth_endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "POST")
            
            # Skip non-login endpoints
            if not any(pattern in path for pattern in ["/login", "/signin", "/sign-in", "/token"]):
                continue
                
            # Try to login
            try:
                # Prepare credentials
                credentials = self.auth.get("credentials", {})
                username = credentials.get("username", credentials.get("email", ""))
                password = credentials.get("password", "")
                
                if not username or not password:
                    self.logger.warning("No credentials available for login")
                    continue
                
                # Prepare payload with common field names
                payload = {
                    "username": username,
                    "email": username,
                    "password": password
                }
                
                # Try to login
                self.logger.info(f"Attempting to login at {path}")
                response = self._make_request(
                    method,
                    path,
                    json_data=payload,
                    try_auth_if_needed=False
                )
                
                # Check if login was successful
                if response.status_code in [200, 201, 204]:
                    try:
                        response_json = response.json()
                        
                        # Look for token in response
                        token_fields = ["token", "access_token", "accessToken", "id_token", "idToken", "jwt"]
                        for field in token_fields:
                            if field in response_json:
                                token = response_json[field]
                                if isinstance(token, str) and "." in token:
                                    self.logger.info(f"Found JWT token in {field} field")
                                    return token
                        
                        # Look for token in nested objects
                        for key, value in response_json.items():
                            if isinstance(value, dict):
                                for field in token_fields:
                                    if field in value:
                                        token = value[field]
                                        if isinstance(token, str) and "." in token:
                                            self.logger.info(f"Found JWT token in {key}.{field} field")
                                            return token
                    except Exception as e:
                        self.logger.debug(f"Error parsing login response: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error during login at {path}: {str(e)}")
        
        self.logger.warning("Could not obtain a valid JWT token")
        return None
    
    def _parse_jwt_token(self, token: str) -> bool:
        """
        Parse a JWT token into header and payload.
        
        Args:
            token: JWT token string
            
        Returns:
            True if parsing was successful, False otherwise
        """
        try:
            # Split the token
            parts = token.split(".")
            if len(parts) < 2:
                self.logger.warning("Invalid JWT token format")
                return False
                
            # Decode header
            header_b64 = parts[0]
            # Add padding if needed
            header_b64 += "=" * ((4 - len(header_b64) % 4) % 4)
            header_json = base64.b64decode(header_b64).decode("utf-8")
            self.jwt_header = json.loads(header_json)
            
            # Decode payload
            payload_b64 = parts[1]
            # Add padding if needed
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            self.jwt_payload = json.loads(payload_json)
            
            self.logger.info(f"Parsed JWT token: alg={self.jwt_header.get('alg')}")
            return True
        except Exception as e:
            self.logger.warning(f"Error parsing JWT token: {str(e)}")
            return False
    
    def _create_modified_token(self, 
                              header_modifications: Dict[str, Any] = None, 
                              payload_modifications: Dict[str, Any] = None,
                              sign_with_key: str = None) -> str:
        """
        Create a modified JWT token.
        
        Args:
            header_modifications: Modifications to make to the header
            payload_modifications: Modifications to make to the payload
            sign_with_key: Key to use for signing, or None for 'none' algorithm
            
        Returns:
            Modified JWT token
        """
        # Start with the original header and payload
        header = self.jwt_header.copy()
        payload = self.jwt_payload.copy()
        
        # Apply header modifications
        if header_modifications:
            header.update(header_modifications)
            
        # Apply payload modifications
        if payload_modifications:
            payload.update(payload_modifications)
            
        # Create the token
        if header.get("alg") == "none" or not sign_with_key:
            # For 'none' algorithm, we need to create the token manually
            header_b64 = base64.b64encode(json.dumps(header).encode()).decode().rstrip("=")
            payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            return f"{header_b64}.{payload_b64}."
        else:
            # For other algorithms, use PyJWT
            return jwt.encode(payload, sign_with_key, algorithm=header.get("alg"), headers=header)
    
    def _test_none_algorithm(self) -> None:
        """Test for JWT 'none' algorithm vulnerability."""
        if not self.test_none_algorithm:
            self.logger.info("Skipping 'none' algorithm test")
            return
            
        self.logger.info("Testing for JWT 'none' algorithm vulnerability")
        
        # Create a token with 'none' algorithm
        token = self._create_modified_token(
            header_modifications={"alg": "none", "typ": "JWT"},
            payload_modifications=None
        )
        
        # Try to use the token on protected endpoints
        for endpoint in self.protected_endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            
            try:
                self.logger.info(f"Testing 'none' algorithm on {path}")
                response = self._make_request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {token}"},
                    try_auth_if_needed=False,
                    capture_for_evidence=True
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    self.logger.warning(f"JWT 'none' algorithm vulnerability found on {path}")
                    self.add_finding(
                        vulnerability="JWT 'none' Algorithm Vulnerability",
                        severity="CRITICAL",
                        endpoint=path,
                        details="The API accepts JWT tokens with the 'none' algorithm, allowing authentication bypass.",
                        evidence={
                            "token": token,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Reject tokens with 'none' algorithm by explicitly checking the algorithm.\n"
                            "2. Use a library that rejects 'none' algorithm by default.\n"
                            "3. Implement proper signature verification for all tokens."
                        ),
                        request_data=response._request_details if hasattr(response, '_request_details') else None,
                        response_data=response._response_details if hasattr(response, '_response_details') else None
                    )
                    return  # Found a vulnerability, no need to check other endpoints
            except Exception as e:
                self.logger.debug(f"Error testing 'none' algorithm on {path}: {str(e)}")
        
        self.logger.info("No JWT 'none' algorithm vulnerability found")
    
    def _test_weak_keys(self) -> None:
        """Test for JWT weak signing key vulnerability."""
        if not self.test_weak_keys:
            self.logger.info("Skipping weak keys test")
            return
            
        self.logger.info("Testing for JWT weak signing key vulnerability")
        
        # Get the original algorithm
        alg = self.jwt_header.get("alg")
        if not alg or alg == "none" or not alg.startswith("HS"):
            self.logger.info("Skipping weak keys test for non-HMAC algorithm")
            return
            
        # Try common weak keys
        for key in self.weak_keys:
            try:
                # Create a token with the weak key
                token = self._create_modified_token(
                    header_modifications=None,
                    payload_modifications=None,
                    sign_with_key=key
                )
                
                # Try to use the token on protected endpoints
                for endpoint in self.protected_endpoints:
                    path = endpoint.get("path", "")
                    method = endpoint.get("method", "GET")
                    
                    try:
                        self.logger.info(f"Testing weak key '{key}' on {path}")
                        response = self._make_request(
                            method,
                            path,
                            headers={"Authorization": f"Bearer {token}"},
                            try_auth_if_needed=False,
                            capture_for_evidence=True
                        )
                        
                        # Check if the request was successful
                        if response.status_code in [200, 201, 204]:
                            self.logger.warning(f"JWT weak signing key vulnerability found on {path} with key '{key}'")
                            self.add_finding(
                                vulnerability="JWT Weak Signing Key",
                                severity="CRITICAL",
                                endpoint=path,
                                details=f"The API uses a weak signing key ('{key}') for JWT tokens, allowing token forgery.",
                                evidence={
                                    "token": token,
                                    "weak_key": key,
                                    "response_code": response.status_code
                                },
                                remediation=(
                                    "1. Use a strong, randomly generated key with sufficient length (at least 256 bits).\n"
                                    "2. Store the key securely and rotate it periodically.\n"
                                    "3. Consider using asymmetric algorithms (RS256, ES256) instead of symmetric ones (HS256)."
                                ),
                                request_data=response._request_details if hasattr(response, '_request_details') else None,
                                response_data=response._response_details if hasattr(response, '_response_details') else None
                            )
                            return  # Found a vulnerability, no need to check other keys or endpoints
                    except Exception as e:
                        self.logger.debug(f"Error testing weak key on {path}: {str(e)}")
            except Exception as e:
                self.logger.debug(f"Error creating token with key '{key}': {str(e)}")
        
        self.logger.info("No JWT weak signing key vulnerability found")
    
    def _test_missing_signature_validation(self) -> None:
        """Test for missing JWT signature validation."""
        if not self.test_missing_signature:
            self.logger.info("Skipping missing signature validation test")
            return
            
        self.logger.info("Testing for missing JWT signature validation")
        
        # Create a token with an invalid signature
        token_parts = self.jwt_token.split(".")
        if len(token_parts) < 3:
            self.logger.warning("Invalid JWT token format, skipping missing signature validation test")
            return
            
        # Create a token with the same header and payload but an invalid signature
        invalid_token = f"{token_parts[0]}.{token_parts[1]}.INVALID_SIGNATURE"
        
        # Try to use the token on protected endpoints
        for endpoint in self.protected_endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            
            try:
                self.logger.info(f"Testing invalid signature on {path}")
                response = self._make_request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {invalid_token}"},
                    try_auth_if_needed=False,
                    capture_for_evidence=True
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    self.logger.warning(f"Missing JWT signature validation vulnerability found on {path}")
                    self.add_finding(
                        vulnerability="Missing JWT Signature Validation",
                        severity="CRITICAL",
                        endpoint=path,
                        details="The API does not properly validate JWT signatures, allowing attackers to modify token content without detection.",
                        evidence={
                            "token": invalid_token,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Implement proper signature verification for all tokens.\n"
                            "2. Use a library that validates signatures by default.\n"
                            "3. Ensure the signature is checked against the expected key or certificate."
                        ),
                        request_data=response._request_details if hasattr(response, '_request_details') else None,
                        response_data=response._response_details if hasattr(response, '_response_details') else None
                    )
                    return  # Found a vulnerability, no need to check other endpoints
            except Exception as e:
                self.logger.debug(f"Error testing invalid signature on {path}: {str(e)}")
        
        self.logger.info("No missing JWT signature validation vulnerability found")
    
    def _test_token_expiration_manipulation(self) -> None:
        """Test for JWT expiration time manipulation vulnerability."""
        if not self.test_expiration:
            self.logger.info("Skipping expiration manipulation test")
            return
            
        self.logger.info("Testing for JWT expiration manipulation vulnerability")
        
        # Check if the token has an expiration claim
        if "exp" not in self.jwt_payload:
            self.logger.info("No expiration claim in token, skipping expiration manipulation test")
            return
            
        # Create a token with a far-future expiration time
        token = self._create_modified_token(
            header_modifications=None,
            payload_modifications={"exp": int(time.time()) + 31536000},  # 1 year in the future
            sign_with_key=None  # Use invalid signature
        )
        
        # Try to use the token on protected endpoints
        for endpoint in self.protected_endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            
            try:
                self.logger.info(f"Testing expiration manipulation on {path}")
                response = self._make_request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {token}"},
                    try_auth_if_needed=False,
                    capture_for_evidence=True
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    self.logger.warning(f"JWT expiration manipulation vulnerability found on {path}")
                    self.add_finding(
                        vulnerability="JWT Expiration Manipulation",
                        severity="CRITICAL",
                        endpoint=path,
                        details="The API does not properly validate the integrity of JWT tokens, allowing attackers to modify the expiration time.",
                        evidence={
                            "token": token,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Implement proper signature verification for all tokens.\n"
                            "2. Validate the expiration time against the current time.\n"
                            "3. Consider using shorter expiration times and refresh tokens."
                        ),
                        request_data=response._request_details if hasattr(response, '_request_details') else None,
                        response_data=response._response_details if hasattr(response, '_response_details') else None
                    )
                    return  # Found a vulnerability, no need to check other endpoints
            except Exception as e:
                self.logger.debug(f"Error testing expiration manipulation on {path}: {str(e)}")
        
        self.logger.info("No JWT expiration manipulation vulnerability found")
    
    def _test_token_tampering(self) -> None:
        """Test for JWT token tampering vulnerability."""
        self.logger.info("Testing for JWT token tampering vulnerability")
        
        # Create a token with elevated privileges
        token = self._create_modified_token(
            header_modifications={"alg": "none", "typ": "JWT"},
            payload_modifications={"role": "admin", "isAdmin": True, "admin": True}
        )
        
        # Try to use the token on protected endpoints
        for endpoint in self.protected_endpoints:
            path = endpoint.get("path", "")
            method = endpoint.get("method", "GET")
            
            try:
                self.logger.info(f"Testing token tampering on {path}")
                response = self._make_request(
                    method,
                    path,
                    headers={"Authorization": f"Bearer {token}"},
                    try_auth_if_needed=False,
                    capture_for_evidence=True
                )
                
                # Check if the request was successful
                if response.status_code in [200, 201, 204]:
                    self.logger.warning(f"JWT token tampering vulnerability found on {path}")
                    self.add_finding(
                        vulnerability="JWT Token Tampering - None algorithm",
                        severity="CRITICAL",
                        endpoint=path,
                        details="The API does not properly validate the integrity of JWT tokens, allowing attackers to modify the payload using None algorithm to gain elevated privileges.",
                        evidence={
                            "token": token,
                            "response_code": response.status_code
                        },
                        remediation=(
                            "1. Implement proper signature verification for all tokens.\n"
                            "2. Reject tokens with 'none' algorithm.\n"
                            "3. Validate all claims in the token, especially role and permission claims."
                        ),
                        request_data=response._request_details if hasattr(response, '_request_details') else None,
                        response_data=response._response_details if hasattr(response, '_response_details') else None
                    )
                    return  # Found a vulnerability, no need to check other endpoints
            except Exception as e:
                self.logger.debug(f"Error testing token tampering on {path}: {str(e)}")
        
        self.logger.info("No JWT token tampering vulnerability found")
    
    def run(self) -> List[Dict[str, Any]]:
        """
        Run the JWT vulnerabilities scanner.
        
        Returns:
            List of findings
        """
        self.logger.info("Running JWT vulnerabilities scanner")
        
        # Find authentication endpoints
        self._find_auth_endpoints()
        
        if not self.auth_endpoints and not self.protected_endpoints:
            self.logger.warning("No authentication or protected endpoints found, skipping JWT vulnerability tests")
            return self.findings
            
        self.logger.info(f"Found {len(self.auth_endpoints)} auth endpoints and {len(self.protected_endpoints)} protected endpoints")
        
        # Get a valid JWT token
        self.jwt_token = self._get_valid_jwt_token()
        if not self.jwt_token:
            self.logger.warning("Could not obtain a valid JWT token, skipping some JWT vulnerability tests")
        else:
            # Parse the token
            if not self._parse_jwt_token(self.jwt_token):
                self.logger.warning("Could not parse JWT token, skipping some JWT vulnerability tests")
            else:
                # Run tests that require a valid token
                self._test_weak_keys()
                self._test_missing_signature_validation()
                self._test_token_expiration_manipulation()
        
        # Run tests that don't require a valid token
        self._test_none_algorithm()
        self._test_token_tampering()
        
        return self.findings
