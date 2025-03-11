"""
Test module for JWT vulnerabilities scanner.

This module tests the functionality of the JWT vulnerabilities scanner,
which detects issues like weak signing keys, algorithm confusion, and missing validation.
"""

import os
import sys
import json
import unittest
import jwt
from datetime import datetime, timedelta, timezone

# Add parent directory to path to import scanner modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.jwt_vulnerabilities import Scanner


class MockResponse:
    """Mock response object for testing."""
    
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data
        
    def json(self):
        return self._json_data


class TestJWTVulnerabilitiesScanner(unittest.TestCase):
    """Test cases for JWT vulnerabilities scanner."""
    
    def setUp(self):
        """Set up test environment."""
        # Mock configuration
        self.target = {
            "base_url": "http://localhost:5002",
            "headers": {
                "Content-Type": "application/json"
            }
        }
        
        self.config = {
            "login_endpoint": "/users/v1/login",
            "user_info_endpoint": "/users/v1/me",
            "register_endpoint": "/users/v1/register",
            "username_field": "username",
            "password_field": "password",
            "access_token_field": "auth_token",
            "success_status_codes": [200, 201, 204],
            "weak_keys": ["secret", "key", "password"],
            "jwt_algorithms": ["none", "HS256", "HS384", "HS512"]
        }
        
        # Create scanner instance
        self.scanner = Scanner(self.target, self.config)
        
        # Override _make_request to avoid actual HTTP requests
        self.scanner._make_request = self._mock_make_request
        self.scanner._make_authenticated_request = self._mock_make_authenticated_request
        
        # Test data
        self.test_username = "test_user"
        self.test_password = "Test@123"
        
        # Create test tokens
        self.valid_token = self._create_test_token("secret", "HS256", 3600)
        self.expired_token = self._create_test_token("secret", "HS256", -3600)
        self.no_exp_token = self._create_test_token("secret", "HS256", None)
        self.weak_key_token = self._create_test_token("secret", "HS256", 3600)
        
    def _create_test_token(self, key, algorithm, expiration_seconds):
        """Create a test JWT token."""
        payload = {
            "sub": self.test_username,
            "iat": datetime.now(timezone.utc),
            "iss": "test-issuer"
        }
        
        # Add expiration if specified
        if expiration_seconds is not None:
            payload["exp"] = datetime.now(timezone.utc) + timedelta(seconds=expiration_seconds)
            
        # Create token
        if algorithm == "none":
            # Special case for 'none' algorithm
            header = {"alg": "none", "typ": "JWT"}
            header_b64 = jwt.utils.base64url_encode(json.dumps(header).encode()).decode()
            payload_b64 = jwt.utils.base64url_encode(json.dumps(payload).encode()).decode()
            return f"{header_b64}.{payload_b64}."
        else:
            return jwt.encode(payload, key, algorithm=algorithm)
    
    def _mock_make_request(self, method, endpoint, json_data=None, headers=None):
        """Mock the _make_request method."""
        if endpoint == self.config["register_endpoint"] and method == "POST":
            return MockResponse(201)
            
        if endpoint == self.config["login_endpoint"] and method == "POST":
            return MockResponse(200, {
                self.config["access_token_field"]: self.valid_token
            })
            
        return MockResponse(404)
    
    def _mock_make_authenticated_request(self, method, endpoint, token):
        """Mock the _make_authenticated_request method."""
        # For testing the 'none' algorithm vulnerability
        if token.count('.') == 2 and token.split('.')[0] and token.split('.')[1]:
            try:
                header_b64 = token.split('.')[0]
                header_str = jwt.utils.base64url_decode(header_b64).decode('utf-8')
                header = json.loads(header_str)
                
                # Simulate a server that accepts 'none' algorithm
                if header.get('alg') == 'none':
                    return MockResponse(200, {"message": "Success"})
                    
                # Simulate a server vulnerable to algorithm confusion
                if header.get('alg') == 'RS256' and token.split('.')[2]:
                    return MockResponse(200, {"message": "Success"})
            except Exception:
                pass
        
        # For testing weak keys
        if token == self.weak_key_token:
            return MockResponse(200, {"message": "Success"})
            
        # For testing token without expiration
        if token == self.no_exp_token:
            return MockResponse(200, {"message": "Success"})
            
        # Default: token is invalid
        return MockResponse(401, {"message": "Unauthorized"})
    
    def test_is_jwt_token(self):
        """Test JWT token detection."""
        self.assertTrue(self.scanner._is_jwt_token(self.valid_token))
        self.assertFalse(self.scanner._is_jwt_token("not-a-jwt-token"))
        self.assertFalse(self.scanner._is_jwt_token(None))
    
    def test_jwt_none_algorithm(self):
        """Test detection of JWT 'none' algorithm vulnerability."""
        # Reset findings
        self.scanner.findings = []
        
        # Test the vulnerability
        self.scanner._test_jwt_none_algorithm(self.valid_token)
        
        # Check if the vulnerability was detected
        none_findings = [f for f in self.scanner.findings if "none" in f["vulnerability"].lower()]
        self.assertTrue(len(none_findings) > 0, "Should detect 'none' algorithm vulnerability")
    
    def test_jwt_algorithm_confusion(self):
        """Test detection of JWT algorithm confusion vulnerability."""
        # Reset findings
        self.scanner.findings = []
        
        # Test the vulnerability
        self.scanner._test_jwt_algorithm_confusion(self.valid_token)
        
        # Check if the vulnerability was detected
        confusion_findings = [f for f in self.scanner.findings if "confusion" in f["vulnerability"].lower()]
        self.assertTrue(len(confusion_findings) > 0, "Should detect algorithm confusion vulnerability")
    
    def test_jwt_weak_signing_key(self):
        """Test detection of weak JWT signing key."""
        # Reset findings
        self.scanner.findings = []
        
        # Test the vulnerability
        self.scanner._test_jwt_weak_signing_key(self.weak_key_token)
        
        # Check if the vulnerability was detected
        weak_key_findings = [f for f in self.scanner.findings if "weak" in f["vulnerability"].lower()]
        self.assertTrue(len(weak_key_findings) > 0, "Should detect weak signing key vulnerability")
    
    def test_jwt_expiration_manipulation(self):
        """Test detection of JWT without expiration."""
        # Reset findings
        self.scanner.findings = []
        
        # Test the vulnerability
        self.scanner._test_jwt_expiration_manipulation(self.no_exp_token)
        
        # Check if the vulnerability was detected
        exp_findings = [f for f in self.scanner.findings if "expiration" in f["vulnerability"].lower()]
        self.assertTrue(len(exp_findings) > 0, "Should detect missing expiration vulnerability")
    
    def test_run_scanner(self):
        """Test running the full scanner."""
        # Reset findings
        self.scanner.findings = []
        
        # Run the scanner
        findings = self.scanner.run()
        
        # Check if any vulnerabilities were detected
        self.assertTrue(len(findings) > 0, "Scanner should detect at least one vulnerability")


if __name__ == "__main__":
    unittest.main()
