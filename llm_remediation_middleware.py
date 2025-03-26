#!/usr/bin/env python3
"""
LLM Remediation Middleware

This module provides a middleware for enhancing vulnerability remediation steps
using LLM APIs (OpenAI or Ollama) with Redis caching. It includes support for:

1. Template versioning for cache management
2. Section template loading and generation for missing sections
3. Enhanced metadata for tracking template usage
4. Intelligent response parsing to identify and fill missing sections

The middleware can be used to enhance scan results with detailed remediation steps
that are tailored to specific vulnerability types and API structures.
"""

import json
import logging
import os
import sys
import time
import hashlib
import re
import datetime
import concurrent.futures
from typing import Dict, Any, List, Optional, Tuple

import redis
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from pydantic import BaseModel, Field

from utils.prompt_manager import get_prompt_template

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("llm_remediation")

class RemediationConfig(BaseModel):
    """Configuration for the LLM remediation middleware."""
    
    # Redis configuration
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_db: int = Field(default=0, description="Redis database")
    redis_password: str = Field(default="", description="Redis password")
    redis_cache_ttl: int = Field(
        default=86400 * 7, description="Redis cache TTL in seconds (default: 7 days)"
    )
    redis_key_prefix: str = Field(
        default="llm_remed:", description="Redis key prefix for namespacing"
    )
    
    # LLM configuration
    llm_provider: str = Field(
        default="ollama", description="LLM provider (openai or ollama)"
    )
    
    # OpenAI configuration
    openai_api_key: Optional[str] = Field(
        default=None, description="OpenAI API key"
    )
    openai_model: str = Field(
        default="gpt-4", description="OpenAI model to use"
    )
    
    # Ollama configuration
    ollama_base_url: str = Field(
        default="http://localhost:11434", description="Ollama base URL"
    )
    ollama_model: str = Field(
        default="llama3.3", description="Ollama model to use"
    )
    
    # General LLM configuration
    temperature: float = Field(
        default=0.2, description="Temperature for LLM generation"
    )
    max_tokens: int = Field(
        default=1024, description="Maximum tokens for LLM generation"
    )
    
    # Batch processing configuration
    batch_size: int = Field(
        default=10, description="Batch size for processing vulnerabilities"
    )
    max_workers: int = Field(
        default=5, description="Maximum number of worker threads for batch processing"
    )
    
    class Config:
        """Pydantic config."""
        
        extra = "allow"


class ScannerResults(BaseModel):
    """Model for scanner results."""
    
    name: str = Field(..., description="Scanner name")
    vulnerabilities: List[Dict[str, Any]] = Field(
        default_factory=list, description="List of vulnerabilities"
    )
    
    class Config:
        extra = "allow"


class ScanResults(BaseModel):
    """Model for overall scan results."""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Target URL or system")
    start_time: str = Field(..., description="Scan start time")
    duration: float = Field(..., description="Scan duration in seconds")
    scanners: List[ScannerResults] = Field(
        default_factory=list, description="List of scanner results"
    )
    
    class Config:
        extra = "allow"


class LLMRemediationMiddleware:
    """
    Middleware that enhances vulnerability remediation details using LLM APIs
    with Redis caching.
    """
    
    def __init__(self, config: RemediationConfig):
        """
        Initialize the middleware with the provided configuration.
        
        Args:
            config: Configuration for the middleware
        """
        self.config = config
        self._setup_redis()
        self._setup_llm()
        self._setup_prompt_template()
        
        # Statistics tracking
        self.processed_count = 0
        self.total_count = 0
        self.success_count = 0
        self.error_count = 0
        self.skipped_count = 0
        self.start_time = None
    
    def _setup_redis(self):
        """Set up Redis connection for caching."""
        try:
            self.redis_client = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password,
                decode_responses=True,
            )
            # Test connection
            self.redis_client.ping()
            logger.info(
                f"Connected to Redis at {self.config.redis_host}:{self.config.redis_port}"
            )
        except redis.ConnectionError as e:
            logger.warning(f"Failed to connect to Redis: {e}")
            logger.warning("Proceeding without caching")
            self.redis_client = None
    
    def _setup_llm(self):
        """Set up LLM client based on the configured provider."""
        if self.config.llm_provider == "openai":
            # Check if OpenAI API key is available
            openai_api_key = self.config.openai_api_key or os.environ.get("OPENAI_API_KEY")
            
            if not openai_api_key:
                logger.error("OpenAI API key is not provided. Please set it in the .env file or pass it as an argument.")
                sys.exit(1)
                
            # Set OpenAI API key
            os.environ["OPENAI_API_KEY"] = openai_api_key
            
            try:
                # Use ChatOpenAI instead of the deprecated OpenAI class
                self.llm = ChatOpenAI(
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    model=self.config.openai_model,
                )
                logger.info("Using OpenAI API for remediation generation")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI: {e}")
                sys.exit(1)
        else:  # ollama
            try:
                self.llm = Ollama(
                    base_url=self.config.ollama_base_url,
                    model=self.config.ollama_model,
                    temperature=self.config.temperature,
                )
                logger.info(f"Using Ollama API with model {self.config.ollama_model}")
            except Exception as e:
                logger.error(f"Failed to initialize Ollama: {e}")
                sys.exit(1)
    
    def _setup_prompt_template(self):
        """Set up the prompt template for remediation generation with versioning support."""
        # Get template from prompt manager
        template_data = get_prompt_template('remediation_template', with_metadata=True)
        
        # Get template hash for versioning
        try:
            self.template_hash = get_template_hash('remediation_template')
            if self.template_hash:
                logger.info(f"Using template hash {self.template_hash} for cache versioning")
            else:
                logger.warning("Could not get template hash, cache versioning may not work properly")
        except Exception as e:
            logger.warning(f"Error getting template hash: {e}")
            self.template_hash = None
        
        # Load section templates
        self.section_templates = {}
        try:
            # Get section templates from prompt manager
            for section in ['description', 'risk', 'impact', 'examples', 'remediation']:
                template_key = f'section_templates.{section}'
                section_template = get_prompt_template(template_key)
                
                # Validate the template content
                if section_template is None:
                    logger.warning(f"Section template for '{section}' not found in prompt configuration")
                    continue
                    
                if not section_template.strip():
                    logger.warning(f"Section template for '{section}' is blank or empty")
                    continue
                    
                # Check if template has the required placeholders
                required_placeholders = ['{vulnerability_name}', '{severity}', '{endpoint}', '{evidence}']
                missing_placeholders = [p for p in required_placeholders if p not in section_template]
                
                if missing_placeholders:
                    logger.warning(f"Section template for '{section}' is missing required placeholders: {', '.join(missing_placeholders)}")
                    continue
                    
                # Template is valid, add it to the collection
                self.section_templates[section] = section_template
                logger.debug(f"Loaded section template for '{section}'")
            
            # Log summary of loaded templates
            if not self.section_templates:
                logger.warning("No section templates were loaded. Section generation will not be available.")
            else:
                loaded_sections = ', '.join(self.section_templates.keys())
                logger.info(f"Successfully loaded {len(self.section_templates)} section templates: {loaded_sections}")
                
        except Exception as e:
            logger.warning(f"Error loading section templates: {e}")
        
        if not template_data:
            logger.warning('Could not load remediation template from prompt manager, using default template')
            template_str = """
You are a cybersecurity expert specializing in API security. Your task is to provide detailed remediation steps for a vulnerability.

Vulnerability: {vulnerability}
Severity: {severity}
Endpoint: {endpoint}
Details: {details}
API Structure: {api_structure}

Based on the information above, provide comprehensive, actionable remediation steps to fix this vulnerability.
Include:
1. Root cause analysis
2. Step-by-step technical instructions for fixing the issue, tailored to the specific API structure
3. Code examples where applicable
4. Best practices to prevent similar issues in the future
5. References to relevant security standards or guidelines

Your response should be technical, precise, and directly applicable to the vulnerability described.

Remediation:
"""
        else:
            # If template_data is a string, use it directly
            # If it's a dictionary, extract the template field
            if isinstance(template_data, dict) and 'template' in template_data:
                template_str = template_data['template']
            else:
                template_str = template_data
                
            logger.info("Successfully loaded remediation template from prompt manager")

        self.prompt_template = PromptTemplate(
            input_variables=["vulnerability", "severity", "endpoint", "details", "api_structure"],
            template=template_str,
        )
    
    def _detect_api_structure(self, endpoint: str) -> str:
        """
        Detect the API structure based on the endpoint pattern.
        
        Args:
            endpoint: The API endpoint to analyze
            
        Returns:
            The detected API structure name
        """
        if not endpoint:
            return "standard"
        
        # Normalize the endpoint for consistent pattern matching
        normalized_endpoint = endpoint.strip().lower()
        if normalized_endpoint.startswith('/'):
            normalized_endpoint = normalized_endpoint[1:]
        
        # Check for Snorefox API structure (based on the memory about Snorefox API)
        if any(pattern in normalized_endpoint for pattern in [
            "auth/sign-up", "auth/sign-in", "auth/sign-out", 
            "users/me", "auth/check", "auth/refresh", "auth/"
        ]):
            return "snorefox"
        
        # Check for mobile API patterns (focus on mobile API endpoints as mentioned in memory)
        if "api/v1/mobile" in normalized_endpoint or "mobile" in normalized_endpoint or "app" in normalized_endpoint:
            return "mobile_api"
        
        # Check for standard RESTful API patterns
        if any(pattern in normalized_endpoint for pattern in [
            "api/users", "api/login", "api/register", "users", "register", "login",
            "api/auth", "api/v1/users", "api/v2/users", "api/v1", "api/v2"
        ]):
            return "standard_rest"
        
        # Check for JWT-related endpoints (based on memory about JWT vulnerabilities)
        if "jwt" in normalized_endpoint or "token" in normalized_endpoint or "auth" in normalized_endpoint:
            return "jwt_auth"
        
        # Check for GraphQL API pattern
        if "graphql" in normalized_endpoint or "gql" in normalized_endpoint:
            return "graphql"
        
        # Default to standard API structure
        return "standard"
    
    def _get_api_structure_description(self, structure_name: str) -> str:
        """
        Get a description of the API structure.
        
        Args:
            structure_name: Name of the API structure
            
        Returns:
            Description of the API structure
        """
        if structure_name == "snorefox":
            return (
                "This API follows the RESTful pattern with authentication endpoints under the `/auth` path. "
                "Registration endpoint is at `/auth/sign-up` instead of the more common `/users` or `/register`. "
                "Login endpoint is at `/auth/sign-in` instead of `/login`. "
                "User-specific endpoints are under `/users/me` with bearer token authentication. "
                "The API uses different field names than standard API conventions. "
                "Authentication is handled via JWT tokens with bearer authentication. "
                "This API structure requires special handling for vulnerability detection due to its non-standard naming conventions."
            )
        elif structure_name == "standard_rest":
            return (
                "This API follows a standard RESTful pattern with common endpoint naming conventions. "
                "User registration is typically at `/api/users` or `/api/register`. "
                "Authentication is typically at `/api/login` or `/api/auth`. "
                "Resources are organized in a hierarchical structure following RESTful principles. "
                "Standard JWT authentication mechanisms are likely used."
            )
        elif structure_name == "graphql":
            return (
                "This API follows a GraphQL pattern with a single endpoint that accepts query and mutation operations. "
                "Authentication is typically handled via HTTP headers rather than specific endpoints. "
                "Vulnerabilities in GraphQL APIs often relate to introspection, query depth, and authorization checks. "
                "JWT tokens may be used for authentication and are subject to similar vulnerabilities as in REST APIs."
            )
        elif structure_name == "mobile_api":
            return (
                "This API is designed for mobile applications with endpoints under the `/api/v1/mobile/` path. "
                "Mobile APIs often have different authentication mechanisms and may expose sensitive functionality. "
                "These APIs may have less stringent security controls compared to web-focused APIs. "
                "Mobile APIs are particularly susceptible to unrestricted account creation vulnerabilities and JWT-related issues. "
                "Rate limiting vulnerabilities may be present, allowing attackers to create accounts at high rates despite apparent protections."
            )
        elif structure_name == "jwt_auth":
            return (
                "This API uses JWT (JSON Web Token) based authentication. "
                "Common vulnerabilities include weak signing keys, 'none' algorithm acceptance, missing signature validation, "
                "and improper handling of token expiration. JWT tokens should be carefully validated on the server side "
                "to prevent authentication bypasses and unauthorized access to protected resources. "
                "Attackers may attempt to modify token payloads or exploit implementation weaknesses in the JWT validation process."
            )
        
        # Default description
        return "This API follows a standard pattern with common endpoint naming conventions. It may be vulnerable to common API security issues including JWT vulnerabilities, unrestricted account creation, and broken authentication mechanisms."
    
    def _generate_cache_key(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate a unique cache key for a vulnerability with versioning support.
        
        Args:
            vulnerability: Vulnerability data as dictionary
            
        Returns:
            Unique cache key as a string
        """
        # Create a string with key vulnerability attributes for hashing
        cache_input = f"{vulnerability.get('vulnerability', '')}-{vulnerability.get('endpoint', '')}-{vulnerability.get('details', '')}"
        
        # Use the template hash stored in the class instance for versioning support
        template_hash = getattr(self, 'template_hash', None) or "default"
        
        # Include LLM model information in the cache key
        model_info = ""
        if self.config.llm_provider == "openai":
            model_info = f"openai-{self.config.openai_model}"
        else:
            model_info = f"ollama-{self.config.ollama_model}"
        
        # Generate MD5 hash of the input string with template version and model info
        versioned_input = f"{cache_input}-template:{template_hash}-model:{model_info}"
        cache_key = hashlib.md5(versioned_input.encode()).hexdigest()
        
        # Add prefix for Redis key namespace
        return f"{self.config.redis_key_prefix}{cache_key}"
    
    def _get_cached_remediation(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached remediation from Redis if available with metadata.
        
        Args:
            cache_key: Cache key for the remediation
            
        Returns:
            Dictionary with remediation text and metadata or None if not found
        """
        if not self.redis_client:
            return None
            
        try:
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                try:
                    # Try to parse as JSON first (for newer cache entries with metadata)
                    try:
                        parsed_data = json.loads(cached_data)
                        if isinstance(parsed_data, dict) and "remediation" in parsed_data:
                            logger.info(f"Cache hit for {cache_key} (with metadata)")
                            
                            # Log metadata if available
                            if "_metadata" in parsed_data:
                                metadata = parsed_data["_metadata"]
                                logger.debug(f"Cache metadata: template_version={metadata.get('template_version')}, model={metadata.get('model')}")
                            
                            return parsed_data
                    except json.JSONDecodeError:
                        # Legacy format - just a string
                        logger.info(f"Cache hit for {cache_key} (legacy format)")
                        return {"remediation": cached_data}
                except Exception as e:
                    logger.warning(f"Error parsing cached data for {cache_key}: {e}")
                    # Attempt to delete corrupted cache entry
                    try:
                        self.redis_client.delete(cache_key)
                        logger.info(f"Deleted corrupted cache entry for {cache_key}")
                    except Exception:
                        pass
                    return None
            else:
                logger.info(f"Cache miss for {cache_key}")
                return None
        except Exception as e:
            logger.warning(f"Error retrieving from cache: {e}")
            return None
    
    def _cache_remediation(self, cache_key: str, remediation: str) -> bool:
        """
        Cache remediation in Redis with metadata.
        
        Args:
            cache_key: Cache key for the remediation
            remediation: Remediation text to cache
            
        Returns:
            True if caching was successful, False otherwise
        """
        if not self.redis_client:
            return False
        
        # Get template version information
        template_version = "unknown"
        template_hash = "unknown"
        try:
            from utils.prompt_manager import get_prompt_template
            template_data = get_prompt_template('remediation_template', with_metadata=True)
            if isinstance(template_data, dict):
                template_version = template_data.get('version', "1.0.0")
                template_hash = template_data.get('template_hash', 'unknown')
        except Exception as e:
            logger.warning(f"Failed to get template version: {e}")
        
        # Create cache data with metadata
        cache_data = {
            "remediation": remediation,
            "_metadata": {
                "created_at": datetime.datetime.now().isoformat(),
                "template_version": template_version,
                "template_hash": template_hash,
                "model": f"{self.config.llm_provider}:{self.config.openai_model if self.config.llm_provider == 'openai' else self.config.ollama_model}",
                "ttl": self.config.redis_cache_ttl,
                "section_templates_used": hasattr(self, 'section_templates') and bool(self.section_templates),
                "section_templates_count": len(self.section_templates) if hasattr(self, 'section_templates') else 0
            }
        }
            
        try:
            # Use pipeline for atomic operation
            with self.redis_client.pipeline() as pipe:
                pipe.setex(
                    cache_key,
                    self.config.redis_cache_ttl,
                    json.dumps(cache_data)
                )
                # Also store the key in a set for easier management
                pipe.sadd(f"{self.config.redis_key_prefix}all_keys", cache_key)
                # Store in template-specific set for version-based invalidation
                pipe.sadd(f"{self.config.redis_key_prefix}template:{template_hash}", cache_key)
                pipe.execute()
                
            logger.info(f"Cached remediation for {cache_key} with metadata")
            return True
        except Exception as e:
            logger.warning(f"Error caching remediation: {e}")
            return False
            
    def invalidate_cache_by_template(self, template_key: str) -> int:
        """
        Invalidate all cache entries for a specific template.
        
        Args:
            template_key: Template key to invalidate cache for
            
        Returns:
            Number of invalidated cache entries
        """
        if not self.redis_client:
            return 0
            
        try:
            # Get template hash
            template_hash = "unknown"
            try:
                from utils.prompt_manager import get_template_hash
                template_hash = get_template_hash(template_key) or "unknown"
            except Exception as e:
                logger.warning(f"Failed to get template hash for {template_key}: {e}")
                return 0
                
            # Get all keys for this template
            template_set_key = f"{self.config.redis_key_prefix}template:{template_hash}"
            keys = self.redis_client.smembers(template_set_key)
            
            if not keys:
                logger.info(f"No cache entries found for template {template_key} (hash: {template_hash})")
                return 0
                
            # Delete all keys and remove from sets
            count = 0
            with self.redis_client.pipeline() as pipe:
                for key in keys:
                    key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                    pipe.delete(key_str)
                    pipe.srem(f"{self.config.redis_key_prefix}all_keys", key_str)
                    count += 1
                    
                # Delete the template set itself
                pipe.delete(template_set_key)
                pipe.execute()
                
            logger.info(f"Invalidated {count} cache entries for template {template_key} (hash: {template_hash})")
            return count
            
        except Exception as e:
            logger.error(f"Error invalidating cache by template {template_key}: {e}")
            return 0
            
    def invalidate_all_cache(self) -> int:
        """
        Invalidate all cache entries.
        
        Returns:
            Number of invalidated cache entries
        """
        if not self.redis_client:
            return 0
            
        try:
            # Get all keys
            all_keys_set = f"{self.config.redis_key_prefix}all_keys"
            keys = self.redis_client.smembers(all_keys_set)
            
            if not keys:
                logger.info("No cache entries found")
                return 0
                
            # Delete all keys
            count = 0
            with self.redis_client.pipeline() as pipe:
                for key in keys:
                    key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                    pipe.delete(key_str)
                    count += 1
                    
                # Delete all template sets
                template_set_pattern = f"{self.config.redis_key_prefix}template:*"
                for key in self.redis_client.keys(template_set_pattern):
                    key_str = key.decode('utf-8') if isinstance(key, bytes) else key
                    pipe.delete(key_str)
                    
                # Delete the all_keys set itself
                pipe.delete(all_keys_set)
                pipe.execute()
                
            logger.info(f"Invalidated {count} cache entries")
            return count
            
        except Exception as e:
            logger.error(f"Error invalidating all cache: {e}")
            return 0
    
    def _log_progress(self) -> None:
        """
        Log progress of processing vulnerabilities.
        """
        if self.total_count == 0:
            return
            
        elapsed_time = time.time() - self.start_time
        processed_percent = (self.processed_count / self.total_count) * 100
        
        # Calculate estimated remaining time
        if self.processed_count > 0:
            avg_time_per_item = elapsed_time / self.processed_count
            remaining_items = self.total_count - self.processed_count
            estimated_remaining = avg_time_per_item * remaining_items
        else:
            estimated_remaining = 0
            
        logger.info(
            f"Progress: {self.processed_count}/{self.total_count} ({processed_percent:.1f}%) - "
            f"Elapsed: {elapsed_time:.1f}s, Estimated remaining: {estimated_remaining:.1f}s"
        )
    
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate remediation steps for a vulnerability using LLM with caching.
        
        Args:
            vulnerability: Vulnerability data as dictionary
            
        Returns:
            Remediation steps as a string
        """
        # Check if vulnerability has required fields
        required_fields = ["vulnerability", "severity", "endpoint", "details"]
        if not all(field in vulnerability for field in required_fields):
            logger.warning(f"Skipping vulnerability with missing required fields: {vulnerability.get('vulnerability', 'Unknown')}")
            return ""
        
        # Check if vulnerability already has substantial remediation
        existing_remediation = vulnerability.get("remediation", "")
        if existing_remediation and len(existing_remediation) > 100:
            logger.info(f"Skipping {vulnerability['vulnerability']} - already has substantial remediation")
            return existing_remediation
        
        # Generate cache key
        cache_key = self._generate_cache_key(vulnerability)
        
        # Check cache first
        cached_data = self._get_cached_remediation(cache_key)
        if cached_data:
            # Extract remediation text from the cached data
            if isinstance(cached_data, dict) and "remediation" in cached_data:
                # New format with metadata
                return cached_data["remediation"]
            elif isinstance(cached_data, str):
                # Legacy format (just the string)
                return cached_data
            else:
                logger.warning(f"Unexpected cache data format for {cache_key}")
                return ""
        
        # Detect API structure
        endpoint = vulnerability.get("endpoint", "")
        api_structure = self._detect_api_structure(endpoint)
        api_structure_description = self._get_api_structure_description(api_structure)
        
        # Prepare prompt inputs
        prompt_inputs = {
            "vulnerability": vulnerability.get("vulnerability", ""),
            "severity": vulnerability.get("severity", ""),
            "endpoint": endpoint,
            "details": vulnerability.get("details", ""),
            "api_structure": api_structure_description
        }
        
        # Generate remediation using LLM with retry logic
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Generating remediation for {vulnerability['vulnerability']} (attempt {attempt}/{max_retries})")
                
                # Format the prompt and generate response
                prompt = self.prompt_template.format(**prompt_inputs)
                response = self.llm.invoke(prompt)
                
                # Extract the response text
                remediation_text = response.content if hasattr(response, 'content') else str(response)
                
                # Clean up the response text
                remediation_text = remediation_text.strip()
                
                # Parse the response to extract sections
                parsed_response = self._parse_remediation_response(remediation_text, vulnerability)
                
                # If the parsed response is valid, use it
                if parsed_response:
                    remediation_text = parsed_response
                # If the remediation text is too short or empty, try using section templates
                elif len(remediation_text) < 50 and hasattr(self, 'section_templates') and self.section_templates:
                    logger.info(f"Main remediation template produced insufficient results, trying section template")
                    section_remediation = self._generate_remediation_from_section_template(vulnerability)
                    if section_remediation and len(section_remediation) > len(remediation_text):
                        remediation_text = section_remediation
                
                # Cache the remediation
                self._cache_remediation(cache_key, remediation_text)
                
                return remediation_text
                
            except Exception as e:
                logger.error(f"Error generating remediation (attempt {attempt}/{max_retries}): {e}")
                if attempt == max_retries:
                    return "Error generating remediation steps. Please try again later or consult security documentation for this vulnerability type."
                time.sleep(2)  # Wait before retrying
    
    def _parse_remediation_response(self, response_text: str, vulnerability: Dict[str, Any]) -> str:
        """
        Parse the LLM response to extract sections and generate missing sections using templates.
        
        Args:
            response_text: Raw response text from the LLM
            vulnerability: Vulnerability data as dictionary
            
        Returns:
            Parsed and enhanced response text with all sections
        """
        if not response_text or not hasattr(self, 'section_templates') or not self.section_templates:
            return response_text
            
        try:
            # Define expected sections in a remediation response
            expected_sections = {
                'root cause': None,
                'technical instructions': None,
                'code examples': None,
                'best practices': None,
                'references': None
            }
            
            # Extract sections from the response text
            current_section = None
            sections = {}
            lines = response_text.split('\n')
            section_content = []
            
            for line in lines:
                line_lower = line.lower()
                
                # Check if this line is a section header
                new_section = None
                for section in expected_sections.keys():
                    if section in line_lower and (line_lower.startswith(section) or 
                                                 line_lower.startswith(f"# {section}") or 
                                                 line_lower.startswith(f"## {section}") or
                                                 line_lower.startswith(f"### {section}") or
                                                 line_lower.startswith(f"* {section}") or
                                                 line_lower.startswith(f"- {section}") or
                                                 line_lower.startswith(f"1. {section}") or
                                                 ':' in line_lower and line_lower.split(':')[0].strip().endswith(section)):
                        new_section = section
                        break
                
                # If we found a new section, save the current section content and start a new one
                if new_section:
                    if current_section and section_content:
                        sections[current_section] = '\n'.join(section_content).strip()
                    current_section = new_section
                    section_content = [line]
                elif current_section:
                    section_content.append(line)
                    
            # Save the last section
            if current_section and section_content:
                sections[current_section] = '\n'.join(section_content).strip()
            
            # Check if we have any missing sections that need to be generated
            missing_sections = [section for section in expected_sections.keys() if section not in sections]
            
            if not missing_sections:
                # If all sections are present, return the original response
                return response_text
                
            # Generate missing sections using templates
            logger.info(f"Generating missing sections: {', '.join(missing_sections)}")
            for section in missing_sections:
                section_content = self._generate_section_content(section, vulnerability)
                if section_content:
                    sections[section] = section_content
            
            # Reconstruct the response with all sections
            enhanced_response = ["# Remediation Steps\n"]
            for section in expected_sections.keys():
                if section in sections:
                    enhanced_response.append(f"## {section.title()}\n{sections[section]}\n")
            
            return '\n'.join(enhanced_response)
            
        except Exception as e:
            logger.error(f"Error parsing remediation response: {e}")
            return response_text
    
    def _generate_section_content(self, section: str, vulnerability: Dict[str, Any]) -> str:
        """
        Generate content for a specific section using the appropriate template.
        
        Args:
            section: Section name to generate content for
            vulnerability: Vulnerability data as dictionary
            
        Returns:
            Generated section content or empty string if failed
        """
        # Map section names to template keys
        section_template_map = {
            'root cause': 'description',
            'technical instructions': 'remediation',
            'code examples': 'remediation',
            'best practices': 'remediation',
            'references': 'remediation'
        }
        
        template_key = section_template_map.get(section)
        if not template_key or template_key not in self.section_templates:
            return ""
            
        try:
            # Get the section template
            template = self.section_templates[template_key]
            
            # Extract evidence from details if available
            evidence = vulnerability.get("details", "")
            
            # Prepare template inputs
            template_inputs = {
                "vulnerability_name": vulnerability.get("vulnerability", ""),
                "severity": vulnerability.get("severity", ""),
                "endpoint": vulnerability.get("endpoint", ""),
                "evidence": evidence
            }
            
            # Add section-specific instructions to the template
            if section == 'root cause':
                template = f"For the vulnerability: {{vulnerability_name}}, provide a detailed root cause analysis. {template}"
            elif section == 'technical instructions':
                template = f"For the vulnerability: {{vulnerability_name}}, provide step-by-step technical instructions to fix the issue. {template}"
            elif section == 'code examples':
                template = f"For the vulnerability: {{vulnerability_name}}, provide code examples that demonstrate how to fix the issue. {template}"
            elif section == 'best practices':
                template = f"For the vulnerability: {{vulnerability_name}}, provide best practices to prevent similar issues in the future. {template}"
            elif section == 'references':
                template = f"For the vulnerability: {{vulnerability_name}}, provide references to relevant security standards or guidelines. {template}"
            
            # Format the prompt and generate response
            prompt = template.format(**template_inputs)
            response = self.llm.invoke(prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # Clean up the response text
            section_content = response_text.strip()
            
            logger.info(f"Generated content for section '{section}'")
            return section_content
            
        except Exception as e:
            logger.error(f"Error generating content for section '{section}': {e}")
            return ""
    
    def _generate_remediation_from_section_template(self, vulnerability: Dict[str, Any]) -> str:
        """
        Generate remediation using the section template when the main template fails or produces insufficient results.
        
        Args:
            vulnerability: Vulnerability data as dictionary
            
        Returns:
            Remediation text generated from section template or empty string if failed
        """
        if 'remediation' not in self.section_templates:
            logger.warning("No remediation section template available")
            return ""
            
        try:
            # Get the remediation section template
            template = self.section_templates['remediation']
            
            # Extract evidence from details if available
            evidence = vulnerability.get("details", "")
            
            # Prepare template inputs
            template_inputs = {
                "vulnerability_name": vulnerability.get("vulnerability", ""),
                "severity": vulnerability.get("severity", ""),
                "endpoint": vulnerability.get("endpoint", ""),
                "evidence": evidence
            }
            
            # Format the prompt and generate response
            prompt = template.format(**template_inputs)
            response = self.llm.invoke(prompt)
            response_text = response.content if hasattr(response, 'content') else str(response)
            
            # Clean up the response text
            remediation_text = response_text.strip()
            
            logger.info(f"Generated remediation using section template")
            return remediation_text
            
        except Exception as e:
            logger.error(f"Error generating remediation using section template: {e}")
            return ""
    
    def _process_finding(self, finding: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, bool]:
        """
        Process a single finding and generate remediation steps.
        
        Args:
            finding: The vulnerability finding to process
            
        Returns:
            Tuple of (updated finding, success flag, skipped flag)
        """
        try:
            # Generate remediation steps
            remediation = self.generate_remediation(finding)
            
            # Check if remediation was generated or skipped
            if not remediation:
                logger.info(f"Skipped {finding.get('vulnerability', 'Unknown')}")
                return finding, False, True
            
            # Update finding with remediation steps
            finding["remediation"] = remediation
            
            return finding, True, False
            
        except Exception as e:
            logger.error(f"Error processing finding: {e}")
            return finding, False, False
    
    def _process_batch(self, findings: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], bool, bool]]:
        """
        Process a batch of findings in parallel.
        
        Args:
            findings: List of findings to process
            
        Returns:
            List of processed findings with success and skipped flags
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            # Submit all tasks
            future_to_finding = {executor.submit(self._process_finding, finding): finding for finding in findings}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_finding):
                try:
                    processed_finding, success, skipped = future.result()
                    results.append((processed_finding, success, skipped))
                    
                    # Update statistics
                    self.processed_count += 1
                    if success:
                        self.success_count += 1
                    elif skipped:
                        self.skipped_count += 1
                    else:
                        self.error_count += 1
                        
                    # Log progress periodically
                    if self.processed_count % 5 == 0 or self.processed_count == self.total_count:
                        self._log_progress()
                        
                except Exception as e:
                    logger.error(f"Error processing batch item: {e}")
                    self.processed_count += 1
                    self.error_count += 1
            
        return results
    
    def _group_vulnerabilities_by_api_structure(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group vulnerabilities by their API structure for more consistent remediation generation.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dictionary mapping API structure names to lists of vulnerabilities
        """
        grouped = {}
        
        for finding in findings:
            endpoint = finding.get("endpoint", "")
            api_structure = self._detect_api_structure(endpoint)
            
            if api_structure not in grouped:
                grouped[api_structure] = []
                
            grouped[api_structure].append(finding)
            
        return grouped
    
    def process_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process scan results to generate remediation steps for vulnerabilities using batch processing.
        
        Args:
            scan_results: Scan results to process as dictionary
            
        Returns:
            Processed scan results with remediation steps
        """
        scan_id = scan_results.get("scan_id", "unknown")
        logger.info(f"Processing scan results for scan ID: {scan_id}")
        
        # Reset statistics and start timer
        self.processed_count = 0
        self.total_count = 0
        self.success_count = 0
        self.error_count = 0
        self.skipped_count = 0
        self.start_time = time.time()
        
        # Collect all findings for batch processing
        all_findings = []
        finding_map = {}  # Maps finding to its location in the scan_results
        
        for scanner_idx, scanner in enumerate(scan_results.get("scanners", [])):
            scanner_name = scanner.get("name", "unknown")
            findings = scanner.get("findings", [])
            
            if not findings:
                logger.info(f"No findings for scanner: {scanner_name}")
                continue
                
            logger.info(f"Collecting findings from scanner: {scanner_name}")
            
            for finding_idx, finding in enumerate(findings):
                all_findings.append(finding)
                finding_map[id(finding)] = (scanner_idx, finding_idx)
        
        self.total_count = len(all_findings)
        logger.info(f"Found {self.total_count} total vulnerabilities to process")
        
        if self.total_count == 0:
            logger.info("No vulnerabilities to process")
            return scan_results
        
        # Group findings by API structure for more consistent remediation generation
        grouped_findings = self._group_vulnerabilities_by_api_structure(all_findings)
        
        # Process each group separately
        for api_structure, findings_group in grouped_findings.items():
            group_size = len(findings_group)
            logger.info(f"Processing {group_size} vulnerabilities for API structure: {api_structure}")
            
            # Process findings in batches
            batch_size = min(self.config.batch_size, group_size)
            
            for i in range(0, group_size, batch_size):
                batch = findings_group[i:i+batch_size]
                logger.info(f"Processing batch {i//batch_size + 1}/{(group_size + batch_size - 1)//batch_size} for {api_structure} API structure")
                
                # Process the batch
                processed_batch = self._process_batch(batch)
                
                # Update the original findings in scan_results
                for processed_finding, _, _ in processed_batch:
                    if id(processed_finding) in finding_map:
                        scanner_idx, finding_idx = finding_map[id(processed_finding)]
                        scan_results["scanners"][scanner_idx]["findings"][finding_idx] = processed_finding
        
        # Final progress report
        elapsed_time = time.time() - self.start_time
        logger.info(f"Generated remediation for {self.success_count} out of {self.total_count} vulnerabilities in {elapsed_time:.2f} seconds")
        logger.info(f"Success: {self.success_count}, Errors: {self.error_count}, Skipped: {self.skipped_count}")
        
        return scan_results
