#!/usr/bin/env python3
"""
LLM Description Enhancement Middleware

This module provides a middleware for enhancing vulnerability descriptions
using LLM APIs (OpenAI or Ollama) with Redis caching.
"""

import json
import logging
import os
import sys
import time
import hashlib
import re
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
logger = logging.getLogger("llm_description")

class DescriptionConfig(BaseModel):
    """Configuration for the LLM description enhancement middleware."""
    
    # Redis configuration
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_db: int = Field(default=0, description="Redis database")
    redis_password: str = Field(default="", description="Redis password")
    redis_cache_ttl: int = Field(
        default=86400 * 7, description="Redis cache TTL in seconds (default: 7 days)"
    )
    redis_key_prefix: str = Field(
        default="llm_desc:", description="Redis key prefix for namespacing"
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


class LLMDescriptionMiddleware:
    """
    Middleware that enhances vulnerability descriptions using LLM APIs
    with Redis caching.
    """
    
    def __init__(self, config: DescriptionConfig):
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
            if not self.config.openai_api_key:
                logger.error("OpenAI API key is required for OpenAI provider")
                sys.exit(1)
                
            self.llm = ChatOpenAI(
                model=self.config.openai_model,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                api_key=self.config.openai_api_key,
            )
            logger.info(f"Using OpenAI API for description enhancement")
        elif self.config.llm_provider == "ollama":
            self.llm = Ollama(
                model=self.config.ollama_model,
                temperature=self.config.temperature,
                base_url=self.config.ollama_base_url,
            )
            logger.info(f"Using Ollama API for description enhancement")
        else:
            logger.error(f"Unsupported LLM provider: {self.config.llm_provider}")
            sys.exit(1)
    
    def _setup_prompt_template(self) -> None:
        """Set up the prompt template for description enhancement."""
        # Get template from prompt manager
        template_data = get_prompt_template('description_template')
        
        # Load section templates
        self.section_templates = {}
        try:
            # Get section templates from prompt manager
            for section in ['description', 'risk', 'impact', 'examples', 'remediation']:
                template_key = f'section_templates.{section}'
                section_template = get_prompt_template(template_key)
                if section_template:
                    self.section_templates[section] = section_template
                    logger.debug(f"Loaded section template for {section}")
                else:
                    logger.warning(f"Could not load section template for {section}")
            
            if not self.section_templates:
                logger.warning("No section templates loaded")
        except Exception as e:
            logger.warning(f"Error loading section templates: {e}")
        
        if not template_data:
            logger.warning('Could not load description template from prompt manager, using default template')
            template_str = """
            You are a cybersecurity expert tasked with enhancing vulnerability descriptions with contextual information.
            
            Vulnerability: {vulnerability}
            Severity: {severity}
            Endpoint: {endpoint}
            Details: {details}
            API Structure: {api_structure}
            
            Based on the information above, provide a comprehensive analysis of this vulnerability that includes:
            
            1. RISK ASSESSMENT: Explain the specific security risk this vulnerability represents. Include technical details about how the vulnerability could be exploited and what security principles it violates. If this is related to rate limiting or unrestricted account creation, explain how attackers might bypass rate limiting mechanisms and at what rates accounts could potentially be created.
            
            2. IMPACT ANALYSIS: Describe the potential business and technical impact if this vulnerability were successfully exploited. Consider data confidentiality, integrity, availability, and any regulatory implications. For authentication-related vulnerabilities, discuss how they might affect different API structures including non-standard ones like Snorefox or mobile API endpoints.
            
            3. REAL-WORLD EXAMPLES: Provide 2-3 specific, documented examples of similar vulnerabilities being exploited in real-world scenarios. Include organization names, approximate dates, and outcomes when available. If possible, include examples that are relevant to the specific API structure identified.
            
            Format your response with clear section headers and concise, technical explanations. Focus on factual information relevant to this specific vulnerability type and API structure. If the vulnerability is related to JWT issues, unrestricted account creation, or broken authentication, be particularly detailed about the exploitation techniques and preventative measures.
            
            Response:
            """
        else:
            # If template_data is a string, use it directly
            # If it's a dictionary, extract the template field
            if isinstance(template_data, dict) and 'template' in template_data:
                template_str = template_data['template']
            else:
                template_str = template_data
            
            logger.info("Successfully loaded description template from prompt manager")
        
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
        
        # Get template hash for versioning support
        template_hash = "default"
        try:
            from utils.prompt_manager import get_template_hash
            template_hash = get_template_hash('description_template') or "default"
        except Exception as e:
            logger.warning(f"Failed to get template hash: {e}")
        
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
    
    def _get_cached_description(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """
        Get cached description from Redis if available with metadata.
        
        Args:
            cache_key: Cache key for the description
            
        Returns:
            Cached description with metadata or None if not found
        """
        if not self.redis_client:
            return None
            
        try:
            cached_data = self.redis_client.get(cache_key)
            if cached_data:
                try:
                    parsed_data = json.loads(cached_data)
                    
                    # Check if the cached data has the expected structure
                    if not isinstance(parsed_data, dict):
                        logger.warning(f"Invalid cache data format for {cache_key}")
                        return None
                        
                    # Check for required description sections
                    required_sections = ["risk_assessment", "impact_analysis", "real_world_examples"]
                    if not all(section in parsed_data for section in required_sections):
                        logger.warning(f"Incomplete cached data for {cache_key}, missing required sections")
                        return None
                        
                    logger.info(f"Cache hit for {cache_key} (created: {parsed_data.get('created_at', 'unknown')})")
                    
                    # Extract just the description data if metadata is present
                    if "_metadata" in parsed_data:
                        metadata = parsed_data["_metadata"]
                        logger.debug(f"Cache metadata: template_version={metadata.get('template_version')}, model={metadata.get('model')}")
                    
                    return parsed_data
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON in cache for {cache_key}: {e}")
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
    
    def _cache_description(self, cache_key: str, description_data: Dict[str, str]) -> bool:
        """
        Cache description in Redis with metadata.
        
        Args:
            cache_key: Cache key for the description
            description_data: Description data to cache
            
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
            template_data = get_prompt_template('description_template', with_metadata=True)
            if isinstance(template_data, dict):
                template_version = template_data.get('version', DEFAULT_VERSION)
                template_hash = template_data.get('template_hash', 'unknown')
        except Exception as e:
            logger.warning(f"Failed to get template version: {e}")
        
        # Add metadata to the cached data
        cache_data = description_data.copy()
        cache_data["_metadata"] = {
            "created_at": datetime.datetime.now().isoformat(),
            "template_version": template_version,
            "template_hash": template_hash,
            "model": f"{self.config.llm_provider}:{self.config.openai_model if self.config.llm_provider == 'openai' else self.config.ollama_model}",
            "ttl": self.config.redis_cache_ttl
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
            
            logger.info(f"Cached description for {cache_key} with metadata")
            return True
        except Exception as e:
            logger.warning(f"Error caching description: {e}")
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
    
    def generate_description(self, vulnerability: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate enhanced description for a vulnerability using LLM with caching.
        
        Args:
            vulnerability: Vulnerability data as dictionary
            
        Returns:
            Dictionary with risk assessment, impact analysis, and real-world examples
        """
        # Check if vulnerability has required fields
        required_fields = ["vulnerability", "severity", "endpoint", "details"]
        if not all(field in vulnerability for field in required_fields):
            logger.warning(f"Skipping vulnerability with missing required fields: {vulnerability.get('vulnerability', 'Unknown')}")
            return {
                "risk_assessment": "",
                "impact_analysis": "",
                "real_world_examples": ""
            }
        
        # Check if vulnerability already has substantial description
        existing_fields = [
            vulnerability.get("risk_assessment", ""),
            vulnerability.get("impact_analysis", ""),
            vulnerability.get("real_world_examples", "")
        ]
        if all(field and len(field) > 50 for field in existing_fields):
            logger.info(f"Skipping {vulnerability['vulnerability']} - already has substantial description")
            return {
                "risk_assessment": vulnerability.get("risk_assessment", ""),
                "impact_analysis": vulnerability.get("impact_analysis", ""),
                "real_world_examples": vulnerability.get("real_world_examples", "")
            }
        
        # Generate cache key
        cache_key = self._generate_cache_key(vulnerability)
        
        # Check cache first
        cached_description = self._get_cached_description(cache_key)
        if cached_description:
            return cached_description
        
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
        
        # Generate description using LLM with retry logic
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Generating description for {vulnerability['vulnerability']} (attempt {attempt}/{max_retries})")
                
                # Format the prompt and generate response
                prompt = self.prompt_template.format(**prompt_inputs)
                response = self.llm.invoke(prompt)
                
                # Parse the response to extract sections
                response_text = response.content if hasattr(response, 'content') else str(response)
                
                # Extract sections from the response and generate missing sections if needed
                sections = self._parse_response_sections(response_text, vulnerability)
                
                # Cache the description
                self._cache_description(cache_key, sections)
                
                return sections
                
            except Exception as e:
                logger.error(f"Error generating description (attempt {attempt}/{max_retries}): {e}")
                if attempt == max_retries:
                    return {
                        "risk_assessment": "Error generating risk assessment.",
                        "impact_analysis": "Error generating impact analysis.",
                        "real_world_examples": "Error retrieving real-world examples."
                    }
                time.sleep(2)  # Wait before retrying
    
    def _parse_response_sections(self, response_text: str, vulnerability: Dict[str, Any] = None) -> Dict[str, str]:
        """
        Parse the LLM response to extract the different sections.
        If sections are missing and section templates are available, generate those sections individually.
        
        Args:
            response_text: The full response from the LLM
            vulnerability: Optional vulnerability data to use for section template generation
            
        Returns:
            Dictionary with extracted sections
        """
        sections = {
            "risk_assessment": "",
            "impact_analysis": "",
            "real_world_examples": ""
        }
        
        # Extract Risk Assessment section
        risk_pattern = r"(?i)RISK ASSESSMENT:?\s*([\s\S]*?)(?=IMPACT ANALYSIS:|REAL-WORLD EXAMPLES:|$)"
        risk_match = re.search(risk_pattern, response_text)
        if risk_match:
            sections["risk_assessment"] = risk_match.group(1).strip()
        
        # Extract Impact Analysis section
        impact_pattern = r"(?i)IMPACT ANALYSIS:?\s*([\s\S]*?)(?=RISK ASSESSMENT:|REAL-WORLD EXAMPLES:|$)"
        impact_match = re.search(impact_pattern, response_text)
        if impact_match:
            sections["impact_analysis"] = impact_match.group(1).strip()
        
        # Extract Real-World Examples section
        examples_pattern = r"(?i)REAL-WORLD EXAMPLES:?\s*([\s\S]*?)(?=RISK ASSESSMENT:|IMPACT ANALYSIS:|$)"
        examples_match = re.search(examples_pattern, response_text)
        if examples_match:
            sections["real_world_examples"] = examples_match.group(1).strip()
        
        # If any sections are missing and we have section templates and vulnerability data,
        # try to generate those sections individually
        if vulnerability and hasattr(self, 'section_templates') and self.section_templates:
            self._generate_missing_sections(sections, vulnerability)
        
        return sections
        
    def _generate_missing_sections(self, sections: Dict[str, str], vulnerability: Dict[str, Any]) -> None:
        """
        Generate missing sections using individual section templates.
        
        Args:
            sections: Dictionary of current sections (will be modified in-place)
            vulnerability: Vulnerability data to use for section template generation
        """
        # Map our section keys to the template keys
        section_mapping = {
            "risk_assessment": "risk",
            "impact_analysis": "impact",
            "real_world_examples": "examples"
        }
        
        # Check which sections are missing
        missing_sections = [k for k, v in sections.items() if not v]
        if not missing_sections:
            return
            
        logger.info(f"Generating {len(missing_sections)} missing sections using templates")
        
        for section_key in missing_sections:
            template_key = section_mapping.get(section_key)
            if not template_key or template_key not in self.section_templates:
                continue
                
            try:
                # Prepare inputs for the template
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
                
                # Format the prompt and generate response
                prompt = template.format(**template_inputs)
                response = self.llm.invoke(prompt)
                response_text = response.content if hasattr(response, 'content') else str(response)
                
                # Update the section
                sections[section_key] = response_text.strip()
                logger.info(f"Generated {section_key} using template")
                
            except Exception as e:
                logger.error(f"Error generating {section_key} using template: {e}")
                # Keep the section empty if generation fails
    
    def _process_finding(self, finding: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, bool]:
        """
        Process a single finding and generate enhanced description.
        
        Args:
            finding: The vulnerability finding to process
            
        Returns:
            Tuple of (updated finding, success flag, skipped flag)
        """
        try:
            # Generate enhanced description
            description_data = self.generate_description(finding)
            
            # Check if description was generated or skipped
            if all(not value for value in description_data.values()):
                logger.info(f"Skipped {finding.get('vulnerability', 'Unknown')}")
                return finding, False, True
            
            # Update finding with enhanced description
            finding["risk_assessment"] = description_data["risk_assessment"]
            finding["impact_analysis"] = description_data["impact_analysis"]
            finding["real_world_examples"] = description_data["real_world_examples"]
            
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
        Group vulnerabilities by their API structure for more consistent description enhancement.
        
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
        Process scan results to enhance vulnerability descriptions using batch processing.
        
        Args:
            scan_results: Scan results to process as dictionary
            
        Returns:
            Processed scan results with enhanced descriptions
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
        
        # Group findings by API structure for more consistent description enhancement
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
        logger.info(f"Enhanced {self.success_count} out of {self.total_count} vulnerabilities in {elapsed_time:.2f} seconds")
        logger.info(f"Success: {self.success_count}, Errors: {self.error_count}, Skipped: {self.skipped_count}")
        
        return scan_results
