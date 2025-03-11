#!/usr/bin/env python3
"""
API Security Scanner - Master Orchestration Script

This script orchestrates the execution of individual scanner modules to detect
various API security vulnerabilities.
"""

import argparse
import asyncio
import importlib
import json
import logging
import os
import sys
import time
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Set, Tuple

import yaml
import requests
from jsonschema import validate

from core.logger import setup_logger, get_logger
from core.config import load_config, validate_config, update_config_with_openapi
from core.utils import format_results, save_results
from core.exceptions import ScannerConfigError, ScannerExecutionError
from core.openapi import load_openapi_spec, extract_server_urls, extract_endpoints


class ScannerOrchestrator:
    """Master orchestration class for managing scanner modules."""

    def __init__(self, config_path: str, url_override: str = None, swagger_path: str = None, run_dos_scanner: bool = False):
        """
        Initialize the scanner orchestrator.
        
        Args:
            config_path: Path to the YAML/JSON configuration file
            url_override: Optional URL to override the target base URL
            swagger_path: Optional path to OpenAPI/Swagger specification file
        """
        self.config_path = config_path
        self.config = None
        self.scanners = []
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.run_dos_scanner = run_dos_scanner
        self.url_override = url_override
        self.swagger_path = swagger_path
        self.openapi_spec = None
        self.openapi_endpoints = []
        self.logger = get_logger("orchestrator")

    def load_configuration(self) -> None:
        """Load and validate the scanner configuration."""
        try:
            self.logger.info(f"Loading configuration from {self.config_path}")
            self.config = load_config(self.config_path)
            
            # Process OpenAPI specification if provided
            if self.swagger_path:
                self._load_openapi_spec()
                
            # Apply URL override if provided
            if self.url_override:
                self._apply_url_override()
                
            validate_config(self.config)
            self.logger.info("Configuration loaded and validated successfully")
        except Exception as e:
            self.logger.fatal(f"Failed to load configuration: {str(e)}")
            raise ScannerConfigError(f"Configuration error: {str(e)}")
            
    def _load_openapi_spec(self) -> None:
        """Load and process OpenAPI specification."""
        try:
            self.logger.info(f"Loading OpenAPI specification from {self.swagger_path}")
            
            # Check if file exists
            if not os.path.exists(self.swagger_path):
                raise FileNotFoundError(f"OpenAPI specification file not found: {self.swagger_path}")
            
            # Load and validate OpenAPI specification
            self.openapi_spec = load_openapi_spec(self.swagger_path)
            
            # Extract server URLs from OpenAPI spec
            server_urls = extract_server_urls(self.openapi_spec)
            
            # Extract endpoints from OpenAPI spec
            self.openapi_endpoints = extract_endpoints(self.openapi_spec)
            
            # Update configuration with OpenAPI data
            update_config_with_openapi(self.config, self.openapi_spec, server_urls, self.openapi_endpoints)
            
            self.logger.info(f"Successfully loaded OpenAPI specification with {len(self.openapi_endpoints)} endpoints")
            
            # Log the extracted endpoints for debugging
            if self.logger.isEnabledFor(logging.DEBUG):
                for endpoint in self.openapi_endpoints:
                    self.logger.debug(f"Extracted endpoint: {endpoint['method']} {endpoint['path']} - {endpoint.get('operation_id', 'No operation ID')}")
        except FileNotFoundError as e:
            self.logger.error(f"{str(e)}")
            raise ScannerConfigError(f"OpenAPI specification error: {str(e)}")
        except Exception as e:
            self.logger.error(f"Failed to load OpenAPI specification: {str(e)}")
            raise ScannerConfigError(f"OpenAPI specification error: {str(e)}")
    
    def _apply_url_override(self) -> None:
        """Apply URL override to the configuration."""
        if not self.url_override:
            return
        
        self.logger.info(f"Applying URL override: {self.url_override}")
        
        # Validate URL format
        try:
            parsed_url = urllib.parse.urlparse(self.url_override)
            if not all([parsed_url.scheme, parsed_url.netloc]):
                raise ValueError("URL must include scheme and host")
        except Exception as e:
            self.logger.error(f"Invalid URL format: {str(e)}")
            raise ScannerConfigError(f"Invalid URL format: {str(e)}")
        
        # Update target base_url in configuration
        if "target" not in self.config:
            self.config["target"] = {}
        
        self.config["target"]["base_url"] = self.url_override
        self.config["target"]["url_source"] = "override"
        
        self.logger.info(f"URL override applied successfully")

    def discover_scanners(self) -> None:
        """Discover and load scanner modules based on configuration."""
        self.logger.info("Discovering scanner modules")
        
        for scanner_config in self.config.get("scanners", []):
            scanner_name = scanner_config.get("name")
            if not scanner_name:
                self.logger.warn("Skipping scanner with missing name")
                continue
                
            if not scanner_config.get("enabled", True):
                self.logger.info(f"Scanner '{scanner_name}' is disabled, skipping")
                continue
                
            # Handle RegexDOS scanner if --dos flag is set to false
            if scanner_name == "regex_dos" and not self.run_dos_scanner:
                self.logger.info(f"RegexDOS scanner is disabled via --dos flag, skipping execution")
                # Add a placeholder result for RegexDOS scanner to maintain consistent reporting
                self.results[scanner_name] = {
                    "name": scanner_name,
                    "status": "skipped",
                    "findings": [
                        {
                            "vulnerability": "RegexDOS Scanner Skipped",
                            "severity": "INFO",
                            "endpoint": "N/A",
                            "details": "The RegexDOS scanner was skipped due to the --dos flag being set to false.",
                            "timestamp": time.time(),
                            "evidence": None,
                            "remediation": "To run the RegexDOS scanner, use the --dos true flag."
                        }
                    ],
                    "start_time": time.time(),
                    "end_time": time.time(),
                    "duration": 0
                }
                continue
                
            try:
                # Import the scanner module dynamically
                module_path = f"scanners.{scanner_name}"
                self.logger.debug(f"Attempting to import scanner module: {module_path}")
                scanner_module = importlib.import_module(module_path)
                self.logger.debug(f"Successfully imported module: {module_path}")
                
                scanner_class = getattr(scanner_module, "Scanner")
                self.logger.debug(f"Found Scanner class in module: {module_path}")
                
                # Create scanner instance with its configuration
                scanner_instance = scanner_class(
                    target=self.config.get("target", {}),
                    config=scanner_config.get("config", {})
                )
                self.logger.debug(f"Successfully instantiated scanner: {scanner_name}")
                
                self.scanners.append({
                    "name": scanner_name,
                    "instance": scanner_instance,
                    "concurrent": scanner_config.get("concurrent", False)
                })
                
                self.logger.info(f"Loaded scanner module: {scanner_name}")
            except ImportError as e:
                self.logger.error(f"Failed to import scanner module '{scanner_name}': {str(e)}")
            except AttributeError as e:
                self.logger.error(f"Failed to get Scanner class from '{scanner_name}': {str(e)}")
            except Exception as e:
                self.logger.error(f"Unexpected error loading scanner '{scanner_name}': {str(e)}")

    def run_scanner(self, scanner: Dict) -> Dict:
        """
        Run an individual scanner module.
        
        Args:
            scanner: Scanner configuration and instance
            
        Returns:
            Dict containing scanner results
        """
        scanner_name = scanner["name"]
        scanner_instance = scanner["instance"]
        
        self.logger.info(f"Starting scanner: {scanner_name}")
        start_time = time.time()
        
        try:
            results = scanner_instance.run()
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"Completed scanner '{scanner_name}' in {duration:.2f} seconds")
            
            return {
                "name": scanner_name,
                "success": True,
                "duration": duration,
                "findings": results,
                "start_time": datetime.fromtimestamp(start_time).isoformat(),
                "end_time": datetime.fromtimestamp(end_time).isoformat()
            }
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.error(f"Scanner '{scanner_name}' failed: {str(e)}")
            
            return {
                "name": scanner_name,
                "success": False,
                "duration": duration,
                "error": str(e),
                "start_time": datetime.fromtimestamp(start_time).isoformat(),
                "end_time": datetime.fromtimestamp(end_time).isoformat()
            }

    async def run_scanner_async(self, scanner: Dict) -> Dict:
        """
        Run a scanner asynchronously.
        
        Args:
            scanner: Scanner configuration and instance
            
        Returns:
            Dict containing scanner results
        """
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(executor, self.run_scanner, scanner)

    async def run_scanners_concurrently(self, concurrent_scanners: List[Dict]) -> List[Dict]:
        """
        Run multiple scanners concurrently.
        
        Args:
            concurrent_scanners: List of scanners to run concurrently
            
        Returns:
            List of scanner results
        """
        self.logger.info(f"Running {len(concurrent_scanners)} scanners concurrently")
        tasks = [self.run_scanner_async(scanner) for scanner in concurrent_scanners]
        return await asyncio.gather(*tasks)

    def run(self) -> Dict:
        """
        Run the complete scanning process.
        
        Returns:
            Dict containing all scan results
        """
        self.start_time = time.time()
        self.logger.info("Starting API security scan")
        
        try:
            self.load_configuration()
            self.discover_scanners()
            
            if not self.scanners:
                self.logger.warn("No enabled scanners found in configuration")
                return {"error": "No enabled scanners found"}
            
            # Separate RegexDOS scanner from other scanners
            regex_dos_scanner = None
            regular_scanners = []
            
            for scanner in self.scanners:
                if scanner["name"] == "regex_dos":
                    regex_dos_scanner = scanner
                    self.logger.info("RegexDOS scanner will be run separately after all other scanners")
                else:
                    regular_scanners.append(scanner)
            
            # Group regular scanners by concurrency
            sequential_scanners = []
            concurrent_scanners = []
            
            for scanner in regular_scanners:
                if scanner["concurrent"]:
                    concurrent_scanners.append(scanner)
                else:
                    sequential_scanners.append(scanner)
            
            # Run sequential scanners
            sequential_results = []
            for scanner in sequential_scanners:
                result = self.run_scanner(scanner)
                sequential_results.append(result)
            
            # Run concurrent scanners
            concurrent_results = []
            if concurrent_scanners:
                # Use asyncio.run() for Python 3.7+ to avoid deprecation warning
                async def run_concurrent():
                    return await self.run_scanners_concurrently(concurrent_scanners)
                
                concurrent_results = asyncio.run(run_concurrent())
            
            # Combine results from regular scanners
            all_results = sequential_results + concurrent_results
            
            # Run RegexDOS scanner last, only if it exists and is enabled
            regex_dos_result = []
            if regex_dos_scanner:
                self.logger.info("All regular scanners completed. Running RegexDOS scanner...")
                try:
                    result = self.run_scanner(regex_dos_scanner)
                    regex_dos_result.append(result)
                    self.logger.info("RegexDOS scanner completed successfully")
                except Exception as e:
                    self.logger.error(f"RegexDOS scanner failed: {str(e)}")
                    # Even if RegexDOS scanner fails, we still want to include the results from other scanners
                    regex_dos_result.append({
                        "name": "regex_dos",
                        "success": False,
                        "duration": 0,
                        "error": str(e),
                        "start_time": datetime.now().isoformat(),
                        "end_time": datetime.now().isoformat()
                    })
            elif not self.run_dos_scanner:
                # Add a placeholder result for RegexDOS scanner when it's skipped due to --dos flag
                self.logger.info("RegexDOS scanner was skipped due to --dos flag set to false")
                regex_dos_result.append({
                    "name": "regex_dos",
                    "success": True,  # Mark as success to avoid counting as failed scanner
                    "duration": 0,
                    "findings": [
                        {
                            "vulnerability": "RegexDOS Scanner Skipped",
                            "severity": "INFO",
                            "endpoint": "N/A",
                            "details": "The RegexDOS scanner was skipped due to the --dos flag being set to false.",
                            "remediation": "To run the RegexDOS scanner, use the --dos true flag."
                        }
                    ],
                    "start_time": datetime.now().isoformat(),
                    "end_time": datetime.now().isoformat()
                })
            
            # Add RegexDOS results to all results
            all_results.extend(regex_dos_result)
            
            # Process and format results
            self.results = {
                "scan_id": datetime.now().strftime("%Y%m%d%H%M%S"),
                "target": self.config.get("target", {}).get("base_url", "Unknown"),
                "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                "end_time": datetime.fromtimestamp(time.time()).isoformat(),
                "duration": time.time() - self.start_time,
                "scanners": all_results,
                "metadata": {
                    "config_file": self.config_path,
                    "swagger_file": self.swagger_path,
                    "openapi": {
                        "spec_path": self.swagger_path,
                        "endpoint_count": len(self.openapi_endpoints) if hasattr(self, 'openapi_endpoints') and self.openapi_endpoints else 0,
                        "source": self.config.get("target", {}).get("openapi_source", "none")
                    } if self.swagger_path else None
                },
                "summary": {
                    "total_scanners": len(all_results),
                    "successful_scanners": sum(1 for r in all_results if r["success"]),
                    "failed_scanners": sum(1 for r in all_results if not r["success"]),
                    "total_findings": sum(len(r.get("findings", [])) for r in all_results if r.get("findings"))
                }
            }
            
            # Add OpenAPI metadata if available
            if self.openapi_spec:
                if "metadata" not in self.results:
                    self.results["metadata"] = {}
                
                self.results["metadata"]["openapi"] = {
                    "spec_path": self.swagger_path,
                    "endpoint_count": len(self.openapi_endpoints),
                    "source": self.config.get("target", {}).get("openapi_source", "none")
                }
            
            # Save results if configured
            if self.config.get("output", {}).get("save_results", True):
                output_dir = self.config.get("output", {}).get("directory", "results")
                output_format = self.config.get("output", {}).get("format", "json")
                save_results(self.results, output_dir, output_format)
            
            self.logger.info(f"Scan completed. Found {self.results['summary']['total_findings']} potential vulnerabilities")
            return self.results
            
        except Exception as e:
            self.logger.fatal(f"Scan failed: {str(e)}")
            return {"error": str(e)}
        finally:
            self.end_time = time.time()


def main():
    """Main entry point for the scanner."""
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("--config", "-c", required=True, help="Path to configuration file (YAML/JSON)")
    parser.add_argument("--log-level", "-l", default="INFO", choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
                        help="Logging level")
    parser.add_argument("--output", "-o", help="Path to save results (default: based on config)")
    parser.add_argument("--url", "-u", help="Override target base URL for scanning")
    parser.add_argument("--swagger", "-s", help="Path to OpenAPI/Swagger specification file (JSON or YAML)")
    parser.add_argument("--dos", choices=["true", "false"], default="false",
                        help="Control whether the RegexDOS scanner runs (default: false)")
    args = parser.parse_args()
    
    # Setup logging
    log_config = {}
    try:
        with open(args.config, "r") as f:
            if args.config.endswith(".yaml") or args.config.endswith(".yml"):
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
        log_config = config.get("logging", {})
    except Exception:
        # Use default logging if config can't be loaded
        pass
    
    # Override log level from command line if specified
    if args.log_level:
        log_config["level"] = args.log_level
        
    setup_logger(log_config)
    logger = get_logger("main")
    
    try:
        # Validate URL if provided
        if args.url:
            try:
                parsed_url = urllib.parse.urlparse(args.url)
                if not all([parsed_url.scheme, parsed_url.netloc]):
                    logger.error(f"Invalid URL format: {args.url}")
                    sys.exit(1)
            except Exception as e:
                logger.error(f"Invalid URL format: {str(e)}")
                sys.exit(1)
        
        # Validate OpenAPI spec file if provided
        if args.swagger and not os.path.exists(args.swagger):
            logger.error(f"OpenAPI specification file not found: {args.swagger}")
            sys.exit(1)
        
        # Run the scanner orchestrator
        orchestrator = ScannerOrchestrator(
            config_path=args.config,
            url_override=args.url,
            swagger_path=args.swagger,
            run_dos_scanner=(args.dos.lower() == "true")
        )
        results = orchestrator.run()
        
        # Print summary to console
        formatted_results = format_results(results)
        print(formatted_results)
        
        # Exit with appropriate status code
        if "error" in results or results.get("summary", {}).get("failed_scanners", 0) > 0:
            sys.exit(1)
        sys.exit(0)
        
    except Exception as e:
        logger.fatal(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
