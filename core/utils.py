"""
Utility functions for the API Security Scanner.

This module provides various utility functions used across the scanner.
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

import yaml
from rich.console import Console
from rich.table import Table

from core.logger import get_logger

# Get logger
logger = get_logger("utils")

# Rich console for pretty output
console = Console()


def format_results(results: Dict[str, Any]) -> str:
    """
    Format scan results for console output.
    
    Args:
        results: Scan results dictionary
        
    Returns:
        Formatted string for console output
    """
    if "error" in results:
        console.print(f"[bold red]Error:[/bold red] {results['error']}")
        return f"Error: {results['error']}"
    
    # Create summary table
    summary_table = Table(title="API Security Scan Summary")
    summary_table.add_column("Property", style="cyan")
    summary_table.add_column("Value", style="green")
    
    summary = results.get("summary", {})
    summary_table.add_row("Scan ID", results.get("scan_id", "Unknown"))
    summary_table.add_row("Target", results.get("target", "Unknown"))
    summary_table.add_row("Start Time", results.get("start_time", "Unknown"))
    summary_table.add_row("End Time", results.get("end_time", "Unknown"))
    summary_table.add_row("Duration", f"{results.get('duration', 0):.2f} seconds")
    summary_table.add_row("Total Scanners", str(summary.get("total_scanners", 0)))
    summary_table.add_row("Successful Scanners", str(summary.get("successful_scanners", 0)))
    summary_table.add_row("Failed Scanners", str(summary.get("failed_scanners", 0)))
    summary_table.add_row("Total Findings", str(summary.get("total_findings", 0)))
    
    console.print(summary_table)
    
    # Create findings table
    if summary.get("total_findings", 0) > 0:
        findings_table = Table(title="Vulnerability Findings")
        findings_table.add_column("Scanner", style="cyan")
        findings_table.add_column("Vulnerability", style="yellow")
        findings_table.add_column("Severity", style="red")
        findings_table.add_column("Endpoint", style="blue")
        findings_table.add_column("Details", style="green")
        
        for scanner in results.get("scanners", []):
            if not scanner.get("success", False):
                continue
                
            for finding in scanner.get("findings", []):
                findings_table.add_row(
                    scanner.get("name", "Unknown"),
                    finding.get("vulnerability", "Unknown"),
                    finding.get("severity", "Unknown"),
                    finding.get("endpoint", "Unknown"),
                    finding.get("details", "No details provided")
                )
        
        console.print(findings_table)
    
    # Create errors table if there are any failed scanners
    if summary.get("failed_scanners", 0) > 0:
        errors_table = Table(title="Scanner Errors")
        errors_table.add_column("Scanner", style="cyan")
        errors_table.add_column("Error", style="red")
        
        for scanner in results.get("scanners", []):
            if not scanner.get("success", False):
                errors_table.add_row(
                    scanner.get("name", "Unknown"),
                    scanner.get("error", "Unknown error")
                )
        
        console.print(errors_table)
    
    return "Scan completed successfully"


def save_results(results: Dict[str, Any], output_dir: str, output_format: str = "json") -> str:
    """
    Save scan results to a file.
    
    Args:
        results: Scan results dictionary
        output_dir: Directory to save results
        output_format: Output format (json, yaml, text)
        
    Returns:
        Path to the saved results file
    """
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename based on scan ID and timestamp
    scan_id = results.get("scan_id", datetime.now().strftime("%Y%m%d%H%M%S"))
    filename = f"{scan_id}.{output_format}"
    output_path = os.path.join(output_dir, filename)
    
    try:
        with open(output_path, "w") as f:
            if output_format == "json":
                json.dump(results, f, indent=2)
            elif output_format == "yaml":
                yaml.dump(results, f, default_flow_style=False)
            else:
                # Simple text format
                f.write(f"API Security Scan Results\n")
                f.write(f"=======================\n\n")
                f.write(f"Scan ID: {scan_id}\n")
                f.write(f"Target: {results.get('target', 'Unknown')}\n")
                f.write(f"Start Time: {results.get('start_time', 'Unknown')}\n")
                f.write(f"End Time: {results.get('end_time', 'Unknown')}\n")
                f.write(f"Duration: {results.get('duration', 0):.2f} seconds\n\n")
                
                f.write(f"Summary:\n")
                f.write(f"  Total Scanners: {results.get('summary', {}).get('total_scanners', 0)}\n")
                f.write(f"  Successful Scanners: {results.get('summary', {}).get('successful_scanners', 0)}\n")
                f.write(f"  Failed Scanners: {results.get('summary', {}).get('failed_scanners', 0)}\n")
                f.write(f"  Total Findings: {results.get('summary', {}).get('total_findings', 0)}\n\n")
                
                f.write(f"Findings:\n")
                for scanner in results.get("scanners", []):
                    if not scanner.get("success", False):
                        continue
                        
                    for finding in scanner.get("findings", []):
                        f.write(f"  Scanner: {scanner.get('name', 'Unknown')}\n")
                        f.write(f"  Vulnerability: {finding.get('vulnerability', 'Unknown')}\n")
                        f.write(f"  Severity: {finding.get('severity', 'Unknown')}\n")
                        f.write(f"  Endpoint: {finding.get('endpoint', 'Unknown')}\n")
                        f.write(f"  Details: {finding.get('details', 'No details provided')}\n\n")
        
        logger.info(f"Results saved to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to save results: {str(e)}")
        return ""


def generate_payload(payload_type: str, **kwargs) -> Any:
    """
    Generate a payload for API testing based on payload type.
    
    Args:
        payload_type: Type of payload to generate
        **kwargs: Additional parameters for payload generation
        
    Returns:
        Generated payload
    """
    if payload_type == "json":
        return generate_json_payload(**kwargs)
    elif payload_type == "form":
        return generate_form_payload(**kwargs)
    elif payload_type == "xml":
        return generate_xml_payload(**kwargs)
    else:
        return kwargs.get("default", {})


def generate_json_payload(template: Dict = None, **kwargs) -> Dict:
    """
    Generate a JSON payload based on a template.
    
    Args:
        template: Template dictionary
        **kwargs: Additional parameters
        
    Returns:
        Generated JSON payload
    """
    if template is None:
        template = {}
    
    # Create a copy of the template
    payload = template.copy()
    
    # Add or override fields
    for key, value in kwargs.items():
        if key != "template":
            payload[key] = value
    
    return payload


def generate_form_payload(fields: List[str] = None, **kwargs) -> Dict:
    """
    Generate a form payload.
    
    Args:
        fields: List of field names
        **kwargs: Field values
        
    Returns:
        Generated form payload
    """
    payload = {}
    
    if fields:
        for field in fields:
            if field in kwargs:
                payload[field] = kwargs[field]
    else:
        # If no fields specified, use all kwargs
        for key, value in kwargs.items():
            if key != "fields":
                payload[key] = value
    
    return payload


def generate_xml_payload(root_element: str = "request", elements: Dict = None, **kwargs) -> str:
    """
    Generate an XML payload.
    
    Args:
        root_element: Root element name
        elements: Dictionary of element names and values
        **kwargs: Additional parameters
        
    Returns:
        Generated XML payload
    """
    if elements is None:
        elements = {}
    
    # Start XML document
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<{root_element}>\n'
    
    # Add elements
    for name, value in elements.items():
        xml += f'  <{name}>{value}</{name}>\n'
    
    # Close root element
    xml += f'</{root_element}>'
    
    return xml


def rate_limit(max_requests: int, period: float) -> None:
    """
    Implement rate limiting for API requests.
    
    Args:
        max_requests: Maximum number of requests
        period: Time period in seconds
    """
    # Simple implementation using sleep
    time.sleep(period / max_requests)


def parse_response(response: Any, response_format: str = "json") -> Dict:
    """
    Parse API response based on format.
    
    Args:
        response: API response
        response_format: Response format (json, xml, text)
        
    Returns:
        Parsed response as dictionary
    """
    if response_format == "json":
        try:
            return response.json()
        except (ValueError, AttributeError):
            logger.error("Failed to parse JSON response")
            return {}
    elif response_format == "xml":
        # Simple XML parsing (in a real implementation, use a proper XML parser)
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(response.text)
            result = {}
            for child in root:
                result[child.tag] = child.text
            return result
        except Exception as e:
            logger.error(f"Failed to parse XML response: {str(e)}")
            return {}
    else:
        # Return text response as is
        try:
            return {"text": response.text}
        except AttributeError:
            return {"text": str(response)}
