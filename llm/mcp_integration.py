#!/usr/bin/env python3
"""
MCP Integration for LLM Enhancement

This module demonstrates how to integrate Model Context Protocol (MCP) with LLMs
to enhance their functionality by providing standardized access to prompt templates
and other data sources.
"""

import json
import requests
import os
import sys
from typing import Dict, List, Any, Optional, Union

class MCPClient:
    """
    Python client for the Model Context Protocol (MCP)
    """
    def __init__(self, endpoint: str):
        """
        Initialize the MCP client
        
        Args:
            endpoint: The MCP server endpoint URL
        """
        self.endpoint = endpoint
        self.initialized = False
        self.request_id = 1
        self.capabilities = None
    
    def get_next_request_id(self) -> int:
        """Get the next request ID"""
        request_id = self.request_id
        self.request_id += 1
        return request_id
    
    def send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Send a request to the MCP server
        
        Args:
            method: The method name
            params: The method parameters
            
        Returns:
            The response from the server
        """
        if params is None:
            params = {}
            
        request = {
            "jsonrpc": "2.0",
            "id": self.get_next_request_id(),
            "method": method,
            "params": params
        }
        
        try:
            response = requests.post(
                self.endpoint,
                headers={"Content-Type": "application/json"},
                json=request
            )
            response.raise_for_status()
            
            data = response.json()
            
            if "error" in data:
                raise Exception(f"MCP error: {data['error']['message']}")
                
            return data["result"]
        except Exception as e:
            print(f"MCP client error: {str(e)}")
            raise
    
    def initialize(self) -> Dict[str, Any]:
        """
        Initialize the MCP connection
        
        Returns:
            The initialization result
        """
        if self.initialized:
            return self.capabilities
            
        try:
            result = self.send_request("initialize", {
                "protocolVersion": "1.0"
            })
            
            self.capabilities = result["capabilities"]
            self.initialized = True
            return result
        except Exception as e:
            print(f"Failed to initialize MCP connection: {str(e)}")
            raise
    
    def list_tools(self) -> Dict[str, Any]:
        """
        Get the list of available tools
        
        Returns:
            The tools list
        """
        if not self.initialized:
            self.initialize()
            
        return self.send_request("listTools")
    
    def call_tool(self, tool_name: str, args: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Call a tool
        
        Args:
            tool_name: The name of the tool to call
            args: The tool arguments
            
        Returns:
            The tool result
        """
        if args is None:
            args = {}
            
        if not self.initialized:
            self.initialize()
            
        return self.send_request("callTool", {
            "toolName": tool_name,
            "arguments": args
        })
    
    def get_prompt_template(self, template_id: str) -> Dict[str, Any]:
        """
        Get a prompt template by ID
        
        Args:
            template_id: The template ID
            
        Returns:
            The prompt template
        """
        return self.call_tool("getPromptTemplate", {"id": template_id})
    
    def list_prompt_templates(self, category: str = "all", limit: int = 20) -> Dict[str, Any]:
        """
        List prompt templates by category
        
        Args:
            category: The category of prompts
            limit: The maximum number of templates to return
            
        Returns:
            The list of prompt templates
        """
        return self.call_tool("listPromptTemplates", {
            "category": category,
            "limit": limit
        })
    
    def search_prompt_templates(self, query: str) -> Dict[str, Any]:
        """
        Search prompt templates by keyword
        
        Args:
            query: The search query
            
        Returns:
            The search results
        """
        return self.call_tool("searchPromptTemplates", {"query": query})


class MCPEnhancedLLM:
    """
    LLM wrapper that uses MCP to enhance functionality
    """
    def __init__(self, mcp_endpoint: str, llm_provider: str = "openai"):
        """
        Initialize the MCP-enhanced LLM
        
        Args:
            mcp_endpoint: The MCP server endpoint URL
            llm_provider: The LLM provider (openai, ollama, etc.)
        """
        self.mcp_client = MCPClient(mcp_endpoint)
        self.llm_provider = llm_provider
        
        # Initialize MCP connection
        self.mcp_client.initialize()
        
        # Get available tools
        self.tools = self.mcp_client.list_tools()
        print(f"Available MCP tools: {[tool['name'] for tool in self.tools['tools']]}")
        
        # Set up LLM provider
        if self.llm_provider == "openai":
            self._setup_openai()
        elif self.llm_provider == "ollama":
            self._setup_ollama()
        else:
            print(f"Warning: Unsupported LLM provider '{llm_provider}'. Using simulation mode.")
    
    def _setup_openai(self):
        """
        Set up OpenAI API
        """
        try:
            import openai
            import os
            self.openai_client = openai.OpenAI(
                api_key=os.environ.get("OPENAI_API_KEY", "")
            )
            print("OpenAI API initialized")
        except ImportError:
            print("Warning: openai package not installed. Using simulation mode.")
            self.openai_client = None
        except Exception as e:
            print(f"Error initializing OpenAI API: {str(e)}")
            self.openai_client = None
    
    def _setup_ollama(self):
        """
        Set up Ollama API
        """
        import os
        self.ollama_endpoint = os.environ.get("OLLAMA_ENDPOINT", "http://localhost:11434")
        print(f"Ollama API initialized with endpoint: {self.ollama_endpoint}")
    
    def _find_relevant_templates(self, query: str) -> List[Dict[str, Any]]:
        """
        Find relevant templates for a query
        
        Args:
            query: The user query
            
        Returns:
            List of relevant templates
        """
        # First try searching for templates
        search_results = self.mcp_client.search_prompt_templates(query)
        if "results" in search_results and search_results["results"]:
            return search_results["results"]
        
        # If no search results, try to determine category from query
        category = "all"
        if "scan" in query.lower() or "security" in query.lower():
            category = "scan"
        elif "report" in query.lower():
            category = "report"
        elif "vulnerability" in query.lower():
            category = "vulnerability"
        
        # Get templates by category
        templates_result = self.mcp_client.list_prompt_templates(category)
        if "templates" in templates_result and templates_result["templates"]:
            return templates_result["templates"]
        
        return []
    
    def _fill_template(self, template: Dict[str, Any], context: Dict[str, Any]) -> str:
        """
        Fill a template with context variables
        
        Args:
            template: The template object
            context: The context variables
            
        Returns:
            The filled template
        """
        template_text = template.get("template", "")
        
        # Simple template variable replacement
        for key, value in context.items():
            placeholder = f"{{{{{key}}}}}"
            if placeholder in template_text:
                template_text = template_text.replace(placeholder, str(value))
        
        return template_text
    
    def _call_openai(self, prompt: str) -> str:
        """
        Call OpenAI API
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            The LLM response
        """
        if not hasattr(self, 'openai_client') or not self.openai_client:
            print("OpenAI client not initialized. Using simulation mode.")
            return f"[Simulated OpenAI response for prompt]"  
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in API security."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error calling OpenAI API: {str(e)}")
            return f"[Error calling OpenAI API: {str(e)}]"  
    
    def _call_ollama(self, prompt: str) -> str:
        """
        Call Ollama API
        
        Args:
            prompt: The prompt to send to the LLM
            
        Returns:
            The LLM response
        """
        try:
            response = requests.post(
                f"{self.ollama_endpoint}/api/generate",
                json={
                    "model": "llama3",
                    "prompt": prompt,
                    "stream": False
                }
            )
            
            if response.status_code == 200:
                return response.json().get('response', '')
            else:
                print(f"Error calling Ollama API: {response.status_code} {response.text}")
                return f"[Error calling Ollama API: {response.status_code}]"  
        except Exception as e:
            print(f"Error calling Ollama API: {str(e)}")
            return f"[Error calling Ollama API: {str(e)}]"  
    
    def generate(self, query: str, context: Dict[str, Any] = None) -> str:
        """
        Generate a response using MCP-enhanced LLM
        
        Args:
            query: The user query
            context: Additional context variables
            
        Returns:
            The generated response
        """
        if context is None:
            context = {}
            
        # Find relevant templates using MCP
        templates = self._find_relevant_templates(query)
        
        if not templates:
            return f"No relevant templates found for: {query}"
        
        # Use the most relevant template
        template = templates[0]
        print(f"Using template: {template.get('name', 'Unknown')}")
        
        # Fill the template with context
        filled_template = self._fill_template(template, context)
        
        print("\nFilled template:\n-------------------")
        print(filled_template)
        print("-------------------\n")
        
        # Call the appropriate LLM
        if self.llm_provider == "openai" and hasattr(self, 'openai_client'):
            response = self._call_openai(filled_template)
        elif self.llm_provider == "ollama" and hasattr(self, 'ollama_endpoint'):
            response = self._call_ollama(filled_template)
        else:
            # Simulation mode
            print("Using simulation mode for LLM response.")
            response = f"[Simulated LLM response using template: {template.get('name', 'Unknown')}]"  
        
        return response


def main():
    """Main function to demonstrate MCP-enhanced LLM"""
    # Get MCP endpoint from environment or use default
    mcp_endpoint = os.environ.get("MCP_ENDPOINT", "http://localhost:3001/api/mcp/mcp")
    
    # Create MCP-enhanced LLM
    llm = MCPEnhancedLLM(mcp_endpoint)
    
    # Process command line arguments or use default query
    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Generate a security report for API endpoint /users/login"
    
    # Sample context
    context = {
        "endpoint": "/users/login",
        "findings": "1 high, 2 medium, and 3 low severity issues",
        "method": "POST"
    }
    
    # Generate response
    response = llm.generate(query, context)
    
    # Print response
    print(response)


if __name__ == "__main__":
    main()
