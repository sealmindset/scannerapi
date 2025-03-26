#!/usr/bin/env python3
"""
Enhance a specific section of a vulnerability report using an LLM.
"""

import argparse
import json
import os
import sys
import time

def get_llm_response(prompt, provider, model, api_key=None):
    """Get a response from the LLM based on the provider.
    
    Args:
        prompt (str): The prompt to send to the LLM
        provider (str): The LLM provider (ollama or openai)
        model (str): The model to use
        api_key (str, optional): API key for OpenAI
        
    Returns:
        str: The LLM response or None if an error occurred
    """
    if provider.lower() == 'ollama':
        try:
            import ollama
            # Check if Ollama server is running
            try:
                response = ollama.chat(model=model, messages=[{'role': 'user', 'content': prompt}])
                return response['message']['content']
            except ConnectionError:
                print(f"Error: Could not connect to Ollama server. Make sure it's running.", file=sys.stderr)
                return None
            except Exception as e:
                print(f"Error with Ollama API call: {str(e)}", file=sys.stderr)
                return None
        except ImportError:
            print(f"Error: No module named 'ollama'. Install with 'pip install ollama'", file=sys.stderr)
            return None
    elif provider.lower() == 'openai':
        try:
            from openai import OpenAI
            # Check for API key
            if not api_key:
                api_key = os.environ.get('OPENAI_API_KEY') or os.environ.get('LLM_OPENAI_API_KEY')
                if not api_key:
                    print(f"Error: OpenAI API key not provided and not found in environment", file=sys.stderr)
                    return None
            
            # Initialize client and make API call
            try:
                client = OpenAI(api_key=api_key)
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7,
                )
                return response.choices[0].message.content
            except Exception as e:
                print(f"Error with OpenAI API call: {str(e)}", file=sys.stderr)
                return None
        except ImportError:
            print(f"Error: No module named 'openai'. Install with 'pip install openai'", file=sys.stderr)
            return None
    else:
        print(f"Error: Unsupported provider '{provider}'. Use 'ollama' or 'openai'.", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(description='Enhance a section of a vulnerability report')
    parser.add_argument('--input', required=True, help='Input JSON file with vulnerability details')
    parser.add_argument('--output', required=True, help='Output file for enhanced content')
    parser.add_argument('--provider', required=True, help='LLM provider (ollama or openai)')
    parser.add_argument('--model', required=True, help='LLM model name')
    parser.add_argument('--api-key', help='API key for the LLM provider')
    parser.add_argument('--section', help='Section name being enhanced (for logging)')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')
    
    args = parser.parse_args()
    
    try:
        section_name = args.section or "vulnerability section"
        
        # Validate provider
        if args.provider.lower() not in ['ollama', 'openai']:
            print(f"Error: Invalid provider '{args.provider}'. Must be 'ollama' or 'openai'.", file=sys.stderr)
            sys.exit(1)
        
        # Load the input file
        try:
            print(f"Loading input file: {args.input}")
            with open(args.input, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in input file: {args.input}", file=sys.stderr)
            sys.exit(1)
        
        # Extract prompt
        prompt = data.get('prompt', '')
        if not prompt:
            print("Error: No prompt found in input file", file=sys.stderr)
            sys.exit(1)
        
        # Log enhancement start
        print(f"Enhancing {section_name} with {args.provider} {args.model}")
        print(f"Progress: 1/3 33.3%")
        
        # Get the LLM response
        enhanced_content = get_llm_response(prompt, args.provider, args.model, args.api_key)
        
        if not enhanced_content:
            print(f"Error: Failed to get response from {args.provider} {args.model}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Progress: 2/3 66.7%")
        
        # Write the output
        try:
            # Ensure output directory exists
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            with open(args.output, 'w') as f:
                f.write(enhanced_content)
        except PermissionError:
            print(f"Error: Permission denied when writing to output file: {args.output}", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
            sys.exit(1)
        
        print(f"Progress: 3/3 100.0%")
        print(f"Enhanced content written to: {args.output}")
        
    except KeyboardInterrupt:
        print("\nEnhancement process interrupted by user", file=sys.stderr)
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
