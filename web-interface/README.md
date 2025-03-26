# API Security Scanner Web Interface

A modern web interface for the API Security Scanner tool, built with Express.js and Handlebars.

## Features

- User-friendly interface for configuring and launching API security scans
- Swagger/OpenAPI file upload with drag-and-drop support
- Configurable scan options (DoS testing, SQL injection detection)
- Enhanced scan reports with LLM-generated vulnerability descriptions
- Responsive design for desktop and mobile devices

## Installation

1. Navigate to the web-interface directory:
   ```
   cd web-interface
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Start the server:
   ```
   npm start
   ```

4. Open your browser and navigate to http://localhost:3000

## Usage

### Home Page
The home page provides an overview of the API Security Scanner capabilities.

### Scan Target Page
This page allows you to configure and launch a new scan:

1. **Title**: Enter a descriptive name for your scan
2. **Description**: (Optional) Add details about the purpose of the scan
3. **Target URL**: Enter the base URL of the API to scan (e.g., http://localhost:5003)
4. **Allow to test for DoS**: Choose whether to enable Denial of Service vulnerability testing
5. **Blind SQL Injection**: Configure the SQL injection testing approach
6. **Swagger/OpenAPI File**: Upload your API specification file (JSON or YAML format)

After filling out the form, click the "Scan" button to start the scan. The system will:

1. Process the Swagger/OpenAPI file to generate a configuration
2. Run the scanner with the specified options
3. Generate an enhanced report with LLM-generated descriptions
4. Display the results in a formatted HTML report

### Results Page
This page displays the scan results, including:

- Scan title and description
- Detailed vulnerability findings
- Enhanced descriptions with risk assessments and remediation suggestions

## Architecture

The web interface integrates with the existing Python-based scanner through command-line execution:

1. **Express.js Server**: Handles HTTP requests and serves the web interface
2. **Handlebars Templates**: Renders dynamic HTML content
3. **Scanner Utility Module**: Manages interactions with the Python scanner scripts
4. **Multer**: Handles file uploads for Swagger/OpenAPI specifications

## Dependencies

- Express.js: Web framework
- Express-Handlebars: Templating engine
- Multer: File upload handling
- Body-parser: Request body parsing
- CORS: Cross-origin resource sharing
- Method-override: HTTP method override
- Bootstrap: Frontend styling

## License

This project is part of the API Security Scanner tool suite.
