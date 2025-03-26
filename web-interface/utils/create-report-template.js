#!/usr/bin/env node
/**
 * Script to extract the enhanced_report3.html template and convert it to a Handlebars template
 * for use with the report editor.
 */

const fs = require('fs');
const path = require('path');

// Paths
const sourcePath = path.join(__dirname, '../../reports/enhanced_report3.html');
const targetPath = path.join(__dirname, '../../web-interface/views/report-template.handlebars');

// Read the source template
console.log(`Reading source template from ${sourcePath}`);
const sourceTemplate = fs.readFileSync(sourcePath, 'utf8');

// Extract the CSS styles
const styleMatch = sourceTemplate.match(/<style>([\s\S]*?)<\/style>/);
const styles = styleMatch ? styleMatch[1] : '';

// Extract the HTML structure
const bodyMatch = sourceTemplate.match(/<body>([\s\S]*?)<\/body>/);
const bodyContent = bodyMatch ? bodyMatch[1] : '';

// Create the Handlebars template
const handlebarsTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Report - {{scanId}}</title>
    <style>
${styles}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability Report</h1>

        <h2>Scan Summary</h2>
        <table class="summary-table">
            <tr>
                <th>Scan ID</th>
                <td>{{scanId}}</td>
            </tr>
            <tr>
                <th>Timestamp</th>
                <td>{{timestamp}}</td>
            </tr>
            <tr>
                <th>Target URL</th>
                <td>{{target}}</td>
            </tr>
        </table>
        
        <h2>Vulnerability Summary</h2>
        <table class="summary-table">
            <tr>
                <th>Scanner</th>
                <th>Vulnerability</th>
                <th>Severity</th>
                <th>Endpoint</th>
            </tr>

            {{#each vulnerabilities}}
            <tr>
                <td>{{scanner}}</td>
                <td>{{title}}</td>
                <td class="severity {{severityClass}}">{{severity}}</td>
                <td>{{#if details.endpoint}}{{details.endpoint}}{{else}}N/A{{/if}}</td>
            </tr>
            {{/each}}
        </table>

        <h2>Detailed Findings</h2>
        
        {{#each vulnerabilities}}
        <div class="vulnerability {{severityClass}}">
            <div class="vuln-header">
                <h3>{{index}}. {{title}}</h3>
                <span class="severity {{severityClass}}">{{severity}}</span>
            </div>
            
            <div class="section">
                <div class="section-title">Description:</div>
                <div class="enhanced-content">{{{description}}}</div>
            </div>
            
            {{#if evidence}}
            <div class="section">
                <div class="section-title">Evidence:</div>
                <div class="code-block">
                {{#each evidence}}
                    <p><strong>{{@key}}:</strong></p>
                    <pre>{{this}}</pre>
                {{/each}}
                </div>
            </div>
            {{/if}}
            
            <div class="section">
                <div class="section-title">Remediation:</div>
                <div class="enhanced-content">{{{remediation}}}</div>
            </div>
        </div>
        {{/each}}
    </div>
</body>
</html>`;

// Write the Handlebars template to the target path
console.log(`Writing Handlebars template to ${targetPath}`);
fs.writeFileSync(targetPath, handlebarsTemplate);

console.log('Template conversion complete!');
