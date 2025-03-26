/**
 * Report Manager - Handles report generation, storage, and retrieval
 * 
 * This module provides functionality to:
 * 1. Generate enhanced reports using OpenAI's gpt-4o model
 * 2. Store report content in Redis with Scan ID as the key
 * 3. Retrieve and update report content
 * 4. Generate downloadable reports in various formats
 */

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { exec } = require('child_process');
const execAsync = promisify(exec);
const redis = require('redis');
const { cacheReportField, getCachedReportField } = require('./redis');
const handlebars = require('handlebars');

// Load the reference report template
const TEMPLATE_PATH = path.join(__dirname, '../views/report-template.handlebars');
let reportTemplate;

try {
  const templateContent = fs.readFileSync(TEMPLATE_PATH, 'utf8');
  reportTemplate = handlebars.compile(templateContent);
} catch (error) {
  console.error(`Error loading report template: ${error.message}`);
}

/**
 * Generate enhanced report content using OpenAI and store in Redis
 * @param {string} scanId - Scan ID
 * @param {string} provider - LLM provider (default: openai)
 * @param {string} model - LLM model (default: gpt-4o)
 * @param {string} existingEnhancedFile - Path to existing enhanced results file (optional)
 * @returns {Promise<object>} - Status and message
 */
async function generateEnhancedContent(scanId, provider = 'openai', model = 'gpt-4o', existingEnhancedFile = null) {
  try {
    const inputFile = path.join(__dirname, `../../results/${scanId}.json`);
    const outputFile = existingEnhancedFile || path.join(__dirname, `../../results/${scanId}_enhanced.json`);
    
    // If an existing enhanced file is provided, skip the enhancement process
    if (existingEnhancedFile) {
      console.log(`Using existing enhanced file: ${existingEnhancedFile}`);
      
      // Check if the enhanced file exists
      if (!fs.existsSync(existingEnhancedFile)) {
        return { success: false, message: `Enhanced file not found: ${existingEnhancedFile}` };
      }
      
      // Process the enhanced file and store in Redis
      return processEnhancedResults(scanId, existingEnhancedFile, provider, model);
    }
    
    // Check if input file exists
    if (!fs.existsSync(inputFile)) {
      return { success: false, message: `Input file not found: ${inputFile}` };
    }
    
    console.log(`Generating enhanced content for scan ${scanId} using ${provider}/${model}...`);
    
    // Run the enhancement process
    // Use path.resolve to get the absolute path to report_generator.py
    const reportGeneratorPath = path.resolve(path.join(__dirname, '..', '..', 'report_generator.py'));
    
    // Use spawn instead of exec for better error handling and logging
    const rootDir = path.join(__dirname, '..', '..');
    console.log(`Using working directory: ${rootDir}`);
    
    // Build the arguments array
    const args = [
      reportGeneratorPath,
      'enhance-with-llm',
      '--input', path.join(rootDir, 'results', `${scanId}.json`),
      '--output', path.join(rootDir, 'results', `${scanId}_enhanced.json`),
      '--provider', provider,
      '--model', model
    ];
    
    // Add API key if using OpenAI
    if (provider === 'openai') {
      const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
      if (apiKey) {
        args.push('--api-key', apiKey);
      }
    }
    
    console.log(`Running command: python3 ${args.join(' ')}`);
    
    // Use promisify to convert spawn to a promise-based function
    const { promisify } = require('util');
    const { spawn } = require('child_process');
    
    return new Promise((resolve, reject) => {
      const process = spawn('python3', args, {
        cwd: rootDir
      });
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
        console.log(`[Report Generator] ${data.toString().trim()}`);
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
        console.error(`[Report Generator Error] ${data.toString().trim()}`);
      });
      
      process.on('close', (code) => {
        if (code === 0) {
          resolve({ stdout, stderr });
        } else {
          console.error(`Process exited with code ${code}`);
          reject(new Error(`Process exited with code ${code}: ${stderr}`));
        }
      });
    }).then(({ stdout, stderr }) => {
      if (!fs.existsSync(outputFile)) {
        return { success: false, message: `Failed to generate enhanced content: ${stderr}` };
      }
      
      // Read the enhanced content
      const enhancedContent = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
      
      // We need to use Promise chains instead of await inside a .then()
      let promiseChain = Promise.resolve();
      
      // Store vulnerabilities in Redis
      for (const scanner of Object.keys(enhancedContent.scanners)) {
        if (enhancedContent.scanners[scanner].vulnerabilities) {
          for (const vuln of enhancedContent.scanners[scanner].vulnerabilities) {
            const vulnId = `${scanner}:${vuln.id || vuln.title.replace(/\s+/g, '_').toLowerCase()}`;
            
            // Cache each field separately using Promise chaining
            promiseChain = promiseChain
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:title`, vuln.title))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:severity`, vuln.severity))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:description`, vuln.description))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:remediation`, vuln.remediation));
            
            if (vuln.details) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:details`, JSON.stringify(vuln.details)));
            }
            
            if (vuln.evidence) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:evidence`, JSON.stringify(vuln.evidence)));
            }
          }
        }
      }
      
      // Store scan metadata
      promiseChain = promiseChain
        .then(() => cacheReportField(scanId, 'metadata', JSON.stringify({
          scanId,
          timestamp: enhancedContent.timestamp,
          target: enhancedContent.target,
          summary: enhancedContent.summary,
          title: enhancedContent.title || enhancedContent.scan_info?.title || `Scan ${scanId}`
        })));
      
      // Store vulnerability list
      const vulnList = [];
      for (const scanner of Object.keys(enhancedContent.scanners)) {
        if (enhancedContent.scanners[scanner].vulnerabilities) {
          for (const vuln of enhancedContent.scanners[scanner].vulnerabilities) {
            vulnList.push({
              id: `${scanner}:${vuln.id || vuln.title.replace(/\s+/g, '_').toLowerCase()}`,
              title: vuln.title,
              severity: vuln.severity,
              scanner
            });
          }
        }
      }
      
      return promiseChain
        .then(() => cacheReportField(scanId, 'vulnList', JSON.stringify(vulnList)))
        .then(() => ({ success: true, message: `Enhanced content generated and stored for scan ${scanId}` }));
    }).catch(error => {
      console.error(`Error generating enhanced content: ${error.message}`);
      return { success: false, message: `Error: ${error.message}` };
    });
  } catch (error) {
    console.error(`Error generating enhanced content: ${error.message}`);
    return { success: false, message: `Error: ${error.message}` };
  }
}

/**
 * Get vulnerability data for a scan
 * @param {string} scanId - Scan ID
 * @returns {Promise<object>} - Vulnerability data
 */
async function getVulnerabilityData(scanId) {
  try {
    // Get metadata and vulnerability list
    const metadata = JSON.parse(await getCachedReportField(scanId, 'metadata') || '{}');
    const vulnList = JSON.parse(await getCachedReportField(scanId, 'vulnList') || '[]');
    
    // Get detailed vulnerability data
    const vulnerabilities = [];
    for (const vuln of vulnList) {
      const vulnData = {
        id: vuln.id,
        title: await getCachedReportField(scanId, `vuln:${vuln.id}:title`) || vuln.title,
        severity: await getCachedReportField(scanId, `vuln:${vuln.id}:severity`) || vuln.severity,
        description: await getCachedReportField(scanId, `vuln:${vuln.id}:description`) || '',
        remediation: await getCachedReportField(scanId, `vuln:${vuln.id}:remediation`) || '',
        scanner: vuln.scanner
      };
      
      // Get details and evidence if available
      const details = await getCachedReportField(scanId, `vuln:${vuln.id}:details`);
      if (details) {
        vulnData.details = JSON.parse(details);
      }
      
      const evidence = await getCachedReportField(scanId, `vuln:${vuln.id}:evidence`);
      if (evidence) {
        vulnData.evidence = JSON.parse(evidence);
      }
      
      vulnerabilities.push(vulnData);
    }
    
    return {
      metadata,
      vulnerabilities
    };
  } catch (error) {
    console.error(`Error getting vulnerability data: ${error.message}`);
    return { metadata: {}, vulnerabilities: [] };
  }
}

/**
 * Update vulnerability field
 * @param {string} scanId - Scan ID
 * @param {string} vulnId - Vulnerability ID
 * @param {string} field - Field to update
 * @param {string} content - New content
 * @returns {Promise<boolean>} - Success status
 */
async function updateVulnerabilityField(scanId, vulnId, field, content) {
  try {
    await cacheReportField(scanId, `vuln:${vulnId}:${field}`, content);
    return true;
  } catch (error) {
    console.error(`Error updating vulnerability field: ${error.message}`);
    return false;
  }
}

/**
 * Generate HTML report based on the enhanced_report3.html template
 * @param {string} scanId - Scan ID
 * @returns {Promise<string>} - HTML content
 */
async function generateHtmlReport(scanId) {
  try {
    const { metadata, vulnerabilities } = await getVulnerabilityData(scanId);
    
    // Sort vulnerabilities by severity
    const sortedVulnerabilities = [...vulnerabilities].sort((a, b) => {
      const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
    
    // Count vulnerabilities by severity
    const severityCounts = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Info: 0
    };
    
    for (const vuln of vulnerabilities) {
      if (severityCounts[vuln.severity] !== undefined) {
        severityCounts[vuln.severity]++;
      }
    }
    
    // Function to ensure content is properly formatted
    const ensureProperContent = (content) => {
      if (!content) return 'Not available';
      // If content is already HTML (contains HTML tags), return it as is
      if (typeof content === 'string' && (content.includes('<p>') || content.includes('<div>') || content.includes('<br>'))) {
        return content;
      }
      // Otherwise, format it as paragraphs
      if (typeof content === 'string') {
        return content.split('\n').filter(line => line.trim()).map(line => `<p>${line}</p>`).join('');
      }
      return String(content);
    };
    
    // Prepare template data
    const templateData = {
      scanId: metadata.scanId || scanId,
      timestamp: metadata.timestamp || new Date().toISOString(),
      target: metadata.target || 'Unknown Target',
      summary: metadata.summary || 'No summary available',
      title: metadata.title || `Scan ${scanId}`,
      severityCounts,
      vulnerabilities: sortedVulnerabilities.map((vuln, index) => ({
        ...vuln,
        index: index + 1,
        severityClass: vuln.severity.toLowerCase(),
        // Ensure description and remediation are properly formatted
        description: ensureProperContent(vuln.description),
        remediation: ensureProperContent(vuln.remediation)
      }))
    };
    
    // Generate HTML using the template
    if (!reportTemplate) {
      throw new Error('Report template not loaded');
    }
    
    return reportTemplate(templateData);
  } catch (error) {
    console.error(`Error generating HTML report: ${error.message}`);
    throw error;
  }
}

/**
 * Save report to file
 * @param {string} scanId - Scan ID
 * @param {string} format - Report format (html, json, pdf)
 * @returns {Promise<string>} - File path
 */
async function saveReport(scanId, format = 'html') {
  try {
    const outputDir = path.join(__dirname, '../../reports');
    const outputFile = path.join(outputDir, `${scanId}_report.${format}`);
    
    // Create output directory if it doesn't exist
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    
    if (format === 'html') {
      // Generate HTML report
      const htmlContent = await generateHtmlReport(scanId);
      fs.writeFileSync(outputFile, htmlContent);
    } else if (format === 'json') {
      // Generate JSON report
      const { metadata, vulnerabilities } = await getVulnerabilityData(scanId);
      const jsonContent = JSON.stringify({ metadata, vulnerabilities }, null, 2);
      fs.writeFileSync(outputFile, jsonContent);
    } else if (format === 'pdf') {
      // For PDF, we'll need to convert HTML to PDF
      // This would typically use a library like puppeteer
      // For now, we'll just create an HTML file
      const htmlContent = await generateHtmlReport(scanId);
      fs.writeFileSync(outputFile.replace('.pdf', '.html'), htmlContent);
      
      // TODO: Implement PDF conversion
      throw new Error('PDF generation not yet implemented');
    } else {
      throw new Error(`Unsupported format: ${format}`);
    }
    
    return outputFile;
  } catch (error) {
    console.error(`Error saving report: ${error.message}`);
    throw error;
  }
}

/**
 * Process enhanced results file and store in Redis
 * @param {string} scanId - Scan ID
 * @param {string} enhancedFilePath - Path to enhanced results file
 * @param {string} provider - LLM provider used (optional)
 * @param {string} model - LLM model used (optional)
 * @returns {Promise<boolean>} - Success status
 */
async function processEnhancedResults(scanId, enhancedFilePath, provider = 'openai', model = 'gpt-4o') {
  try {
    console.log(`[${new Date().toISOString()}] Processing enhanced results from ${enhancedFilePath}`);
    
    // Check if file exists
    if (!fs.existsSync(enhancedFilePath)) {
      console.error(`Enhanced results file not found: ${enhancedFilePath}`);
      return false;
    }
    
    // Read the enhanced content
    const enhancedContent = JSON.parse(fs.readFileSync(enhancedFilePath, 'utf8'));
    
    // Log the structure of the enhanced content for debugging
    console.log(`Enhanced content structure: ${Object.keys(enhancedContent).join(', ')}`);
    if (enhancedContent.scanners) {
      if (Array.isArray(enhancedContent.scanners)) {
        console.log(`Scanners: Array with ${enhancedContent.scanners.length} items`);
        console.log(`Scanner names: ${enhancedContent.scanners.map(s => s.name).join(', ')}`);
      } else {
        console.log(`Scanners: ${Object.keys(enhancedContent.scanners).join(', ')}`);
      }
    }
    
    // We need to use Promise chains instead of await inside a .then()
    let promiseChain = Promise.resolve();
    
    // Store vulnerabilities in Redis
    if (Array.isArray(enhancedContent.scanners)) {
      // Handle array structure (new format)
      for (const scanner of enhancedContent.scanners) {
        const scannerName = scanner.name;
        if (scanner.findings && Array.isArray(scanner.findings)) {
          console.log(`Processing ${scanner.findings.length} findings from scanner ${scannerName}`);
          
          for (const finding of scanner.findings) {
            // Extract vulnerability information
            const vulnTitle = finding.vulnerability || finding.title || 'Unknown Vulnerability';
            const vulnId = `${scannerName}:${finding.id || vulnTitle.replace(/\s+/g, '_').toLowerCase()}`;
            
            console.log(`Processing vulnerability: ${vulnId}`);
            
            // Cache each field separately using Promise chaining
            promiseChain = promiseChain
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:title`, vulnTitle))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:severity`, finding.severity || 'UNKNOWN'))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:description`, finding.details || ''));
            
            // Add remediation if available
            if (finding.remediation) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:remediation`, finding.remediation));
            }
            
            // Add details if available
            if (finding.details) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:details`, finding.details));
            }
            
            // Add evidence if available
            if (finding.evidence) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:evidence`, JSON.stringify(finding.evidence)));
            }
          }
        }
      }
    } else {
      // Handle object structure (old format)
      for (const scanner of Object.keys(enhancedContent.scanners)) {
        if (enhancedContent.scanners[scanner].vulnerabilities) {
          for (const vuln of enhancedContent.scanners[scanner].vulnerabilities) {
            const vulnId = `${scanner}:${vuln.id || vuln.title.replace(/\s+/g, '_').toLowerCase()}`;
            
            // Cache each field separately using Promise chaining
            promiseChain = promiseChain
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:title`, vuln.title))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:severity`, vuln.severity))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:description`, vuln.description))
              .then(() => cacheReportField(scanId, `vuln:${vulnId}:remediation`, vuln.remediation));
            
            if (vuln.details) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:details`, JSON.stringify(vuln.details)));
            }
            
            if (vuln.evidence) {
              promiseChain = promiseChain
                .then(() => cacheReportField(scanId, `vuln:${vulnId}:evidence`, JSON.stringify(vuln.evidence)));
            }
          }
        }
      }
    }
    
    // Store scan metadata
    promiseChain = promiseChain
      .then(() => cacheReportField(scanId, 'metadata', JSON.stringify({
        scanId,
        timestamp: enhancedContent.timestamp,
        target: enhancedContent.target,
        summary: enhancedContent.summary,
        title: enhancedContent.title || enhancedContent.scan_info?.title || `Scan ${scanId}`
      })));
    
    // Store vulnerability list
    const vulnList = [];
    
    if (Array.isArray(enhancedContent.scanners)) {
      // Handle array structure (new format)
      for (const scanner of enhancedContent.scanners) {
        const scannerName = scanner.name;
        if (scanner.findings && Array.isArray(scanner.findings)) {
          for (const finding of scanner.findings) {
            const vulnTitle = finding.vulnerability || finding.title || 'Unknown Vulnerability';
            vulnList.push({
              id: `${scannerName}:${finding.id || vulnTitle.replace(/\s+/g, '_').toLowerCase()}`,
              title: vulnTitle,
              severity: finding.severity || 'UNKNOWN',
              scanner: scannerName
            });
          }
        }
      }
    } else {
      // Handle object structure (old format)
      for (const scanner of Object.keys(enhancedContent.scanners)) {
        if (enhancedContent.scanners[scanner].vulnerabilities) {
          for (const vuln of enhancedContent.scanners[scanner].vulnerabilities) {
            vulnList.push({
              id: `${scanner}:${vuln.id || vuln.title.replace(/\s+/g, '_').toLowerCase()}`,
              title: vuln.title,
              severity: vuln.severity,
              scanner
            });
          }
        }
      }
    }
    
    console.log(`Storing ${vulnList.length} vulnerabilities in Redis for scan ${scanId}`);
    
    return promiseChain
      .then(() => cacheReportField(scanId, 'vulnList', JSON.stringify(vulnList)))
      .then(() => {
        console.log(`[${new Date().toISOString()}] Successfully processed and stored enhanced content for scan ${scanId}`);
        return true;
      });
  } catch (error) {
    console.error(`[${new Date().toISOString()}] Error processing enhanced results: ${error.message}`);
    return false;
  }
}

module.exports = {
  generateEnhancedContent,
  getVulnerabilityData,
  updateVulnerabilityField,
  generateHtmlReport,
  saveReport,
  processEnhancedResults
};
