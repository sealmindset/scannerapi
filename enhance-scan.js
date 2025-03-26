/**
 * Script to enhance existing scan results with LLM and store in Redis
 * 
 * Usage: node enhance-scan.js <scanId> <resultsFilePath>
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { processEnhancedResults } = require('./web-interface/utils/report-manager');
require('dotenv').config();

// Get command line arguments
const scanId = process.argv[2];
const resultsFilePath = process.argv[3];

if (!scanId || !resultsFilePath) {
  console.error('Usage: node enhance-scan.js <scanId> <resultsFilePath>');
  process.exit(1);
}

// Check if the results file exists
if (!fs.existsSync(resultsFilePath)) {
  console.error(`Results file not found: ${resultsFilePath}`);
  process.exit(1);
}

// Function to run the report generator to enhance results
async function enhanceWithLLM(scanId, inputFilePath) {
  return new Promise((resolve, reject) => {
    try {
      console.log(`Enhancing scan ${scanId} with LLM...`);
      
      // Prepare output paths
      const enhancedOutputPath = path.join(__dirname, `results/${scanId}_enhanced.json`);
      const reportOutputPath = path.join(__dirname, `reports/${scanId}.html`);
      
      // Ensure directories exist
      if (!fs.existsSync(path.join(__dirname, 'results'))) {
        fs.mkdirSync(path.join(__dirname, 'results'), { recursive: true });
      }
      
      if (!fs.existsSync(path.join(__dirname, 'reports'))) {
        fs.mkdirSync(path.join(__dirname, 'reports'), { recursive: true });
      }
      
      // Prepare command arguments
      let provider = 'ollama';
      let model = 'llama3.3';
      
      // Check for OpenAI API key
      const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
      if (apiKey) {
        console.log('Using OpenAI API key from environment');
        provider = 'openai';
        model = 'gpt-3.5-turbo';
      } else {
        console.log('No OpenAI API key found, using Ollama');
      }
      
      const args = [
        'report_generator.py',
        'enhance-with-llm',
        '--input', inputFilePath,
        '--output', enhancedOutputPath,
        '--provider', provider,
        '--model', model,
        '--generate-report',
        '--report-format', 'html',
        '--report-output', reportOutputPath
      ];
      
      if (apiKey) {
        args.push('--api-key', apiKey);
      }
      
      console.log(`Running command: python3 ${args.join(' ')}`);
      
      // Spawn the process
      const pythonProcess = spawn('python3', args);
      
      // Collect stdout
      let stdout = '';
      pythonProcess.stdout.on('data', (data) => {
        stdout += data.toString();
        console.log(`[STDOUT] ${data.toString().trim()}`);
      });
      
      // Collect stderr
      let stderr = '';
      pythonProcess.stderr.on('data', (data) => {
        stderr += data.toString();
        console.error(`[STDERR] ${data.toString().trim()}`);
      });
      
      // Handle process completion
      pythonProcess.on('close', (code) => {
        console.log(`Python process exited with code ${code}`);
        
        if (code !== 0) {
          return reject(new Error(`Python process failed with code ${code}: ${stderr}`));
        }
        
        // Check if enhanced file was created
        if (!fs.existsSync(enhancedOutputPath)) {
          return reject(new Error(`Enhanced output file not created: ${enhancedOutputPath}`));
        }
        
        console.log(`Enhanced results saved to ${enhancedOutputPath}`);
        console.log(`HTML report saved to ${reportOutputPath}`);
        
        resolve({
          enhancedFilePath: enhancedOutputPath,
          reportFilePath: reportOutputPath,
          provider: apiKey ? 'openai' : 'ollama',
          model: apiKey ? 'gpt-3.5-turbo' : 'llama3.3'
        });
      });
    } catch (error) {
      reject(error);
    }
  });
}

// Main function
async function main() {
  try {
    // Enhance the scan results with LLM
    const enhanceResult = await enhanceWithLLM(scanId, resultsFilePath);
    
    // Process the enhanced results and store in Redis
    // We'll do this manually to ensure it works correctly
    const enhancedContent = JSON.parse(fs.readFileSync(enhanceResult.enhancedFilePath, 'utf8'));
    
    // Connect to Redis
    const redis = require('redis');
    const redisHost = process.env.LLM_REDIS_HOST || 'localhost';
    const redisPort = process.env.LLM_REDIS_PORT || 6379;
    const redisDb = process.env.LLM_REDIS_DB || 0;
    const redisPassword = process.env.LLM_REDIS_PASSWORD || '';
    
    let redisUrl = `redis://${redisHost}:${redisPort}/${redisDb}`;
    if (redisPassword) {
      redisUrl = `redis://:${redisPassword}@${redisHost}:${redisPort}/${redisDb}`;
    }
    
    const redisClient = redis.createClient({
      url: redisUrl
    });
    
    await redisClient.connect();
    console.log('Connected to Redis for storing enhanced results');
    
    // Store vulnerabilities in Redis
    let vulnCount = 0;
    const vulnList = [];
    // Handle both array and object formats for scanners
    const scanners = Array.isArray(enhancedContent.scanners) 
      ? enhancedContent.scanners 
      : (enhancedContent.scanners || {});
    
    // Process scanners
    if (Array.isArray(scanners)) {
      // Handle array format
      for (const scanner of scanners) {
        const scannerName = scanner.name;
        if (scanner.findings && scanner.findings.length > 0) {
          const vulns = scanner.findings;
          console.log(`Processing ${vulns.length} vulnerabilities from scanner ${scannerName}`);
          
          for (const vuln of vulns) {
            // Create a unique ID for the vulnerability
            const vulnId = `${scannerName}:${vuln.id || vuln.vulnerability.replace(/\s+/g, '_').toLowerCase()}`;
            console.log(`Processing vulnerability ${vulnId}`);
            
            // Cache each field separately
            await redisClient.set(`report:${scanId}:vuln:${vulnId}:title`, vuln.vulnerability);
            await redisClient.set(`report:${scanId}:vuln:${vulnId}:severity`, vuln.severity);
            await redisClient.set(`report:${scanId}:vuln:${vulnId}:description`, vuln.description || vuln.details || '');
            await redisClient.set(`report:${scanId}:vuln:${vulnId}:remediation`, vuln.remediation || '');
            
            // Store details if available
            if (vuln.details) {
              await redisClient.set(`report:${scanId}:vuln:${vulnId}:details`, JSON.stringify({
                endpoint: vuln.endpoint,
                details: vuln.details
              }));
            }
            
            // Store evidence if available
            if (vuln.evidence) {
              await redisClient.set(`report:${scanId}:vuln:${vulnId}:evidence`, JSON.stringify(vuln.evidence));
            }
            
            vulnList.push({
              id: vulnId,
              title: vuln.vulnerability,
              severity: vuln.severity,
              scanner: scannerName
            });
            
            vulnCount++;
          }
        }
      }
    } else {
      // Handle object format
      for (const scanner of Object.keys(scanners)) {
        if (scanners[scanner].vulnerabilities) {
          const vulns = scanners[scanner].vulnerabilities;
          console.log(`Processing ${vulns.length} vulnerabilities from scanner ${scanner}`);
          
          for (const vuln of vulns) {
          const vulnId = `${scanner}:${vuln.id || vuln.title.replace(/\s+/g, '_').toLowerCase()}`;
          console.log(`Processing vulnerability ${vulnId}`);
          
          // Cache each field separately
          await redisClient.set(`report:${scanId}:vuln:${vulnId}:title`, vuln.title);
          await redisClient.set(`report:${scanId}:vuln:${vulnId}:severity`, vuln.severity);
          await redisClient.set(`report:${scanId}:vuln:${vulnId}:description`, vuln.description || '');
          await redisClient.set(`report:${scanId}:vuln:${vulnId}:remediation`, vuln.remediation || '');
          
          if (vuln.details) {
            await redisClient.set(`report:${scanId}:vuln:${vulnId}:details`, JSON.stringify(vuln.details));
          }
          
          if (vuln.evidence) {
            await redisClient.set(`report:${scanId}:vuln:${vulnId}:evidence`, JSON.stringify(vuln.evidence));
          }
          
          vulnList.push({
            id: vulnId,
            title: vuln.title,
            severity: vuln.severity,
            scanner
          });
          
          vulnCount++;
        }
      }
    }
  }
    
    // Store scan metadata
    await redisClient.set(`report:${scanId}:metadata`, JSON.stringify({
      scanId,
      timestamp: enhancedContent.start_time || enhancedContent.timestamp || new Date().toISOString(),
      target: enhancedContent.target || 'Unknown',
      summary: enhancedContent.summary || { 
        total_findings: vulnCount,
        total_scanners: Array.isArray(scanners) ? scanners.length : Object.keys(scanners).length,
        successful_scanners: Array.isArray(scanners) ? scanners.filter(s => s.success).length : 0,
        failed_scanners: Array.isArray(scanners) ? scanners.filter(s => !s.success).length : 0
      },
      title: enhancedContent.title || enhancedContent.scan_info?.title || `Scan ${scanId}`
    }));
    
    // Store vulnerability list
    await redisClient.set(`report:${scanId}:vulnList`, JSON.stringify(vulnList));
    
    await redisClient.disconnect();
    console.log(`Successfully processed ${vulnCount} vulnerabilities and stored in Redis`);
    
    const processResult = { 
      success: true, 
      message: `Enhanced content processed and stored for scan ${scanId}` 
    };
    
    if (processResult.success) {
      console.log(`Successfully processed enhanced results: ${processResult.message}`);
      console.log(`\nYou can now view the report in the web interface at:`);
      console.log(`http://localhost:3000/report/editor/${scanId}`);
    } else {
      console.error(`Failed to process enhanced results: ${processResult.message}`);
    }
    
    process.exit(processResult.success ? 0 : 1);
  } catch (error) {
    console.error(`Error in main function: ${error.message}`);
    process.exit(1);
  }
}

// Run the main function
main();
