/**
 * Test script for re-enhancing scan results
 * 
 * This script tests the enhanced scan report functionality by:
 * 1. Finding the most recent scan result
 * 2. Running the report_generator.py script to enhance it
 * 3. Processing the enhanced results and storing them in Redis
 * 4. Verifying that the vulnerabilities are correctly stored in Redis
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const { promisify } = require('util');
const redisClient = require('./web-interface/utils/redis').client;
const reportManager = require('./web-interface/utils/report-manager');

// Get the most recent scan result
function getMostRecentScan() {
  const resultsDir = path.join(__dirname, 'web-interface', 'results');
  
  console.log(`Looking for scan results in ${resultsDir}`);
  
  // Get all JSON files in the results directory
  const files = fs.readdirSync(resultsDir)
    .filter(file => file.endsWith('.json') && !file.includes('_enhanced'))
    .map(file => ({
      name: file,
      scanId: file.replace('.json', ''),
      path: path.join(resultsDir, file),
      time: fs.statSync(path.join(resultsDir, file)).mtime.getTime()
    }))
    .sort((a, b) => b.time - a.time); // Sort by most recent first
  
  if (files.length === 0) {
    console.log('No scan results found');
    return null;
  }
  
  console.log(`Found ${files.length} scan results`);
  console.log(`Most recent scan: ${files[0].scanId} (${new Date(files[0].time).toISOString()})`);
  
  return files[0];
}

// Enhance scan results using report_generator.py
async function enhanceScanResults(scanInfo, provider = 'openai', model = 'gpt-4o') {
  return new Promise((resolve, reject) => {
    const inputPath = scanInfo.path;
    const outputPath = path.join(path.dirname(inputPath), `${scanInfo.scanId}_enhanced.json`);
    const reportPath = path.join(__dirname, 'web-interface', 'reports', `${scanInfo.scanId}.html`);
    
    console.log(`Enhancing scan results for ${scanInfo.scanId}`);
    console.log(`Input path: ${inputPath}`);
    console.log(`Output path: ${outputPath}`);
    console.log(`Report path: ${reportPath}`);
    
    // Prepare command arguments
    const args = [
      'report_generator.py',
      'enhance-with-llm',
      '--input', inputPath,
      '--output', outputPath,
      '--provider', provider,
      '--model', model,
      '--generate-report',
      '--report-format', 'html',
      '--report-output', reportPath
    ];
    
    // Add API key if using OpenAI
    if (provider === 'openai') {
      const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
      if (apiKey) {
        args.push('--api-key', apiKey);
        console.log('Using OpenAI API key from environment');
      } else {
        console.log('No OpenAI API key found in environment');
      }
    }
    
    console.log(`Running command: python3 ${args.join(' ')}`);
    
    // Check if the python directory exists
    const pythonDir = path.join(__dirname, 'python');
    const rootDir = __dirname;
    
    // Determine the correct working directory
    let cwd = rootDir;
    if (fs.existsSync(pythonDir)) {
      cwd = pythonDir;
      console.log(`Using Python directory: ${pythonDir}`);
    } else {
      console.log(`Python directory not found, using root directory: ${rootDir}`);
    }
    
    // Spawn Python process
    const pythonProcess = spawn('python3', args, { cwd });
    
    let output = '';
    
    pythonProcess.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      console.log(`[Enhance] ${chunk}`);
    });
    
    pythonProcess.stderr.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      console.error(`[Enhance Error] ${chunk}`);
    });
    
    pythonProcess.on('error', (error) => {
      console.error(`Error running Python process: ${error.message}`);
      reject(error);
    });
    
    pythonProcess.on('close', (code) => {
      console.log(`Python process exited with code ${code}`);
      
      if (code === 0) {
        // Check if the enhanced results file exists
        if (!fs.existsSync(outputPath)) {
          const errorMsg = `Enhanced results file not found at ${outputPath}`;
          console.error(errorMsg);
          reject(new Error(errorMsg));
          return;
        }
        
        resolve({
          scanId: scanInfo.scanId,
          enhancedPath: outputPath,
          reportPath
        });
      } else {
        reject(new Error(`Python process exited with code ${code}`));
      }
    });
  });
}

// Check Redis for vulnerabilities
async function checkRedisForVulnerabilities(scanId) {
  console.log(`Checking Redis for vulnerabilities for scan ${scanId}`);
  
  // Get the list of vulnerabilities
  const vulnListKey = `report:${scanId}:vulnList`;
  const vulnList = await redisClient.get(vulnListKey);
  
  if (!vulnList) {
    console.log(`No vulnerability list found for scan ${scanId}`);
    return false;
  }
  
  const vulnerabilities = JSON.parse(vulnList);
  console.log(`Found ${vulnerabilities.length} vulnerabilities for scan ${scanId}`);
  
  // Check a few vulnerabilities to make sure they're stored correctly
  for (let i = 0; i < Math.min(3, vulnerabilities.length); i++) {
    const vuln = vulnerabilities[i];
    console.log(`Checking vulnerability ${i + 1}: ${vuln.id}`);
    
    const titleKey = `report:${scanId}:vuln:${vuln.id}:title`;
    const title = await redisClient.get(titleKey);
    
    if (!title) {
      console.log(`No title found for vulnerability ${vuln.id}`);
      continue;
    }
    
    console.log(`Title: ${title}`);
    
    const descriptionKey = `report:${scanId}:vuln:${vuln.id}:description`;
    const description = await redisClient.get(descriptionKey);
    
    if (description) {
      console.log(`Description: ${description.substring(0, 100)}...`);
    } else {
      console.log(`No description found for vulnerability ${vuln.id}`);
    }
    
    console.log('---');
  }
  
  return true;
}

// Main function
async function main() {
  try {
    // Find the most recent scan
    const scanInfo = getMostRecentScan();
    if (!scanInfo) {
      console.log('No scan results found. Please run a scan first.');
      process.exit(1);
    }
    
    // Enhance the scan results
    const enhancedInfo = await enhanceScanResults(scanInfo);
    console.log(`Enhanced scan results saved to ${enhancedInfo.enhancedPath}`);
    console.log(`Report saved to ${enhancedInfo.reportPath}`);
    
    // Process the enhanced results and store them in Redis
    console.log('Processing enhanced results and storing in Redis...');
    const processed = await reportManager.processEnhancedResults(
      enhancedInfo.scanId,
      enhancedInfo.enhancedPath
    );
    
    console.log(`Processed enhanced results: ${processed ? 'Success' : 'Failed'}`);
    
    // Check Redis for vulnerabilities
    const redisCheck = await checkRedisForVulnerabilities(enhancedInfo.scanId);
    console.log(`Redis check: ${redisCheck ? 'Success' : 'Failed'}`);
    
    // Close Redis connection
    await redisClient.quit();
    console.log('Done!');
  } catch (error) {
    console.error(`Error: ${error.message}`);
    try {
      await redisClient.quit();
    } catch (err) {
      console.error(`Error closing Redis connection: ${err.message}`);
    }
    process.exit(1);
  }
}

// Run the main function
main();
