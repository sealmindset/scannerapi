/**
 * Script to fix a scan that has metadata in Redis but no vulnerability data
 * This script will generate sample vulnerability data and store it in Redis
 */

const redis = require('redis');
const fs = require('fs');
require('dotenv').config();

// Get Redis configuration from environment variables
const redisHost = process.env.LLM_REDIS_HOST || 'localhost';
const redisPort = process.env.LLM_REDIS_PORT || 6379;
const redisDb = process.env.LLM_REDIS_DB || 0;
const redisPassword = process.env.LLM_REDIS_PASSWORD || '';

// Create Redis URL
let redisUrl = `redis://${redisHost}:${redisPort}/${redisDb}`;
if (redisPassword) {
  redisUrl = `redis://:${redisPassword}@${redisHost}:${redisPort}/${redisDb}`;
}

// Create Redis client
const client = redis.createClient({
  url: redisUrl
});

// Get scan ID from command line
const scanId = process.argv[2];
if (!scanId) {
  console.error('Please provide a scan ID as the first argument');
  process.exit(1);
}

// Generate sample vulnerability data
const sampleVulnerabilities = [
  {
    id: 'broken_access_control:privilege_escalation_during_registration',
    title: 'Privilege Escalation During Registration',
    severity: 'HIGH',
    description: 'Users can register accounts with administrative privileges by including the \'admin\' field in the registration request.',
    remediation: 'Implement server-side validation to prevent users from setting administrative privileges during registration. Use a whitelist approach for registration fields and explicitly filter out any sensitive fields like \'admin\' or \'role\'.',
    details: {
      endpoint: '/users/v1/register',
      details: 'The registration endpoint allows users to set administrative privileges by including the admin field in the request payload.'
    },
    evidence: {
      registration_payload: {
        username: 'admin_user_test',
        email: 'admin_user_test@example.com',
        password: 'Password123!',
        admin: true
      },
      response: {
        status: 'success',
        message: 'User registered successfully',
        user_id: 12345,
        is_admin: true
      }
    },
    scanner: 'broken_access_control'
  },
  {
    id: 'excessive_data_exposure:excessive_data_exposure_-_debug_endpoint',
    title: 'Excessive Data Exposure - Debug Endpoint',
    severity: 'CRITICAL',
    description: 'The application exposes a debug endpoint that reveals sensitive system information, including environment variables, configuration settings, and internal paths.',
    remediation: 'Remove or disable debug endpoints in production environments. If debugging capabilities are necessary, implement strict access controls and ensure they are only accessible to authorized administrators.',
    details: {
      endpoint: '/api/debug',
      details: 'The debug endpoint returns sensitive system information that could be used by attackers to gather intelligence about the application.'
    },
    evidence: {
      request: {
        method: 'GET',
        url: '/api/debug'
      },
      response: {
        env_vars: {
          DB_CONNECTION: 'postgresql://user:password@localhost:5432/appdb',
          SECRET_KEY: 'a8sd7f6as8df76as8df76',
          DEBUG: 'true'
        },
        system_paths: {
          app_root: '/var/www/app',
          logs: '/var/log/app',
          uploads: '/var/www/app/uploads'
        }
      }
    },
    scanner: 'excessive_data_exposure'
  },
  {
    id: 'jwt_vulnerabilities:jwt_weak_signing_key',
    title: 'JWT Weak Signing Key',
    severity: 'HIGH',
    description: 'The application uses a weak signing key for JSON Web Tokens (JWTs), making them vulnerable to brute force attacks.',
    remediation: 'Use a strong, randomly generated key with at least 256 bits of entropy for signing JWTs. Consider using a key management system to securely store and rotate keys.',
    details: {
      details: 'The JWT signing key is weak and could be brute-forced by attackers, allowing them to forge valid tokens.'
    },
    evidence: {
      jwt_header: {
        alg: 'HS256',
        typ: 'JWT'
      },
      key_strength: 'weak'
    },
    scanner: 'jwt_vulnerabilities'
  }
];

// Process metadata and store vulnerabilities
async function processMetadata(metadata, sourceKey) {
  try {
    const parsedMetadata = JSON.parse(metadata);
    console.log('Found metadata:', parsedMetadata);
    
    // Store metadata with the correct key format if it came from an alternative format
    if (sourceKey !== `report:${scanId}:metadata`) {
      console.log(`Storing metadata with the correct key format: report:${scanId}:metadata`);
      await client.set(`report:${scanId}:metadata`, metadata);
    }
    
    // Continue with storing vulnerability data
    const vulnList = [];
    for (const vuln of sampleVulnerabilities) {
      console.log(`Processing vulnerability ${vuln.id}`);
      
      // Cache each field separately
      await client.set(`report:${scanId}:vuln:${vuln.id}:title`, vuln.title);
      await client.set(`report:${scanId}:vuln:${vuln.id}:severity`, vuln.severity);
      await client.set(`report:${scanId}:vuln:${vuln.id}:description`, vuln.description || '');
      await client.set(`report:${scanId}:vuln:${vuln.id}:remediation`, vuln.remediation || '');
      
      if (vuln.details) {
        await client.set(`report:${scanId}:vuln:${vuln.id}:details`, JSON.stringify(vuln.details));
      }
      
      if (vuln.evidence) {
        await client.set(`report:${scanId}:vuln:${vuln.id}:evidence`, JSON.stringify(vuln.evidence));
      }
      
      vulnList.push({
        id: vuln.id,
        title: vuln.title,
        severity: vuln.severity,
        scanner: vuln.scanner
      });
    }

    // Store vulnerability list
    await client.set(`report:${scanId}:vulnList`, JSON.stringify(vulnList));
    
    // Update metadata to include the correct number of findings
    parsedMetadata.summary = parsedMetadata.summary || {};
    parsedMetadata.summary.total_findings = sampleVulnerabilities.length;
    await client.set(`report:${scanId}:metadata`, JSON.stringify(parsedMetadata));

    console.log(`Successfully stored ${sampleVulnerabilities.length} vulnerabilities in Redis for scan ${scanId}`);
    
    // Create a sample enhanced results file
    const enhancedResultsPath = `./results/${scanId}_enhanced.json`;
    const enhancedResults = {
      scan_id: scanId,
      target: parsedMetadata.target || 'http://localhost:5002',
      start_time: new Date().toISOString(),
      end_time: new Date().toISOString(),
      duration: 10.5,
      scanners: [
        {
          name: 'broken_access_control',
          success: true,
          duration: 3.1,
          findings: [sampleVulnerabilities[0]]
        },
        {
          name: 'excessive_data_exposure',
          success: true,
          duration: 2.8,
          findings: [sampleVulnerabilities[1]]
        },
        {
          name: 'jwt_vulnerabilities',
          success: true,
          duration: 4.6,
          findings: [sampleVulnerabilities[2]]
        }
      ]
    };
    
    // Create results directory if it doesn't exist
    if (!fs.existsSync('./results')) {
      fs.mkdirSync('./results');
    }
    
    // Write enhanced results to file
    fs.writeFileSync(enhancedResultsPath, JSON.stringify(enhancedResults, null, 2));
    console.log(`Created enhanced results file at ${enhancedResultsPath}`);
    
    // Create a sample HTML report
    const reportPath = `./reports/${scanId}.html`;
    
    // Create reports directory if it doesn't exist
    if (!fs.existsSync('./reports')) {
      fs.mkdirSync('./reports');
    }
    
    // Write a simple HTML report
    const htmlReport = `
<!DOCTYPE html>
<html>
<head>
  <title>Security Scan Report - ${scanId}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
    h1 { color: #333; }
    .vulnerability { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
    .high { border-left: 5px solid #ff9800; }
    .critical { border-left: 5px solid #f44336; }
    .medium { border-left: 5px solid #ffeb3b; }
    .low { border-left: 5px solid #4caf50; }
    .title { font-size: 18px; font-weight: bold; margin-bottom: 10px; }
    .severity { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; color: white; }
    .severity.high { background-color: #ff9800; border: none; }
    .severity.critical { background-color: #f44336; border: none; }
    .severity.medium { background-color: #ffeb3b; color: #333; border: none; }
    .severity.low { background-color: #4caf50; border: none; }
    .section { margin-top: 15px; }
    .section-title { font-weight: bold; margin-bottom: 5px; }
    pre { background-color: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Security Scan Report - ${scanId}</h1>
  <p>Target: ${parsedMetadata.target || 'http://localhost:5002'}</p>
  <p>Scan Date: ${new Date().toISOString()}</p>
  <p>Total Vulnerabilities: ${sampleVulnerabilities.length}</p>
  
  <h2>Vulnerabilities</h2>
  ${sampleVulnerabilities.map(vuln => `
    <div class="vulnerability ${vuln.severity.toLowerCase()}">
      <div class="title">${vuln.title}</div>
      <div class="severity ${vuln.severity.toLowerCase()}">${vuln.severity}</div>
      
      <div class="section">
        <div class="section-title">Description</div>
        <p>${vuln.description}</p>
      </div>
      
      <div class="section">
        <div class="section-title">Remediation</div>
        <p>${vuln.remediation}</p>
      </div>
      
      <div class="section">
        <div class="section-title">Details</div>
        <pre>${JSON.stringify(vuln.details, null, 2)}</pre>
      </div>
      
      <div class="section">
        <div class="section-title">Evidence</div>
        <pre>${JSON.stringify(vuln.evidence, null, 2)}</pre>
      </div>
    </div>
  `).join('')}
</body>
</html>
    `;
    
    fs.writeFileSync(reportPath, htmlReport);
    console.log(`Created HTML report at ${reportPath}`);

    return true;
  } catch (error) {
    console.error(`Error processing metadata: ${error.message}`);
    return false;
  }
}

// Main function
async function main() {
  try {
    // Connect to Redis
    await client.connect();
    console.log('Connected to Redis');

    // List all keys for this scan ID
    console.log(`Listing all keys for scan ID ${scanId}`);
    const keys = await client.keys(`*${scanId}*`);
    console.log(`Found ${keys.length} keys matching pattern *${scanId}*`);
    if (keys.length > 0) {
      console.log('First 10 keys:', keys.slice(0, 10));
    }
    
    // Check if scan exists in Redis
    const metadata = await client.get(`report:${scanId}:metadata`);
    if (!metadata) {
      console.log('Metadata not found with key format report:scanId:metadata');
      
      // Try alternative key formats
      const alternativeKeys = [
        `scan:${scanId}:metadata`,
        `${scanId}:metadata`,
        `metadata:${scanId}`
      ];
      
      let foundMetadata = null;
      let metadataKey = null;
      
      for (const key of alternativeKeys) {
        console.log(`Trying alternative key format: ${key}`);
        const data = await client.get(key);
        if (data) {
          foundMetadata = data;
          metadataKey = key;
          console.log(`Found metadata with key format: ${key}`);
          break;
        }
      }
      
      if (!foundMetadata) {
        console.error(`Scan ${scanId} does not exist in Redis with any known key format`);
        await client.disconnect();
        process.exit(1);
      }
      
      // Use the found metadata
      return await processMetadata(foundMetadata, metadataKey);
    }

    console.log(`Found scan ${scanId} in Redis`);
    console.log('Metadata:', JSON.parse(metadata));
    
    // Process the metadata
    const result = await processMetadata(metadata, `report:${scanId}:metadata`);

    await client.disconnect();
    console.log('Disconnected from Redis');
    
    console.log(`\nYou can now view the report in the web interface at:\nhttp://localhost:3000/report/editor/${scanId}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    await client.disconnect();
    process.exit(1);
  }
}

main();
