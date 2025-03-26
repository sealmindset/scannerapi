/**
 * Script to populate Redis with report data from a scan results file
 * This helps ensure the Edit Report page has data to display
 */

const fs = require('fs');
const path = require('path');
const redis = require('../utils/redis');
const cheerio = require('cheerio');

// Scan ID to process
const scanId = process.argv[2];

if (!scanId) {
  console.error('Please provide a scan ID as an argument');
  console.error('Usage: node populate_report_data.js <scanId>');
  process.exit(1);
}

async function populateReportData() {
  try {
    console.log(`Processing report data for scan ID: ${scanId}`);
    
    // Check if the report file exists
    const reportPath = path.join(__dirname, '../../reports', `report_${scanId}.html`);
    
    if (!fs.existsSync(reportPath)) {
      console.error(`Report file not found: ${reportPath}`);
      process.exit(1);
    }
    
    // Read the report content
    const reportContent = fs.readFileSync(reportPath, 'utf8');
    console.log(`Read report file: ${reportPath}`);
    
    // Use cheerio to parse the HTML
    const $ = cheerio.load(reportContent);
    const vulnerabilities = [];
    
    // Extract vulnerability sections
    $('.vulnerability').each((index, element) => {
      // Get the vulnerability name from the h2 tag
      const name = $(element).find('h2').text().trim();
      const id = name.toLowerCase().replace(/[^a-z0-9]/g, '_');
      
      // Extract sections
      const description = extractSection($(element), 'Description');
      const risk = extractSection($(element), 'Risk Assessment');
      const impact = extractSection($(element), 'Impact Analysis');
      const examples = extractSection($(element), 'Real-World Examples');
      const remediation = extractSection($(element), 'Remediation');
      const evidence = extractSection($(element), 'Evidence');
      
      console.log(`Found vulnerability: ${name}`);
      
      vulnerabilities.push({
        id,
        name,
        description,
        risk,
        impact,
        examples,
        remediation,
        evidence
      });
    });
    
    // If no vulnerabilities were found, create a placeholder
    if (vulnerabilities.length === 0) {
      console.log('No vulnerabilities found in the report, creating placeholder');
      
      // Try to get the title and description from the report
      const title = $('h1').first().text().trim() || 'Vulnerability Report';
      const description = $('p').first().text().trim() || 'No vulnerabilities were found in this scan.';
      
      vulnerabilities.push({
        id: 'placeholder',
        name: 'Placeholder Vulnerability',
        description: `This is a placeholder vulnerability for scan ${scanId}. ${description}`,
        risk: 'No risk assessment available.',
        impact: 'No impact analysis available.',
        examples: 'No examples available.',
        remediation: 'No remediation steps available.',
        evidence: 'No evidence available.'
      });
    }
    
    // Store each vulnerability in Redis
    for (const vuln of vulnerabilities) {
      await redis.cacheReportField(scanId, `${vuln.id}_name`, vuln.name);
      await redis.cacheReportField(scanId, `${vuln.id}_description`, vuln.description);
      await redis.cacheReportField(scanId, `${vuln.id}_risk`, vuln.risk);
      await redis.cacheReportField(scanId, `${vuln.id}_impact`, vuln.impact);
      await redis.cacheReportField(scanId, `${vuln.id}_examples`, vuln.examples);
      await redis.cacheReportField(scanId, `${vuln.id}_remediation`, vuln.remediation);
      await redis.cacheReportField(scanId, `${vuln.id}_evidence`, vuln.evidence);
    }
    
    // Store the vulnerability IDs list for easy retrieval
    const vulnIds = vulnerabilities.map(v => v.id);
    await redis.cacheReportField(scanId, 'vulnerability_ids', JSON.stringify(vulnIds));
    
    // Update the scan metadata to indicate it has a report
    const scanMetadata = await redis.getScanMetadata(scanId);
    if (scanMetadata) {
      await redis.storeScanMetadata(scanId, { ...scanMetadata, hasReport: 'true' });
    }
    
    console.log(`Successfully stored ${vulnerabilities.length} vulnerabilities in Redis for scan ID: ${scanId}`);
    process.exit(0);
  } catch (error) {
    console.error(`Error processing report data: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  }
}

// Helper function to extract a section from the vulnerability element
function extractSection(element, sectionName) {
  const sectionHeader = element.find(`h3:contains("${sectionName}")`);
  if (sectionHeader.length === 0) {
    return '';
  }
  
  let content = '';
  let currentElement = sectionHeader[0].nextSibling;
  
  while (currentElement && currentElement.tagName !== 'H3') {
    if (currentElement.type === 'text') {
      content += currentElement.data;
    } else if (currentElement.type === 'tag') {
      content += cheerio.load(currentElement).html();
    }
    
    currentElement = currentElement.nextSibling;
  }
  
  return content.trim();
}

// Run the function and handle Redis connection cleanup
populateReportData()
  .catch(error => {
    console.error(`Unhandled error: ${error.message}`);
    console.error(error.stack);
    process.exit(1);
  });
