const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

/**
 * Enhances scan results with LLM-generated content
 * @param {string} scanId - The scan ID
 * @param {string} provider - LLM provider (openai, ollama)
 * @param {object} io - Socket.IO instance for real-time updates
 * @param {string} sessionId - Socket.IO session ID
 * @returns {Promise<string>} - Path to the enhanced report
 */
async function enhanceWithLLM(scanId, provider = 'openai', io = null, sessionId = null) {
  return new Promise((resolve, reject) => {
    // Paths for input and output files
    const inputFile = path.join(__dirname, '..', '..', `${scanId}.json`);
    const outputFile = path.join(__dirname, '..', '..', `enhanced_results_${scanId}.json`);
    const reportPath = path.join(__dirname, '..', '..', 'reports', `report_${scanId}.html`);
    
    // Check if input file exists
    if (!fs.existsSync(inputFile)) {
      return reject(new Error(`Input file not found: ${inputFile}`));
    }
    
    // Command to run the report generator
    const pythonPath = 'python3'; // Adjust if needed
    const scriptPath = path.resolve(path.join(__dirname, '..', '..', 'report_generator.py'));
    
    // Build command arguments
    const args = [
      scriptPath,
      'enhance-with-llm',
      '--input', inputFile,
      '--output', outputFile,
      '--provider', provider
      // Removed report generation flags to prevent double processing
      // The web interface will generate the report after enhancement
    ];
    
    // Add model if specified
    if (model) {
      args.push('--model', model);
    }
    
    // Add API key if using OpenAI
    if (provider === 'openai') {
      const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
      if (apiKey) {
        args.push('--api-key', apiKey);
      }
    }
    
    console.log(`Running LLM enhancement: ${pythonPath} ${args.join(' ')}`);
    
    // Use the root directory as cwd to ensure the script is found
    const rootDir = path.join(__dirname, '..', '..');
    console.log(`Using working directory: ${rootDir}`);
    
    // Spawn the process with the correct working directory
    const process = spawn(pythonPath, args, {
      cwd: rootDir
    });
    
    let output = '';
    let errorOutput = '';
    
    // Capture standard output
    process.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      
      if (io && sessionId) {
        io.to(sessionId).emit('llm-enhancer-status', {
          type: 'progress',
          data: chunk
        });
      }
      
      console.log(`LLM Enhancer Output: ${chunk}`);
    });
    
    // Capture error output
    process.stderr.on('data', (data) => {
      const chunk = data.toString();
      errorOutput += chunk;
      
      if (io && sessionId) {
        io.to(sessionId).emit('llm-enhancer-status', {
          type: 'error',
          data: chunk
        });
      }
      
      console.error(`LLM Enhancer Error: ${chunk}`);
    });
    
    // Handle process completion
    process.on('close', async (code) => {
      if (code === 0) {
        // Generate report using the web interface's report manager
        try {
          const reportManager = require('./report-manager');
          
          // Generate HTML report from enhanced data
          console.log(`Generating HTML report for scan ${scanId} using web interface...`);
          if (io && sessionId) {
            io.to(sessionId).emit('llm-enhancer-status', {
              type: 'progress',
              data: `Generating HTML report for scan ${scanId}...`
            });
          }
          
          // Generate the HTML report
          const htmlContent = await reportManager.generateHtmlReport(scanId);
          
          // Save the report
          fs.writeFileSync(reportPath, htmlContent);
          
          console.log(`Generated HTML report at ${reportPath}`);
          
          // Notify the client
          if (io && sessionId) {
            io.to(sessionId).emit('llm-enhancer-status', {
              type: 'complete',
              success: true,
              reportPath: `/reports/report_${scanId}.html`
            });
          }
          
          resolve(reportPath);
        } catch (reportError) {
          console.error(`Error generating report: ${reportError.message}`);
          
          if (io && sessionId) {
            io.to(sessionId).emit('llm-enhancer-status', {
              type: 'error',
              data: `Error generating report: ${reportError.message}`
            });
            
            // Even if report generation fails, the enhancement was successful
            io.to(sessionId).emit('llm-enhancer-status', {
              type: 'complete',
              success: true,
              error: reportError.message
            });
          }
          
          // Even if report generation fails, the enhancement was successful
          resolve(outputFile);
        }
      } else {
        const error = new Error(`LLM enhancement failed with code ${code}: ${errorOutput}`);
        
        if (io && sessionId) {
          io.to(sessionId).emit('llm-enhancer-status', {
            type: 'complete',
            success: false,
            error: error.message
          });
        }
        
        reject(error);
      }
    });
  });
}

module.exports = {
  enhanceWithLLM
};
