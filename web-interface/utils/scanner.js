const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { enhanceWithLLM } = require('./llm-enhancer');
const util = require('util');
const { appendSessionOutput, updateSessionStatus } = require('./session-store');

// Track active processes by session ID
const activeProcesses = {};

// Export a function that takes the Socket.IO instance
module.exports = function(io) {

/**
 * Pause an active scan process
 * @param {string} sessionId - Session ID of the scan to pause
 * @returns {boolean} - Whether the process was successfully paused
 */
function pauseScan(sessionId) {
  if (!activeProcesses[sessionId] || activeProcesses[sessionId].paused) {
    return false;
  }
  
  try {
    // Send SIGSTOP to pause the process
    process.kill(activeProcesses[sessionId].process.pid, 'SIGSTOP');
    
    // Mark as paused
    activeProcesses[sessionId].paused = true;
    
    // Update session status
    updateSessionStatus(sessionId, 'paused', {
      pausedAt: new Date().toISOString()
    });
    
    // Emit status update
    io.to(sessionId).emit('scanner-status', {
      type: 'scan-paused',
      success: true,
      message: 'Scan paused by user'
    });
    
    return true;
  } catch (error) {
    console.error(`Error pausing scan ${sessionId}:`, error);
    return false;
  }
}

/**
 * Resume a paused scan process
 * @param {string} sessionId - Session ID of the scan to resume
 * @returns {boolean} - Whether the process was successfully resumed
 */
function resumeScan(sessionId) {
  if (!activeProcesses[sessionId] || !activeProcesses[sessionId].paused) {
    return false;
  }
  
  try {
    // Send SIGCONT to resume the process
    process.kill(activeProcesses[sessionId].process.pid, 'SIGCONT');
    
    // Mark as not paused
    activeProcesses[sessionId].paused = false;
    
    // Update session status
    updateSessionStatus(sessionId, 'running', {
      resumedAt: new Date().toISOString()
    });
    
    // Emit status update
    io.to(sessionId).emit('scanner-status', {
      type: 'scan-resumed',
      success: true,
      message: 'Scan resumed by user'
    });
    
    return true;
  } catch (error) {
    console.error(`Error resuming scan ${sessionId}:`, error);
    return false;
  }
}

/**
 * Stop an active scan process
 * @param {string} sessionId - Session ID of the scan to stop
 * @returns {boolean} - Whether the process was successfully stopped
 */
function stopScan(sessionId) {
  if (!activeProcesses[sessionId]) {
    return false;
  }
  
  try {
    // Kill the process
    activeProcesses[sessionId].process.kill();
    
    // Update session status
    updateSessionStatus(sessionId, 'stopped', {
      stoppedAt: new Date().toISOString(),
      stoppedBy: 'user'
    });
    
    // Emit status update
    io.to(sessionId).emit('scanner-status', {
      type: 'scan-stopped',
      success: true,
      message: 'Scan stopped by user'
    });
    
    // Clean up
    delete activeProcesses[sessionId];
    
    return true;
  } catch (error) {
    console.error(`Error stopping scan ${sessionId}:`, error);
    return false;
  }
}

/**
 * Pause an active scan process
 * @param {string} sessionId - Session ID of the scan to pause
 * @returns {boolean} - Whether the process was successfully paused
 */
function pauseScan(sessionId) {
  if (!activeProcesses[sessionId] || activeProcesses[sessionId].paused) {
    return false;
  }
  
  try {
    // Send SIGSTOP to pause the process
    process.kill(activeProcesses[sessionId].process.pid, 'SIGSTOP');
    
    // Mark as paused
    activeProcesses[sessionId].paused = true;
    
    // Update session status
    updateSessionStatus(sessionId, 'paused', {
      pausedAt: new Date().toISOString()
    });
    
    // Emit status update
    io.to(sessionId).emit('scanner-status', {
      type: 'scan-paused',
      success: true,
      message: 'Scan paused by user'
    });
    
    return true;
  } catch (error) {
    console.error(`Error pausing scan ${sessionId}:`, error);
    return false;
  }
}

/**
 * Resume a paused scan process
 * @param {string} sessionId - Session ID of the scan to resume
 * @returns {boolean} - Whether the process was successfully resumed
 */
function resumeScan(sessionId) {
  if (!activeProcesses[sessionId] || !activeProcesses[sessionId].paused) {
    return false;
  }
  
  try {
    // Send SIGCONT to resume the process
    process.kill(activeProcesses[sessionId].process.pid, 'SIGCONT');
    
    // Mark as not paused
    activeProcesses[sessionId].paused = false;
    
    // Update session status
    updateSessionStatus(sessionId, 'running', {
      resumedAt: new Date().toISOString()
    });
    
    // Emit status update
    io.to(sessionId).emit('scanner-status', {
      type: 'scan-resumed',
      success: true,
      message: 'Scan resumed by user'
    });
    
    return true;
  } catch (error) {
    console.error(`Error resuming scan ${sessionId}:`, error);
    return false;
  }
}

/**
 * Generate a configuration file from a Swagger/OpenAPI specification
 * @param {string} swaggerPath - Path to the Swagger/OpenAPI file
 * @param {string} configName - Name for the generated config file
 * @param {string} [sessionId] - Optional session ID for socket communication
 * @returns {Promise<string>} - Path to the generated config file
 */
async function generateConfig(swaggerPath, configName, sessionId) {
  const configOutput = path.join('configs', `${configName}.yaml`);
  const args = [
    'gen_config_yaml.py',
    '--swagger', swaggerPath,
    '--output', configOutput
  ];
  
  return new Promise((resolve, reject) => {
    const process = spawn('python3', args, { 
      cwd: path.join(__dirname, '../..')
    });
    
    // Track the process if session ID is provided
    if (sessionId) {
      activeProcesses[sessionId] = {
        process,
        type: 'report',
        startTime: Date.now(),
        paused: false
      };
    }
    
    let output = '';
    
    process.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      console.log(chunk);
      
      // Update session state if session ID is provided
      if (sessionId) {
        appendSessionOutput(sessionId, 'config', chunk);
      }
      
      // Emit to specific session if provided
      if (sessionId && io) {
        io.to(sessionId).emit('scanner-output', {
          type: 'config',
          data: chunk
        });
      } else if (io) {
        // Broadcast to all clients if no session ID
        io.emit('scanner-output', {
          type: 'config',
          data: chunk
        });
      }
    });
    
    process.stderr.on('data', (data) => {
      const chunk = data.toString();
      console.error(chunk);
      
      // Update session state if session ID is provided
      if (sessionId) {
        appendSessionOutput(sessionId, 'config', `ERROR: ${chunk}`);
      }
      
      if (sessionId && io) {
        io.to(sessionId).emit('scanner-output', {
          type: 'config-error',
          data: chunk
        });
      } else if (io) {
        io.emit('scanner-output', {
          type: 'config-error',
          data: chunk
        });
      }
    });
    
    process.on('close', (code) => {
      if (code === 0) {
        // Update session state if session ID is provided
        if (sessionId) {
          updateSessionStatus(sessionId, 'running', {
            currentStep: 'scan',
            configComplete: true
          });
        }
        
        if (sessionId && io) {
          io.to(sessionId).emit('scanner-status', {
            type: 'config-complete',
            success: true
          });
        }
        resolve(configOutput);
      } else {
        const error = new Error(`Config generation process exited with code ${code}\n${output}`);
        
        // Update session state if session ID is provided
        if (sessionId) {
          updateSessionStatus(sessionId, 'error', {
            error: error.message
          });
        }
        
        if (sessionId && io) {
          io.to(sessionId).emit('scanner-status', {
            type: 'config-complete',
            success: false,
            error: error.message
          });
        }
        reject(error);
      }
    });
  });
}

/**
 * Run a scan using the API Security Scanner
 * @param {string} configPath - Path to the configuration file
 * @param {string} targetUrl - Target URL to scan
 * @param {boolean} allowDos - Whether to allow DoS testing
 * @param {string} sqlInjection - SQL injection testing mode
 * @param {string} [sessionId] - Optional session ID for socket communication
 * @returns {Promise<string>} - Scan ID
 */
async function runScan(configPath, targetUrl, allowDos, sqlInjection, sessionId) {
  const dosFlag = allowDos ? 'true' : 'false';
  const args = [
    'scanner.py',
    '--config', configPath,
    '--url', targetUrl,
    '--dos', dosFlag,
    '--sqlintensity', sqlInjection || 'smart'
  ];
  
  return new Promise((resolve, reject) => {
    const process = spawn('python3', args, { 
      cwd: path.join(__dirname, '../..')
    });
    
    // Track the process if session ID is provided
    if (sessionId) {
      activeProcesses[sessionId] = {
        process,
        type: 'report',
        startTime: Date.now(),
        paused: false
      };
    }
    
    let output = '';
    let scanId = null;
    
    process.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      console.log(chunk);
      
      // Try to extract scan ID from the output
      const scanIdMatch = chunk.match(/Scan ID: (\d+)/);
      // Also look for timestamp format IDs (e.g., 20250317160541)
      const timestampMatch = chunk.match(/Scan ID:\s+([0-9]{14})/);
      const propertyMatch = chunk.match(/\| Scan ID\s+\|\s+([0-9]{14})\s+\|/);
      
      if (scanIdMatch) {
        scanId = scanIdMatch[1];
        console.log(`Extracted scan ID from output: ${scanId}`);
        // Update session with scan ID if available
        if (sessionId) {
          updateSessionStatus(sessionId, 'running', { scanId });
        }
      } else if (timestampMatch) {
        scanId = timestampMatch[1];
        console.log(`Extracted timestamp scan ID from output: ${scanId}`);
        if (sessionId) {
          updateSessionStatus(sessionId, 'running', { scanId });
        }
      } else if (propertyMatch) {
        scanId = propertyMatch[1];
        console.log(`Extracted scan ID from property table: ${scanId}`);
        if (sessionId) {
          updateSessionStatus(sessionId, 'running', { scanId });
        }
      }
      
      // Update session state if session ID is provided
      if (sessionId) {
        appendSessionOutput(sessionId, 'scan', chunk);
      }
      
      // Emit to specific session if provided
      if (sessionId && io) {
        io.to(sessionId).emit('scanner-output', {
          type: 'scan',
          data: chunk
        });
      } else if (io) {
        // Broadcast to all clients if no session ID
        io.emit('scanner-output', {
          type: 'scan',
          data: chunk
        });
      }
    });
    
    process.stderr.on('data', (data) => {
      const chunk = data.toString();
      console.error(chunk);
      
      // Update session state if session ID is provided
      if (sessionId) {
        appendSessionOutput(sessionId, 'scan', `ERROR: ${chunk}`);
      }
      
      if (sessionId && io) {
        io.to(sessionId).emit('scanner-output', {
          type: 'scan-error',
          data: chunk
        });
      } else if (io) {
        io.emit('scanner-output', {
          type: 'scan-error',
          data: chunk
        });
      }
    });
    
    process.on('close', (code) => {
      // Try to extract scan ID from the complete output if not found yet
      if (!scanId) {
        // Try different patterns to extract scan ID
        let scanIdMatch = output.match(/Scan ID: (\d+)/);
        if (!scanIdMatch) {
          // Try to extract timestamp-based ID format (e.g., 20250317123851)
          scanIdMatch = output.match(/Running scan with ID: (\d{14})/);
        }
        if (!scanIdMatch) {
          // Look for scan ID in property table format
          scanIdMatch = output.match(/\| Scan ID\s+\|\s+([0-9]{14})\s+\|/);
        }
        if (!scanIdMatch) {
          // Look for a timestamp pattern in the output
          scanIdMatch = output.match(/(\d{14})/);
        }
        if (scanIdMatch) {
          scanId = scanIdMatch[1];
          console.log(`Extracted scan ID from final output: ${scanId}`);
        } else {
          // If we still can't find a scan ID, generate one based on current timestamp
          scanId = new Date().toISOString().replace(/[-:TZ\.]/g, '');
          console.log(`Generated fallback scan ID: ${scanId}`);
        }
      }
      
      // Check if the results file exists before proceeding
      const resultsPath = path.join(__dirname, '../../results', `${scanId}.json`);
      if (!fs.existsSync(resultsPath)) {
        console.warn(`Results file not found at ${resultsPath}, trying to find the correct file...`);
        // Try to find the most recent results file
        const resultsDir = path.join(__dirname, '../../results');
        if (fs.existsSync(resultsDir)) {
          const files = fs.readdirSync(resultsDir)
            .filter(file => file.endsWith('.json') && !file.startsWith('llm_'))
            .sort((a, b) => {
              const statA = fs.statSync(path.join(resultsDir, a));
              const statB = fs.statSync(path.join(resultsDir, b));
              return statB.mtime.getTime() - statA.mtime.getTime(); // Sort by modification time, newest first
            });
          
          if (files.length > 0) {
            const newestFile = files[0];
            scanId = newestFile.replace('.json', '');
            console.log(`Using most recent results file: ${newestFile} with scan ID: ${scanId}`);
          }
        }
      }
      
      // Always consider the scan successful if the exit code is 0
      if (code === 0) {
        // Update session state if session ID is provided
        if (sessionId) {
          updateSessionStatus(sessionId, 'running', {
            currentStep: 'report',
            scanComplete: true,
            scanId: scanId
          });
        }
        
        if (sessionId && io) {
          io.to(sessionId).emit('scanner-status', {
            type: 'scan-complete',
            success: true,
            scanId: scanId
          });
        }
        resolve(scanId);
      } else {
        const errorMessage = `Scan process exited with code ${code}`;
        const error = new Error(errorMessage);
        
        // Update session state if session ID is provided
        if (sessionId) {
          updateSessionStatus(sessionId, 'error', {
            error: error.message,
            scanId: scanId
          });
        }
        
        if (sessionId && io) {
          io.to(sessionId).emit('scanner-status', {
            type: 'scan-complete',
            success: false,
            error: error.message
          });
        }
        reject(error);
      }
    });
  });
}

/**
 * Generate a report for a scan
 * @param {string} scanId - Scan ID
 * @param {string} provider - LLM provider (openai or ollama)
 * @param {string} [sessionId] - Optional session ID for socket communication
 * @returns {Promise<string>} - Path to the generated report
 */
async function generateReport(scanId, provider = 'ollama', sessionId) {
  // First check if the results file exists
  const resultsPath = path.join(__dirname, '../../results', `${scanId}.json`);
  
  // If the specified results file doesn't exist, try to find the most recent one
  if (!fs.existsSync(resultsPath)) {
    console.warn(`Results file not found at ${resultsPath}, trying to find the correct file...`);
    const resultsDir = path.join(__dirname, '../../results');
    
    if (fs.existsSync(resultsDir)) {
      const files = fs.readdirSync(resultsDir)
        .filter(file => file.endsWith('.json') && !file.startsWith('llm_'))
        .sort((a, b) => {
          const statA = fs.statSync(path.join(resultsDir, a));
          const statB = fs.statSync(path.join(resultsDir, b));
          return statB.mtime.getTime() - statA.mtime.getTime(); // Sort by modification time, newest first
        });
      
      if (files.length > 0) {
        const newestFile = files[0];
        scanId = newestFile.replace('.json', '');
        console.log(`Using most recent results file: ${newestFile} with scan ID: ${scanId}`);
      } else {
        return Promise.reject(new Error(`No results files found in ${resultsDir}`));
      }
    } else {
      return Promise.reject(new Error(`Results directory not found at ${resultsDir}`));
    }
  }
  
  // Use absolute path to report_generator.py to ensure it's found
  const reportGeneratorPath = path.join(__dirname, '..', '..', 'report_generator.py');
  const args = [
    reportGeneratorPath,
    'enhance-with-llm',
    '--input', `results/${scanId}.json`,
    '--output', `results/llm_${scanId}.json`,
    '--provider', provider,
    '--remediation',
    '--description'
    // Removed report generation flags to prevent double processing
    // The web interface will generate the report after enhancement
  ];
  
  // Add API key if using OpenAI
  if (provider === 'openai') {
    const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
    if (apiKey) {
      args.push('--api-key', apiKey);
      console.log('Added OpenAI API key to command arguments');
    } else {
      console.log('No OpenAI API key found in environment variables, letting report_generator.py use its fallback mechanism');
    }
  }
  
  // Log the command for debugging
  console.log(`Generating report with command: python3 ${args.join(' ')}`);
  console.log(`Looking for input file: ${path.join(__dirname, '../../results', `${scanId}.json`)}`);
  
  // Check if the results file exists before proceeding
  const reportResultsPath = path.join(__dirname, '../../results', `${scanId}.json`);
  if (!fs.existsSync(reportResultsPath)) {
    console.warn(`Results file not found at ${reportResultsPath}, trying to find the correct file...`);
    return Promise.reject(new Error(`Results file not found: ${reportResultsPath}`));
  }
  
  return new Promise((resolve, reject) => {
    // Don't use cwd parameter, use absolute paths instead
    const process = spawn('python3', args);
    
    // Track the process if session ID is provided
    if (sessionId) {
      activeProcesses[sessionId] = {
        process,
        type: 'report',
        startTime: Date.now(),
        paused: false
      };
    }
    
    let output = '';
    
    process.stdout.on('data', (data) => {
      const chunk = data.toString();
      output += chunk;
      console.log(chunk);
      
      // Update session state if session ID is provided
      if (sessionId) {
        appendSessionOutput(sessionId, 'report', chunk);
      }
      
      // Emit to specific session if provided
      if (sessionId && io) {
        io.to(sessionId).emit('scanner-output', {
          type: 'report',
          data: chunk
        });
      } else if (io) {
        // Broadcast to all clients if no session ID
        io.emit('scanner-output', {
          type: 'report',
          data: chunk
        });
      }
    });
    
    process.stderr.on('data', (data) => {
      const chunk = data.toString();
      console.error(chunk);
      
      // Update session state if session ID is provided
      if (sessionId) {
        appendSessionOutput(sessionId, 'report', `ERROR: ${chunk}`);
      }
      
      if (sessionId && io) {
        io.to(sessionId).emit('scanner-output', {
          type: 'report-error',
          data: chunk
        });
      } else if (io) {
        io.emit('scanner-output', {
          type: 'report-error',
          data: chunk
        });
      }
    });
    
    process.on('close', async (code) => {
      const reportPath = path.join(__dirname, '../../reports', `report_${scanId}.html`);
      
      if (code === 0) {
        // Process enhanced results and store them in Redis
        try {
          const reportManager = require('./report-manager');
          
          // Process enhanced results file
          const enhancedResultsPath = path.join(__dirname, '../../results', `llm_${scanId}.json`);
          console.log(`Processing enhanced results from ${enhancedResultsPath} for Redis storage`);
          
          if (fs.existsSync(enhancedResultsPath)) {
            // Process the enhanced results and store them in Redis
            const result = await reportManager.processEnhancedResults(scanId, enhancedResultsPath, provider, 'gpt-4o');
            
            if (result.success) {
              console.log(`Successfully processed enhanced results for scan ${scanId} and stored in Redis`);
              if (sessionId && io) {
                io.to(sessionId).emit('scanner-output', {
                  type: 'report',
                  data: `Successfully processed enhanced results for scan ${scanId} and stored in Redis\n`
                });
              }
            } else {
              console.error(`Error processing enhanced results: ${result.message}`);
            }
          } else {
            console.error(`Enhanced results file not found at ${enhancedResultsPath}`);
          }
          
          // Generate HTML report from enhanced data
          console.log(`Generating HTML report for scan ${scanId} using web interface...`);
          if (sessionId && io) {
            io.to(sessionId).emit('scanner-output', {
              type: 'report',
              data: `Generating HTML report for scan ${scanId}...\n`
            });
          }
          
          // Generate the HTML report
          const htmlContent = await reportManager.generateHtmlReport(scanId);
          
          // Save the report
          fs.writeFileSync(reportPath, htmlContent);
          
          console.log(`Generated HTML report at ${reportPath}`);
          
          if (fs.existsSync(reportPath)) {
            // Update session state if session ID is provided
            if (sessionId) {
              updateSessionStatus(sessionId, 'complete', {
                reportComplete: true,
                scanId: scanId,
                reportPath: `/reports/report_${scanId}.html`
              });
            }
            
            if (sessionId && io) {
              io.to(sessionId).emit('scanner-status', {
                type: 'report-complete',
                success: true,
                scanId: scanId,
                reportPath: `/reports/report_${scanId}.html`
              });
            }
            resolve(reportPath);
          } else {
            throw new Error('Report file not found after generation');
          }
        } catch (reportError) {
          console.error(`Error generating report: ${reportError.message}`);
          
          if (sessionId && io) {
            io.to(sessionId).emit('scanner-output', {
              type: 'report-error',
              data: `Error generating report: ${reportError.message}\n`
            });
          }
          
          // Even if report generation fails, the enhancement was successful
          const enhancedResultsPath = path.join(__dirname, '../../results', `llm_${scanId}.json`);
          if (fs.existsSync(enhancedResultsPath)) {
            resolve(enhancedResultsPath);
          } else {
            // If enhanced results file also doesn't exist, reject with error
            reject(new Error(`Enhanced results file not found at ${enhancedResultsPath}`));
          }
        }
      } else {
        const error = new Error(`Report generation process exited with code ${code}${!fs.existsSync(reportPath) ? '. Report file not found' : ''}`);
        
        // Update session state if session ID is provided
        if (sessionId) {
          updateSessionStatus(sessionId, 'error', {
            error: error.message,
            scanId: scanId
          });
        }
        
        if (sessionId && io) {
          io.to(sessionId).emit('scanner-status', {
            type: 'report-complete',
            success: false,
            error: error.message
          });
        }
        reject(error);
      }
    });
  });
}

  return {
    generateConfig,
    runScan,
    generateReport,
    stopScan,
    pauseScan,
    resumeScan
  };
};
