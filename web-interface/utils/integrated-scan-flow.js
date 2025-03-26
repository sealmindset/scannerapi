/**
 * Integrated scan flow utility
 * 
 * This module provides a complete workflow for:
 * 1. Running a security scan (scanner.py)
 * 2. Enhancing results with LLM (report_generator.py)
 * 3. Loading results into Redis for editing (generate_editable_report.py)
 * 4. Providing access to the report editor
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const { appendSessionOutput, updateSessionStatus } = require('./session-store');

// Track active processes by session ID
const activeProcesses = {};

/**
 * Run the complete scan flow
 * @param {Object} options - Scan options
 * @param {string} options.configPath - Path to the configuration file
 * @param {string} options.targetUrl - Target URL to scan
 * @param {boolean} options.allowDos - Whether to allow DoS testing
 * @param {string} options.sqlInjection - SQL injection testing mode
 * @param {string} options.llmProvider - LLM provider (openai or ollama)
 * @param {string} options.llmModel - LLM model to use
 * @param {string} options.sessionId - Session ID for socket communication
 * @param {Object} io - Socket.IO instance
 * @returns {Promise<Object>} - Result object with scanId and reportUrl
 */
async function runIntegratedScanFlow(options, io) {
    const { 
        configPath, 
        targetUrl, 
        allowDos, 
        sqlInjection, 
        llmProvider = 'openai',
        llmModel = 'gpt-4o',
        skipEnhancement = false,
        sessionId 
    } = options;

    return new Promise(async (resolve, reject) => {
        try {
            // Step 1: Run the security scan
            const scanId = await runScan(configPath, targetUrl, allowDos, sqlInjection, sessionId, io);
            
            // Check if we should skip LLM enhancement
            if (skipEnhancement) {
                // Update session status to skip enhancement
                if (sessionId) {
                    updateSessionStatus(sessionId, 'loading', { 
                        scanId,
                        stage: 'loading',
                        message: 'Scan complete. Loading results into Redis...'
                    });
                    
                    if (io) {
                        io.to(sessionId).emit('scanner-status', {
                            type: 'scan-complete',
                            success: true,
                            scanId,
                            stage: 'loading',
                            message: 'Scan complete. Loading results into Redis...'
                        });
                    }
                }
                
                // Skip enhancement but still load into Redis
                await prepareEditableReport(scanId, null, null, sessionId, io, true);
            } else {
                // Update session status for enhancement
                if (sessionId) {
                    updateSessionStatus(sessionId, 'enhancing', { 
                        scanId,
                        stage: 'enhancing',
                        message: 'Scan complete. Enhancing results with LLM...'
                    });
                    
                    if (io) {
                        io.to(sessionId).emit('scanner-status', {
                            type: 'scan-complete',
                            success: true,
                            scanId,
                            stage: 'enhancing',
                            message: 'Scan complete. Enhancing results with LLM...'
                        });
                    }
                }
                
                // Step 2 & 3: Enhance results and load into Redis
                await prepareEditableReport(scanId, llmProvider, llmModel, sessionId, io, false);
            }
            
            // Update session status
            if (sessionId) {
                updateSessionStatus(sessionId, 'complete', { 
                    scanId,
                    stage: 'complete',
                    message: 'Report ready for editing',
                    reportUrl: `/report-editor/editor/${scanId}`
                });
                
                if (io) {
                    io.to(sessionId).emit('scanner-status', {
                        type: 'flow-complete',
                        success: true,
                        scanId,
                        stage: 'complete',
                        message: 'Report ready for editing',
                        reportUrl: `/report-editor/editor/${scanId}`
                    });
                }
            }
            
            resolve({
                scanId,
                reportUrl: `/report-editor/editor/${scanId}`
            });
        } catch (error) {
            console.error('Error in integrated scan flow:', error);
            
            // Update session status
            if (sessionId) {
                updateSessionStatus(sessionId, 'error', { 
                    error: error.message
                });
                
                if (io) {
                    io.to(sessionId).emit('scanner-status', {
                        type: 'flow-error',
                        success: false,
                        error: error.message
                    });
                }
            }
            
            reject(error);
        }
    });
}

/**
 * Run a scan using the API Security Scanner
 * @param {string} configPath - Path to the configuration file
 * @param {string} targetUrl - Target URL to scan
 * @param {boolean} allowDos - Whether to allow DoS testing
 * @param {string} sqlInjection - SQL injection testing mode
 * @param {string} sessionId - Session ID for socket communication
 * @param {Object} io - Socket.IO instance
 * @returns {Promise<string>} - Scan ID
 */
function runScan(configPath, targetUrl, allowDos, sqlInjection, sessionId, io) {
    const dosFlag = allowDos ? 'true' : 'false';
    // Use absolute path to scanner.py to ensure it's found
    const scannerPath = path.join(__dirname, '..', '..', 'scanner.py');
    const args = [
        scannerPath,
        '--config', configPath,
        '--url', targetUrl,
        '--dos', dosFlag,
        '--sqlintensity', sqlInjection || 'smart'
    ];
    
    return new Promise((resolve, reject) => {
        // Use the root directory as cwd to ensure the script is found and results are saved in the correct location
        const rootDir = path.join(__dirname, '..', '..');
        console.log(`Working directory for scanner: ${rootDir}`);
        
        const scannerProcess = spawn('python3', args, {
            cwd: rootDir
        });
        
        // Track the process if session ID is provided
        if (sessionId) {
            activeProcesses[sessionId] = {
                process: scannerProcess,
                type: 'scan',
                startTime: Date.now(),
                paused: false
            };
        }
        
        let output = '';
        let scanId = null;
        
        scannerProcess.stdout.on('data', (data) => {
            const chunk = data.toString();
            output += chunk;
            console.log(`Scanner stdout: ${chunk}`);
            
            // Try to extract scan ID from the output
            const scanIdMatch = chunk.match(/Scan ID: (\d+)/);
            // Also look for timestamp format IDs (e.g., 20250317160541)
            const timestampMatch = chunk.match(/Scan ID:\s+([0-9]{14})/);
            const propertyMatch = chunk.match(/\| Scan ID\s+\|\s+([0-9]{14})\s+\|/);
            // Look for scan_id in JSON output
            const jsonMatch = chunk.match(/"scan_id":\s*"([0-9]{14})"/);
            // Look for saving results message
            const saveMatch = chunk.match(/Saving results to (.+)/);
            // Look for results saved message
            const resultsSavedMatch = chunk.match(/Results saved to: (.+)/);
            
            if (saveMatch) {
                console.log(`Scanner is saving results to: ${saveMatch[1]}`);
            }
            
            if (resultsSavedMatch) {
                console.log(`Scanner saved results to: ${resultsSavedMatch[1]}`);
            }
            
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
            } else if (jsonMatch) {
                scanId = jsonMatch[1];
                console.log(`Extracted scan ID from JSON output: ${scanId}`);
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
        
        scannerProcess.stderr.on('data', (data) => {
            const chunk = data.toString();
            console.error(`Scanner stderr: ${chunk}`);
            
            // Update session state if session ID is provided
            if (sessionId) {
                appendSessionOutput(sessionId, 'scan-error', chunk);
            }
            
            // Emit to specific session if provided
            if (sessionId && io) {
                io.to(sessionId).emit('scanner-output', {
                    type: 'scan-error',
                    data: chunk
                });
            } else if (io) {
                // Broadcast to all clients if no session ID
                io.emit('scanner-output', {
                    type: 'scan-error',
                    data: chunk
                });
            }
        });
        
        scannerProcess.on('error', (error) => {
            console.error(`Scanner process error: ${error.message}`);
            reject(error);
        });
        
        scannerProcess.on('close', (code) => {
            console.log(`Scanner process exited with code ${code}`);
            
            // Clean up process tracking
            if (sessionId) {
                delete activeProcesses[sessionId];
            }
            
            if (code === 0) {
                if (!scanId) {
                    // Try to extract scan ID from the full output if not already found
                    const scanIdMatch = output.match(/Scan ID: (\d+)/);
                    const timestampMatch = output.match(/Scan ID:\s+([0-9]{14})/);
                    const propertyMatch = output.match(/\| Scan ID\s+\|\s+([0-9]{14})\s+\|/);
                    
                    if (scanIdMatch) {
                        scanId = scanIdMatch[1];
                    } else if (timestampMatch) {
                        scanId = timestampMatch[1];
                    } else if (propertyMatch) {
                        scanId = propertyMatch[1];
                    } else {
                        // Try to extract scan ID from the output by looking for results file path
                        const resultPathMatch = output.match(/Results saved to: (.+\/([0-9]{14})\.json)/);
                        const resultWriteMatch = output.match(/Writing results to: (.+\/([0-9]{14})\.json)/);
                        
                        if (resultPathMatch) {
                            const [_, fullPath, extractedId] = resultPathMatch;
                            scanId = extractedId;
                            console.log(`Extracted scan ID from result path: ${scanId}`);
                            console.log(`Result file path: ${fullPath}`);
                            
                            // Verify the file exists
                            if (fs.existsSync(fullPath)) {
                                console.log(`Verified result file exists at: ${fullPath}`);
                            } else {
                                console.log(`Warning: Result file not found at: ${fullPath}`);
                            }
                        } else if (resultWriteMatch) {
                            const [_, fullPath, extractedId] = resultWriteMatch;
                            scanId = extractedId;
                            console.log(`Extracted scan ID from write path: ${scanId}`);
                            console.log(`Result file path: ${fullPath}`);
                            
                            // Verify the file exists
                            if (fs.existsSync(fullPath)) {
                                console.log(`Verified result file exists at: ${fullPath}`);
                            } else {
                                console.log(`Warning: Result file not found at: ${fullPath}`);
                            }
                        }
                        
                        // If still no scan ID, try to find the most recent results file
                        if (!scanId) {
                            const resultsDir = path.join(__dirname, '../../results');
                            console.log('Looking for scan results in directory:', resultsDir);
                            
                            if (fs.existsSync(resultsDir)) {
                                // Create the directory if it doesn't exist
                                try {
                                    // List all files in the results directory for debugging
                                    const allFiles = fs.readdirSync(resultsDir);
                                    console.log('All files in results directory:', allFiles);
                                    
                                    // Filter and sort files to find the most recent scan result
                                    const files = allFiles
                                        .filter(file => file.endsWith('.json') && !file.includes('enhanced') && !file.includes('llm'))
                                        .sort((a, b) => {
                                            const statA = fs.statSync(path.join(resultsDir, a));
                                            const statB = fs.statSync(path.join(resultsDir, b));
                                            return statB.mtime.getTime() - statA.mtime.getTime(); // Sort by modification time, newest first
                                        });
                                    
                                    console.log('Filtered scan result files:', files);
                                    
                                    if (files.length > 0) {
                                        scanId = files[0].replace('.json', '');
                                        console.log(`Using most recent results file: ${files[0]} with scan ID: ${scanId}`);
                                    } else {
                                        console.log('No suitable scan result files found');
                                    }
                                } catch (err) {
                                    console.error(`Error reading results directory: ${err.message}`);
                                }
                            } else {
                                console.log(`Results directory not found: ${resultsDir}`);
                                // Try to create the results directory
                                try {
                                    fs.mkdirSync(resultsDir, { recursive: true });
                                    console.log(`Created results directory: ${resultsDir}`);
                                } catch (err) {
                                    console.error(`Error creating results directory: ${err.message}`);
                                }
                            }
                        }
                    }
                }
                
                if (scanId) {
                    resolve(scanId);
                } else {
                    reject(new Error('Scan completed but could not determine scan ID'));
                }
            } else {
                reject(new Error(`Scanner process exited with code ${code}`));
            }
        });
        
        process.on('error', (error) => {
            console.error(`Error running scanner: ${error.message}`);
            
            // Clean up process tracking
            if (sessionId) {
                delete activeProcesses[sessionId];
            }
            
            reject(error);
        });
    });
}

/**
 * Helper function to wait for a file to exist
 * @param {string} filePath - Absolute path to the file
 * @param {number} timeout - Timeout in milliseconds
 * @param {number} interval - Check interval in milliseconds
 * @returns {Promise<boolean>} - Resolves to true if file exists, rejects if timeout
 */
function waitForFile(filePath, timeout = 5000, interval = 200) {
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        const checkFile = () => {
            // Check if file exists
            if (fs.existsSync(filePath)) {
                console.log(`File found: ${filePath}`);
                return resolve(true);
            }
            
            // Check if timeout has been reached
            if (Date.now() - startTime >= timeout) {
                return reject(new Error(`Timeout waiting for file: ${filePath}`));
            }
            
            // Check again after interval
            setTimeout(checkFile, interval);
        };
        
        // Start checking
        checkFile();
    });
}

/**
 * Prepare an editable report by enhancing scan results and loading into Redis
 * @param {string} scanId - Scan ID
 * @param {string} provider - LLM provider (openai or ollama)
 * @param {string} model - LLM model to use
 * @param {string} sessionId - Session ID for socket communication
 * @param {Object} io - Socket.IO instance
 * @param {boolean} skipEnhancement - Whether to skip LLM enhancement
 * @returns {Promise<void>}
 */
/**
 * Wait for a file to exist with a timeout
 * @param {string} filePath - The absolute path to the file to wait for
 * @param {number} timeout - The maximum time to wait in milliseconds
 * @param {number} interval - The interval between checks in milliseconds
 * @returns {Promise<void>} - Resolves when the file exists, rejects on timeout
 */
function waitForFile(filePath, timeout = 5000, interval = 200) {
    return new Promise((resolve, reject) => {
        // Check if the file already exists
        if (fs.existsSync(filePath)) {
            console.log(`File already exists: ${filePath}`);
            return resolve();
        }
        
        console.log(`Waiting for file to exist: ${filePath}`);
        console.log(`Timeout: ${timeout}ms, Check interval: ${interval}ms`);
        
        const startTime = Date.now();
        const checkInterval = setInterval(() => {
            // Check if the file exists
            if (fs.existsSync(filePath)) {
                clearInterval(checkInterval);
                console.log(`File found after ${Date.now() - startTime}ms: ${filePath}`);
                resolve();
                return;
            }
            
            // Check if we've timed out
            if (Date.now() - startTime > timeout) {
                clearInterval(checkInterval);
                const error = new Error(`Timeout waiting for file: ${filePath}`);
                console.error(error.message);
                reject(error);
                return;
            }
            
            console.log(`File not found yet, waiting... (${Date.now() - startTime}ms elapsed)`);
        }, interval);
    });
}

function prepareEditableReport(scanId, provider = 'openai', model = 'gpt-4o', sessionId, io, skipEnhancement = false) {
    return new Promise((resolve, reject) => {
        // Define the absolute path to the results file
        const rootDir = path.join(__dirname, '..', '..');
        const resultsFile = path.join(rootDir, 'results', `${scanId}.json`);
        
        console.log(`Checking for results file: ${resultsFile}`);
        
        // Wait for the results file to exist before proceeding
        waitForFile(resultsFile, 5000, 200)
            .then(() => {
                console.log(`Results file found, proceeding with report generation: ${resultsFile}`);
                
                // Prepare arguments for the generate_editable_report.py script
                let args = [];
                
                // Determine if we should skip LLM enhancement
                if (skipEnhancement) {
                    // Update the UI to show we're skipping enhancement
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'enhance',
                            data: 'Skipping LLM enhancement as requested.\n'
                        });
                        
                        io.to(sessionId).emit('scanner-status', {
                            type: 'enhance',
                            success: true,
                            output: 'LLM enhancement skipped.'
                        });
                    }
                    
                    // Use the generate_editable_report.py script with --skip-enhancement flag
                    // Use absolute path to generate_editable_report.py to ensure it's found
                    const scriptPath = path.resolve(path.join(__dirname, '..', '..', 'generate_editable_report.py'));
                    console.log(`Using script path: ${scriptPath}`);
                    
                    // Check if the script exists
                    if (!fs.existsSync(scriptPath)) {
                        console.error(`Script not found at: ${scriptPath}`);
                        return reject(new Error(`Script not found at: ${scriptPath}`));
                    }
            
                    // Don't include the full path in the args, we'll use cwd instead
                    args = [
                        'generate_editable_report.py',
                        '--scan-id', scanId,
                        '--skip-enhance',
                        '--no-launch-web' // Don't launch the web interface since it's already running
                    ];
                } else {
                    // Use the report_generator.py script with LLM enhancement
                    // This follows the enhance-with-llm command pattern from the memory
                    
                    // Use absolute path to report_generator.py to ensure it's found
                    const reportGeneratorPath = path.resolve(path.join(__dirname, '..', '..', 'report_generator.py'));
                    console.log(`Using report generator path: ${reportGeneratorPath}`);
                    
                    // Check if the script exists
                    if (!fs.existsSync(reportGeneratorPath)) {
                        console.error(`Script not found at: ${reportGeneratorPath}`);
                        return reject(new Error(`Script not found at: ${reportGeneratorPath}`));
                    }
                    
                    // Define input and output files with absolute paths
                    const inputFile = path.join(rootDir, 'results', `${scanId}.json`);
                    const outputFile = path.join(rootDir, 'results', `${scanId}_enhanced.json`);
                    const reportOutputFile = path.join(rootDir, 'reports', `${scanId}.html`);
                    
                    console.log(`Input file: ${inputFile}`);
                    console.log(`Output file: ${outputFile}`);
                    console.log(`Report output file: ${reportOutputFile}`);
                    
                    // Don't include the full path in the args, we'll use cwd instead
                    args = [
                        'report_generator.py',
                        'enhance-with-llm',
                        '--input', `results/${scanId}.json`,
                        '--output', `results/${scanId}_enhanced.json`,
                        '--provider', provider,
                        '--model', model,
                        '--generate-report',
                        '--report-format', 'html',
                        '--report-output', `reports/${scanId}.html`
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
                }
                
                // Log the command being executed
                console.log(`Running command: python3 ${args.join(' ')}`);
                
                // Use the root directory as cwd to ensure the script is found
                const pythonProcess = spawn('python3', args, {
                    cwd: rootDir
                });
                
                // Track the process if session ID is provided
                if (sessionId) {
                    activeProcesses[sessionId] = {
                        process: pythonProcess,
                        type: 'prepare-report',
                        startTime: Date.now(),
                        paused: false
                    };
                }
                
                let output = '';
                
                pythonProcess.stdout.on('data', (data) => {
                    const chunk = data.toString();
                    output += chunk;
                    console.log(`Report generator stdout: ${chunk}`);
                    
                    // Update session state if session ID is provided
                    if (sessionId) {
                        appendSessionOutput(sessionId, 'prepare-report', chunk);
                    }
                    
                    // Emit to specific session if provided
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'prepare-report',
                            data: chunk
                        });
                    }
                });
        
                pythonProcess.stderr.on('data', (data) => {
                    const chunk = data.toString();
                    console.error(`Report generator stderr: ${chunk}`);
                    
                    // Update session state if session ID is provided
                    if (sessionId) {
                        appendSessionOutput(sessionId, 'prepare-report-error', chunk);
                    }
                    
                    // Emit to specific session if provided
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'prepare-report-error',
                            data: chunk
                        });
                    }
                });
        
                pythonProcess.on('close', async (code) => {
                    console.log(`Prepare report process exited with code ${code}`);
                    
                    // Clean up process tracking
                    if (sessionId) {
                        delete activeProcesses[sessionId];
                    }
                    
                    if (code === 0) {
                        // Process enhanced results and store them in Redis
                        try {
                            const enhancedResultsPath = path.join(rootDir, 'results', `${scanId}_enhanced.json`);
                            console.log(`Processing enhanced results from ${enhancedResultsPath} for Redis storage`);
                            
                            if (fs.existsSync(enhancedResultsPath)) {
                                // Import the report-manager module
                                const { processEnhancedResults } = require('./report-manager');
                                
                                // Process the enhanced results and store them in Redis
                                const result = await processEnhancedResults(scanId, enhancedResultsPath, provider, model);
                                
                                if (result.success) {
                                    console.log(`Successfully processed enhanced results for scan ${scanId} and stored in Redis`);
                                } else {
                                    console.error(`Error processing enhanced results: ${result.message}`);
                                }
                            } else {
                                console.error(`Enhanced results file not found at ${enhancedResultsPath}`);
                            }
                        } catch (error) {
                            console.error(`Error processing enhanced results: ${error.message}`);
                        }
                        
                        // Emit success status updates for both LLM enhancement and report generation
                        if (sessionId && io) {
                            // Update LLM enhancement status
                            io.to(sessionId).emit('scanner-status', {
                                type: 'enhance',
                                success: true,
                                stage: 'complete',
                                message: 'LLM enhancement completed successfully',
                                output: 'LLM enhancement completed successfully'
                            });
                            
                            // Update report generation status
                            io.to(sessionId).emit('scanner-status', {
                                type: 'prepare-report',
                                success: true,
                                stage: 'complete',
                                message: 'Report generation completed successfully',
                                output: 'Report ready for editing',
                                scanId: scanId
                            });
                        }
                        resolve();
                    } else {
                        // Emit failure status updates
                        if (sessionId && io) {
                            io.to(sessionId).emit('scanner-status', {
                                type: 'prepare-report',
                                success: false,
                                stage: 'error',
                                message: `Prepare report process exited with code ${code}`,
                                output: `Error: Prepare report process exited with code ${code}`
                            });
                        }
                        reject(new Error(`Prepare report process exited with code ${code}`));
                    }
                });
        
                pythonProcess.on('error', (error) => {
                    console.error(`Error preparing report: ${error.message}`);
                    
                    // Clean up process tracking
                    if (sessionId) {
                        delete activeProcesses[sessionId];
                    }
                    
                    // Emit error status updates for both LLM enhancement and report generation
                    if (sessionId && io) {
                        // Update LLM enhancement status
                        io.to(sessionId).emit('scanner-status', {
                            type: 'enhance',
                            success: false,
                            stage: 'error',
                            message: `Error preparing report: ${error.message}`,
                            output: `Error: ${error.message}`
                        });
                        
                        // Update report generation status
                        io.to(sessionId).emit('scanner-status', {
                            type: 'prepare-report',
                            success: false,
                            stage: 'error',
                            message: `Error preparing report: ${error.message}`,
                            output: `Error: ${error.message}`
                        });
                    }
                    
                    reject(error);
                });
            })
            .catch((error) => {
                console.error(`Error waiting for results file: ${error.message}`);
                
                // Emit error status updates
                if (sessionId && io) {
                    io.to(sessionId).emit('scanner-status', {
                        type: 'prepare-report',
                        success: false,
                        stage: 'error',
                        message: `Error finding results file: ${error.message}`,
                        output: `Error: ${error.message}`
                    });
                }
                
                reject(error);
            });
    });
}

/**
 * Stop an active process
 * @param {string} sessionId - Session ID
 * @returns {boolean} - Whether the process was successfully stopped
 */
function stopProcess(sessionId) {
    // Print a highly visible message in the console
    console.log('\n=========================================');
    console.log(`🛑 STOP REQUEST RECEIVED FOR SESSION: ${sessionId}`);
    console.log('=========================================\n');
    
    if (!activeProcesses[sessionId]) {
        console.log(`❌ No active process found for session ${sessionId}`);
        return false;
    }
    
    try {
        console.log(`🔄 Attempting to stop process for session ${sessionId}`);
        
        // Get the process
        const processInfo = activeProcesses[sessionId];
        
        // Force kill the process with SIGKILL to ensure it stops
        processInfo.process.kill('SIGKILL');
        
        // On macOS/Linux, we can also try to kill the entire process group
        try {
            // This is a more aggressive approach to kill child processes
            const pid = processInfo.process.pid;
            if (pid) {
                console.log(`Killing process group for PID ${pid}`);
                // Use process.kill to send signal to process group (-pid)
                process.kill(-pid, 'SIGKILL');
            }
        } catch (groupError) {
            // This might fail if we don't have permission or if the process is already gone
            console.log(`Note: Could not kill process group: ${groupError.message}`);
        }
        
        // Update session status
        updateSessionStatus(sessionId, 'stopped', {
            stoppedAt: new Date().toISOString(),
            stoppedBy: 'user'
        });
        
        // Clean up
        delete activeProcesses[sessionId];
        
        console.log(`Process for session ${sessionId} stopped successfully`);
        return true;
    } catch (error) {
        console.error(`Error stopping process ${sessionId}:`, error);
        return false;
    }
}

/**
 * Re-enhance existing scan results using the report_generator.py enhance-with-llm command
 * @param {string} scanId - Scan ID to re-enhance
 * @param {string} provider - LLM provider (openai or ollama)
 * @param {string} model - LLM model to use
 * @param {string} sessionId - Session ID for socket communication
 * @param {Object} io - Socket.IO instance
 * @returns {Promise<Object>} - Result object with success status and message
 */
async function reEnhanceScanResults(scanId, provider = 'openai', model = 'gpt-4o', sessionId, io) {
    console.log(`[${new Date().toISOString()}] Starting re-enhancement for scan ${scanId} with provider ${provider} and model ${model}`);
    
    // Log to a file for debugging
    const logFilePath = path.join(__dirname, '..', '..', 'logs', 'enhance.log');
    try {
        // Create logs directory if it doesn't exist
        const logsDir = path.join(__dirname, '..', '..', 'logs');
        if (!fs.existsSync(logsDir)) {
            fs.mkdirSync(logsDir, { recursive: true });
        }
        
        // Append to log file
        fs.appendFileSync(logFilePath, `\n[${new Date().toISOString()}] Starting re-enhancement for scan ${scanId} with provider ${provider} and model ${model}\n`);
    } catch (err) {
        console.error(`Error writing to log file: ${err.message}`);
    }
    return new Promise((resolve, reject) => {
        // Prepare paths for input and output files
        const inputPath = path.join(__dirname, '../../results', `${scanId}.json`);
        const outputPath = path.join(__dirname, '../../results', `${scanId}_enhanced.json`);
        const reportPath = path.join(__dirname, '../../reports', `report_${scanId}.html`);
        
        // Check if the input file exists
        if (!fs.existsSync(inputPath)) {
            if (sessionId && io) {
                io.to(sessionId).emit('scanner-output', {
                    type: 'enhance',
                    data: `Error: Could not find scan results file for scan ID ${scanId}\n`
                });
                
                io.to(sessionId).emit('scanner-status', {
                    type: 'enhance',
                    success: false,
                    output: 'Error: Scan results file not found'
                });
            }
            return reject(new Error(`Could not find scan results file for scan ID ${scanId}`));
        }
        
        // Update the UI to show we're starting enhancement
        if (sessionId && io) {
            io.to(sessionId).emit('scanner-output', {
                type: 'enhance',
                data: `Starting LLM enhancement for scan ${scanId} using ${provider}/${model}...\n`
            });
            
            io.to(sessionId).emit('scanner-status', {
                type: 'enhance',
                success: true,
                output: 'LLM enhancement started'
            });
        }
        
        // Prepare arguments for the report_generator.py enhance-with-llm command
        // Use absolute path to report_generator.py to ensure it's found
        const reportGeneratorPath = path.resolve(path.join(__dirname, '..', '..', 'report_generator.py'));
        console.log(`Using report generator path: ${reportGeneratorPath}`);
        console.log(`Input path: ${inputPath}`);
        console.log(`Output path: ${outputPath}`);
        
        // Check if the report_generator.py file exists
        if (!fs.existsSync(reportGeneratorPath)) {
            console.error(`Report generator script not found at: ${reportGeneratorPath}`);
            return reject(new Error(`Report generator script not found at: ${reportGeneratorPath}`));
        }
        
        // Check if the input file exists
        if (!fs.existsSync(inputPath)) {
            console.error(`Input file does not exist: ${inputPath}`);
            // Try to create an empty results directory if it doesn't exist
            const resultsDir = path.dirname(inputPath);
            if (!fs.existsSync(resultsDir)) {
                try {
                    fs.mkdirSync(resultsDir, { recursive: true });
                    console.log(`Created results directory: ${resultsDir}`);
                } catch (err) {
                    console.error(`Error creating results directory: ${err.message}`);
                }
            }
            return reject(new Error(`Input file does not exist: ${inputPath}`));
        }
        
        // Build the command arguments
        const args = [
            // Don't include the full path in the args, we'll use cwd instead
            'report_generator.py',
            'enhance-with-llm',
            '--input', inputPath,
            '--output', outputPath,
            '--provider', provider,
            '--model', model,
            // Add report generation flags to ensure a report is generated
            '--generate-report',
            '--report-format', 'html',
            '--report-output', reportPath
        ];
        
        // Log the command to the enhance.log file
        try {
            fs.appendFileSync(logFilePath, `Command: python3 ${args.join(' ')}\n`);
        } catch (err) {
            console.error(`Error writing to log file: ${err.message}`);
        }
        
        // Add API key if using OpenAI
        if (provider === 'openai') {
            const apiKey = process.env.LLM_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
            if (apiKey) {
                args.push('--api-key', apiKey);
            }
        }
        
        console.log(`Running command: python3 ${args.join(' ')}`);
        
        // Use the root directory as cwd to ensure the script is found
        const rootDir = path.join(__dirname, '..', '..');
        console.log(`Working directory: ${rootDir}`);
        
        const pythonProcess = spawn('python3', args, { 
            cwd: rootDir
        });
        
        // Store the process in the active processes map
        if (sessionId) {
            activeProcesses[sessionId] = {
                process: pythonProcess,
                type: 'enhance',
                startTime: Date.now(),
                paused: false
            };
        }
        
        let output = '';
        
        pythonProcess.stdout.on('data', (data) => {
            const chunk = data.toString();
            output += chunk;
            
            // Send output to the client
            if (sessionId && io) {
                io.to(sessionId).emit('scanner-output', {
                    type: 'enhance',
                    data: chunk
                });
            }
            
            // Log to console and file
            console.log(`[Enhance] ${chunk}`);
            try {
                fs.appendFileSync(logFilePath, `[STDOUT] ${chunk}`);
            } catch (err) {
                console.error(`Error writing to log file: ${err.message}`);
            }
        });
        
        pythonProcess.stderr.on('data', (data) => {
            const chunk = data.toString();
            output += chunk;
            
            // Send output to the client
            if (sessionId && io) {
                io.to(sessionId).emit('scanner-output', {
                    type: 'enhance',
                    data: chunk
                });
            }
            
            // Log to console and file
            console.error(`[Enhance Error] ${chunk}`);
            try {
                fs.appendFileSync(logFilePath, `[STDERR] ${chunk}`);
            } catch (err) {
                console.error(`Error writing to log file: ${err.message}`);
            }
        });
        
        pythonProcess.on('error', (error) => {
            console.error(`Error enhancing with LLM: ${error.message}`);
            
            // Clean up process tracking
            if (sessionId) {
                delete activeProcesses[sessionId];
            }
            
            // Emit error status updates
            if (sessionId && io) {
                io.to(sessionId).emit('scanner-status', {
                    type: 'enhance',
                    success: false,
                    stage: 'error',
                    message: `Error enhancing with LLM: ${error.message}`,
                    output: `Error: ${error.message}`
                });
            }
            
            reject(error);
        });
        
        pythonProcess.on('close', async (code) => {
            // Remove from active processes
            if (sessionId) {
                delete activeProcesses[sessionId];
            }
            
            // Log process completion
            const completionMsg = `Python process exited with code ${code}`;
            console.log(`[${new Date().toISOString()}] ${completionMsg}`);
            try {
                fs.appendFileSync(logFilePath, `\n${completionMsg}\n`);
            } catch (err) {
                console.error(`Error writing to log file: ${err.message}`);
            }
            
            if (code === 0) {
                // Enhancement successful
                if (sessionId && io) {
                    io.to(sessionId).emit('scanner-output', {
                        type: 'enhance',
                        data: 'LLM enhancement completed successfully.\n'
                    });
                }
                
                // Check if the enhanced results file exists
                if (!fs.existsSync(outputPath)) {
                    const errorMsg = `Enhanced results file not found at ${outputPath}`;
                    console.error(errorMsg);
                    try {
                        fs.appendFileSync(logFilePath, `ERROR: ${errorMsg}\n`);
                    } catch (err) {
                        console.error(`Error writing to log file: ${err.message}`);
                    }
                    
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'enhance',
                            data: `${errorMsg}\n`,
                            error: true
                        });
                    }
                    
                    reject(new Error(errorMsg));
                    return;
                }
                
                // Process the enhanced results and store them in Redis
                try {
                    const reportManager = require('./report-manager');
                    
                    // Process enhanced results
                    console.log(`Processing enhanced results for scan ${scanId}...`);
                    try {
                        fs.appendFileSync(logFilePath, `Processing enhanced results for scan ${scanId}...\n`);
                    } catch (err) {
                        console.error(`Error writing to log file: ${err.message}`);
                    }
                    
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'enhance',
                            data: `Processing enhanced results for scan ${scanId}...\n`
                        });
                    }
                    
                    // Process the enhanced results and store them in Redis
                    const processed = await reportManager.processEnhancedResults(scanId, outputPath);
                    console.log(`Processed enhanced results: ${processed ? 'Success' : 'Failed'}`);
                    try {
                        fs.appendFileSync(logFilePath, `Processed enhanced results: ${processed ? 'Success' : 'Failed'}\n`);
                    } catch (err) {
                        console.error(`Error writing to log file: ${err.message}`);
                    }
                    
                    // Generate HTML report from enhanced data
                    console.log(`Generating HTML report for scan ${scanId} using web interface...`);
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'enhance',
                            data: `Generating HTML report for scan ${scanId}...\n`
                        });
                    }
                    
                    // Generate the HTML report
                    const htmlContent = await reportManager.generateHtmlReport(scanId);
                    
                    // Save the report
                    fs.writeFileSync(reportPath, htmlContent);
                    
                    console.log(`Generated HTML report at ${reportPath}`);
                    try {
                        fs.appendFileSync(logFilePath, `Generated HTML report at ${reportPath}\n`);
                    } catch (err) {
                        console.error(`Error writing to log file: ${err.message}`);
                    }
                    
                    // Notify the client
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'enhance',
                            data: `Generated HTML report at ${reportPath}\n`
                        });
                        
                        io.to(sessionId).emit('scanner-status', {
                            type: 'enhance',
                            success: true,
                            output: 'LLM enhancement and report generation completed'
                        });
                        
                        // Update session state
                        io.to(sessionId).emit('scan-session-state', {
                            status: 'complete',
                            scanId: scanId,
                            reportPath: reportPath
                        });
                    }
                    
                    resolve({
                        success: true,
                        message: 'LLM enhancement and report generation completed successfully',
                        scanId: scanId,
                        reportPath: reportPath
                    });
                } catch (reportError) {
                    console.error(`Error generating report: ${reportError.message}`);
                    
                    if (sessionId && io) {
                        io.to(sessionId).emit('scanner-output', {
                            type: 'enhance',
                            data: `Error generating report: ${reportError.message}\n`,
                            error: true
                        });
                    }
                    
                    // Even if report generation fails, the enhancement was successful
                    resolve({
                        success: true,
                        message: 'LLM enhancement completed, but report generation failed',
                        scanId: scanId,
                        error: reportError.message
                    });
                }
            } else {
                // Enhancement failed
                const errorMessage = `LLM enhancement failed with exit code ${code}`;
                
                if (sessionId && io) {
                    io.to(sessionId).emit('scanner-output', {
                        type: 'enhance',
                        data: `${errorMessage}\n`
                    });
                    
                    io.to(sessionId).emit('scanner-status', {
                        type: 'enhance',
                        success: false,
                        output: errorMessage
                    });
                }
                
                reject(new Error(errorMessage));
            }
        });
    });
}

/**
 * Generate an HTML report from existing enhanced results
 * @param {string} scanId - Scan ID to generate report for
 * @param {string} [customInputPath] - Optional custom path to the enhanced results file
 * @param {string} [customOutputPath] - Optional custom path for the generated report
 * @returns {Promise<Object>} - Result object with success status and message
 */
async function generateReportFromEnhancedResults(scanId, customInputPath, customOutputPath) {
    return new Promise((resolve, reject) => {
        // Prepare paths for input and output files
        const enhancedResultsPath = customInputPath || path.join(__dirname, '../../results', `${scanId}_enhanced.json`);
        const reportPath = customOutputPath || path.join(__dirname, '../../reports', `report_${scanId}.html`);
        
        console.log(`Generating report with input: ${enhancedResultsPath} and output: ${reportPath}`);
        
        // Check if the enhanced results file exists
        if (!fs.existsSync(enhancedResultsPath)) {
            return reject(new Error(`Could not find enhanced results file at ${enhancedResultsPath}`));
        }
        
        console.log(`Generating report from enhanced results for scan ${scanId}...`);
        
        // Prepare arguments for the report_generator.py quick-report command
        // The first argument after 'quick-report' must be the scanId (positional argument)
        // Extract the filename without extension to use as scanId if needed
        const enhancedFileName = path.basename(enhancedResultsPath, '.json');
        // Use absolute path to report_generator.py to ensure it's found
        const reportGeneratorPath = path.join(__dirname, '..', '..', 'report_generator.py');
        const args = [
            reportGeneratorPath,
            'quick-report',
            scanId, // Use the provided scanId as the positional argument
            '--format', 'html',
            '--output', reportPath
        ];
        
        // Don't use cwd parameter, use absolute paths instead
        const pythonProcess = spawn('python3', args);
        
        let output = '';
        
        pythonProcess.stdout.on('data', (data) => {
            const chunk = data.toString();
            output += chunk;
            console.log(`[Report Generator] ${chunk}`);
        });
        
        pythonProcess.stderr.on('data', (data) => {
            const chunk = data.toString();
            output += chunk;
            console.error(`[Report Generator Error] ${chunk}`);
        });
        
        pythonProcess.on('error', (error) => {
            console.error(`Error generating report: ${error.message}`);
            reject(new Error(`Error generating report: ${error.message}`));
        });
        
        pythonProcess.on('close', (code) => {
            if (code === 0) {
                // Report generation successful
                console.log(`Report generation completed successfully for scan ${scanId}`);
                resolve({
                    success: true,
                    message: 'Report generation completed successfully',
                    scanId: scanId,
                    reportPath: reportPath
                });
            } else {
                // Report generation failed
                const errorMessage = `Report generation failed with exit code ${code}`;
                console.error(errorMessage);
                reject(new Error(errorMessage));
            }
        });
    });
}

module.exports = function(io) {
    return {
        runIntegratedScanFlow,
        stopProcess,
        reEnhanceScanResults,
        generateReportFromEnhancedResults
    };
};
