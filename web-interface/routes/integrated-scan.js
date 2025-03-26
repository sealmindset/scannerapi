/**
 * Integrated Scan Flow Routes
 * 
 * This module provides routes for the integrated scan flow:
 * 1. Running a security scan (scanner.py)
 * 2. Enhancing results with LLM (report_generator.py)
 * 3. Loading results into Redis for editing (generate_editable_report.py)
 * 4. Redirecting to the report editor
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const { setSession, getSession, appendSessionOutput } = require('../utils/session-store');

// Initialize the router with socket.io and integrated scan flow utility
module.exports = function(io) {
    // Import the integrated scan flow utility
    const { runIntegratedScanFlow, stopProcess } = require('../utils/integrated-scan-flow')(io);
    
    // Route to initiate a scan with the integrated flow
    router.post('/start', async (req, res) => {
        try {
            const { configPath, targetUrl, allowDos, sqlInjection, llmProvider, llmModel } = req.body;
            
            if (!configPath || !targetUrl) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required parameters: configPath and targetUrl'
                });
            }
            
            // Generate a session ID for this scan
            const sessionId = uuidv4();
            
            // Initialize session
            setSession(sessionId, {
                type: 'integrated-scan',
                status: 'initializing',
                startTime: new Date().toISOString(),
                configPath,
                targetUrl,
                allowDos: allowDos === 'true' || allowDos === true,
                sqlInjection: sqlInjection || 'smart',
                llmProvider: llmProvider || 'openai',
                llmModel: llmModel || 'gpt-4o'
            });
            
            // Return the session ID immediately
            res.json({
                success: true,
                sessionId,
                message: 'Integrated scan flow initiated'
            });
            
            // Start the integrated scan flow in the background
            runIntegratedScanFlow({
                configPath,
                targetUrl,
                allowDos: allowDos === 'true' || allowDos === true,
                sqlInjection: sqlInjection || 'smart',
                llmProvider: llmProvider || 'openai',
                llmModel: llmModel || 'gpt-4o',
                sessionId
            }, io).catch(error => {
                console.error('Error in integrated scan flow:', error);
                
                // Update session status
                setSession(sessionId, {
                    status: 'error',
                    error: error.message,
                    endTime: new Date().toISOString()
                });
                
                // Emit error to client
                io.to(sessionId).emit('scanner-status', {
                    type: 'flow-error',
                    success: false,
                    error: error.message
                });
            });
        } catch (error) {
            console.error('Error starting integrated scan flow:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });
    
    // Route to get the status of a scan
    router.get('/status/:sessionId', async (req, res) => {
        try {
            const { sessionId } = req.params;
            const session = getSession(sessionId);
            
            if (!session) {
                return res.status(404).json({
                    success: false,
                    error: 'Session not found'
                });
            }
            
            res.json({
                success: true,
                session
            });
        } catch (error) {
            console.error('Error getting scan status:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });
    
    // Route to stop a scan
    router.post('/stop/:sessionId', async (req, res) => {
        try {
            const { sessionId } = req.params;
            console.log(`Received request to stop scan session: ${sessionId}`);
            
            // Get session info before stopping
            const session = getSession(sessionId);
            if (!session) {
                console.log(`Session ${sessionId} not found`);
                return res.status(404).json({
                    success: false,
                    error: 'Session not found'
                });
            }
            
            console.log(`Attempting to stop process for session ${sessionId}`);
            const success = stopProcess(sessionId);
            
            if (success) {
                console.log(`Successfully stopped process for session ${sessionId}`);
                
                // Update session status
                setSession(sessionId, {
                    status: 'stopped',
                    stoppedAt: new Date().toISOString(),
                    stoppedBy: 'user'
                });
                
                // Notify all clients connected to this session
                io.to(sessionId).emit('scanner-status', {
                    type: 'scan-stopped',
                    success: true,
                    message: 'Scan stopped by user',
                    timestamp: new Date().toISOString()
                });
                
                // Also send a clear message to the scanner output
                io.to(sessionId).emit('scanner-output', {
                    type: 'stop-confirmation',
                    data: '\n\n==== STOP REQUEST CONFIRMED ====\n' +
                          '✅ Scan process has been terminated successfully\n' +
                          `⏱️ Stopped at: ${new Date().toLocaleTimeString()}\n` +
                          '============================\n\n'
                });
                
                res.json({
                    success: true,
                    message: 'Scan stopped successfully'
                });
            } else {
                console.log(`Failed to stop process for session ${sessionId}`);
                
                // Even if stopProcess failed, we'll still update the session status
                // This handles cases where the process might have already exited
                setSession(sessionId, {
                    status: 'stopped',
                    stoppedAt: new Date().toISOString(),
                    stoppedBy: 'user',
                    note: 'Process may have already exited'
                });
                
                // Notify clients
                io.to(sessionId).emit('scanner-status', {
                    type: 'scan-stopped',
                    success: true,
                    message: 'Scan marked as stopped (process may have already exited)',
                    timestamp: new Date().toISOString()
                });
                
                // Also send a clear message to the scanner output
                io.to(sessionId).emit('scanner-output', {
                    type: 'stop-confirmation',
                    data: '\n\n==== STOP REQUEST PROCESSED ====\n' +
                          '⚠️ Process may have already exited\n' +
                          `⏱️ Processed at: ${new Date().toLocaleTimeString()}\n` +
                          '============================\n\n'
                });
                
                // We'll still return success to the client
                res.json({
                    success: true,
                    message: 'Scan marked as stopped (process may have already exited)'
                });
            }
        } catch (error) {
            console.error('Error stopping scan:', error);
            res.status(500).json({
                success: false,
                error: error.message
            });
        }
    });
    
    return router;
};
