/**
 * Report Editor Routes
 * 
 * This module provides routes for:
 * 1. Viewing and editing reports
 * 2. Saving edited report content to Redis
 * 3. Generating and downloading reports in various formats
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { 
  generateEnhancedContent, 
  getVulnerabilityData, 
  updateVulnerabilityField,
  generateHtmlReport,
  saveReport
} = require('../utils/report-manager');

// Route to view report editor
router.get('/editor/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Get vulnerability data from Redis
    let reportData = await getVulnerabilityData(scanId);
    
    if (!reportData.metadata || Object.keys(reportData.metadata).length === 0) {
      // If no data in Redis, try to generate it
      const inputFile = path.join(__dirname, `../../results/${scanId}.json`);
      
      if (!fs.existsSync(inputFile)) {
        return res.status(404).render('error', {
          message: `Scan results not found for ID: ${scanId}`,
          error: { status: 404 }
        });
      }
      
      // Generate enhanced content using OpenAI
      const result = await generateEnhancedContent(scanId);
      
      if (!result.success) {
        return res.status(500).render('error', {
          message: 'Failed to generate enhanced content',
          error: { status: 500, stack: result.message }
        });
      }
      
      // Get the newly generated data
      reportData = await getVulnerabilityData(scanId);
    }
    
    // Render the editor page
    res.render('report-editor', {
      title: 'Report Editor',
      scanId,
      metadata: reportData.metadata,
      vulnerabilities: reportData.vulnerabilities
    });
  } catch (error) {
    console.error(`Error in report editor route: ${error.message}`);
    res.status(500).render('error', {
      message: 'Error loading report editor',
      error: { status: 500, stack: error.message }
    });
  }
});

// Route to update vulnerability field
router.post('/update/:scanId/:vulnId/:field', async (req, res) => {
  try {
    const { scanId, vulnId, field } = req.params;
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ success: false, message: 'Content is required' });
    }
    
    // Update the field in Redis
    const success = await updateVulnerabilityField(scanId, vulnId, field, content);
    
    if (!success) {
      return res.status(500).json({ success: false, message: 'Failed to update field' });
    }
    
    res.json({ success: true, message: 'Field updated successfully' });
  } catch (error) {
    console.error(`Error updating vulnerability field: ${error.message}`);
    res.status(500).json({ success: false, message: `Error: ${error.message}` });
  }
});

// Route to generate and download report
router.get('/generate/:scanId/:format', async (req, res) => {
  try {
    const { scanId, format } = req.params;
    
    if (!['html', 'json', 'pdf'].includes(format)) {
      return res.status(400).json({ success: false, message: 'Invalid format' });
    }
    
    // Save report to file
    const filePath = await saveReport(scanId, format);
    
    // Set appropriate content type
    const contentTypes = {
      html: 'text/html',
      json: 'application/json',
      pdf: 'application/pdf'
    };
    
    // Set headers for download
    res.setHeader('Content-Type', contentTypes[format]);
    res.setHeader('Content-Disposition', `attachment; filename=${path.basename(filePath)}`);
    
    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
  } catch (error) {
    console.error(`Error generating report: ${error.message}`);
    res.status(500).json({ success: false, message: `Error: ${error.message}` });
  }
});

// Route to preview report
router.get('/preview/:scanId', async (req, res) => {
  try {
    const { scanId } = req.params;
    
    // Generate HTML report
    const htmlContent = await generateHtmlReport(scanId);
    
    // Send the HTML content
    res.send(htmlContent);
  } catch (error) {
    console.error(`Error previewing report: ${error.message}`);
    res.status(500).json({ success: false, message: `Error: ${error.message}` });
  }
});

module.exports = router;
