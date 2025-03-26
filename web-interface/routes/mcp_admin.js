/**
 * MCP Admin Routes
 * 
 * Routes for managing MCP prompt templates
 */

const express = require('express');
const router = express.Router();
const promptManager = require('../utils/prompt-manager');

/**
 * GET /admin/mcp
 * Render MCP admin page
 */
router.get('/', async (req, res) => {
  try {
    // Get total template count
    const templates = await promptManager.exportTemplates();
    const templateCount = Object.keys(templates).length;
    
    res.render('mcp_admin', {
      title: 'MCP Administration',
      templateCount,
      activeTab: 'mcp-admin'
    });
  } catch (error) {
    console.error('Error rendering MCP admin page:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /admin/mcp/api/templates
 * Get all templates with pagination and filtering
 */
router.get('/api/templates', async (req, res) => {
  try {
    // Get query parameters
    const limit = parseInt(req.query.limit) || 500;
    const offset = parseInt(req.query.offset) || 0;
    const category = req.query.category || 'all';
    
    // Get templates
    const templates = await promptManager.exportTemplates(limit);
    const templateArray = Object.values(templates);
    
    // Filter by category if needed
    const filteredTemplates = category === 'all'
      ? templateArray
      : templateArray.filter(template => template.category === category);
    
    res.json({
      success: true,
      templates: filteredTemplates,
      total: filteredTemplates.length
    });
  } catch (error) {
    console.error('Error getting templates:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to retrieve templates'
    });
  }
});

/**
 * GET /admin/mcp/api/templates/:id
 * Get a specific template by ID
 */
router.get('/api/templates/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const template = await promptManager.getTemplate(id);
    
    if (!template) {
      return res.status(404).json({
        success: false,
        error: 'Template not found'
      });
    }
    
    res.json({
      success: true,
      template
    });
  } catch (error) {
    console.error(`Error getting template ${req.params.id}:`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve template'
    });
  }
});

/**
 * POST /admin/mcp/api/templates
 * Create a new template
 */
router.post('/api/templates', async (req, res) => {
  try {
    const template = req.body;
    
    // Validate template
    if (!template.name || !template.template) {
      return res.status(400).json({
        success: false,
        error: 'Template must have a name and content'
      });
    }
    
    // Create template
    const id = await promptManager.createTemplate(template);
    
    res.json({
      success: true,
      id,
      message: 'Template created successfully'
    });
  } catch (error) {
    console.error('Error creating template:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to create template'
    });
  }
});

/**
 * PUT /admin/mcp/api/templates
 * Update an existing template
 */
router.put('/api/templates', async (req, res) => {
  try {
    const template = req.body;
    
    // Validate template
    if (!template.id) {
      return res.status(400).json({
        success: false,
        error: 'Template ID is required'
      });
    }
    
    if (!template.name || !template.template) {
      return res.status(400).json({
        success: false,
        error: 'Template must have a name and content'
      });
    }
    
    // Update template
    const success = await promptManager.updateTemplate(template.id, template);
    
    if (!success) {
      return res.status(404).json({
        success: false,
        error: 'Template not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Template updated successfully'
    });
  } catch (error) {
    console.error('Error updating template:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to update template'
    });
  }
});

/**
 * DELETE /admin/mcp/api/templates/:id
 * Delete a template
 */
router.delete('/api/templates/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const success = await promptManager.deleteTemplate(id);
    
    if (!success) {
      return res.status(404).json({
        success: false,
        error: 'Template not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Template deleted successfully'
    });
  } catch (error) {
    console.error(`Error deleting template ${req.params.id}:`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete template'
    });
  }
});

/**
 * POST /admin/mcp/api/templates/import
 * Import templates from JSON
 */
router.post('/api/templates/import', async (req, res) => {
  try {
    const { templates, overwrite } = req.body;
    
    if (!templates || !Array.isArray(templates)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid templates data'
      });
    }
    
    // Import templates
    const importedIds = await promptManager.importTemplates(templates);
    
    res.json({
      success: true,
      count: importedIds.length,
      message: `Imported ${importedIds.length} templates successfully`
    });
  } catch (error) {
    console.error('Error importing templates:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to import templates'
    });
  }
});

/**
 * GET /admin/mcp/api/templates/export
 * Export all templates
 */
router.get('/api/templates/export', async (req, res) => {
  try {
    const templates = await promptManager.exportTemplates();
    
    res.json({
      success: true,
      templates
    });
  } catch (error) {
    console.error('Error exporting templates:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to export templates'
    });
  }
});

module.exports = router;
