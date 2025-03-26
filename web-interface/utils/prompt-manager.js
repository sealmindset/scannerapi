/**
 * Prompt Template Manager
 * 
 * Utility for managing prompt templates in Redis
 */

const redis = require('./redis');
const { v4: uuidv4 } = require('uuid');

/**
 * PromptManager class for managing prompt templates
 */
class PromptManager {
  /**
   * Create a new prompt template
   * 
   * @param {Object} template - The prompt template object
   * @param {string} template.name - Name of the template
   * @param {string} template.description - Description of the template
   * @param {string} template.template - The actual template content
   * @param {string} template.category - Category of the template (optional)
   * @returns {Promise<string>} - ID of the created template
   */
  async createTemplate(template) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Validate template
      if (!template.name || !template.template) {
        throw new Error('Template must have a name and content');
      }
      
      // Generate ID if not provided
      const id = template.id || uuidv4();
      
      // Add metadata
      template.created = new Date().toISOString();
      template.updated = template.created;
      
      // Store template in Redis
      await redis.cacheReportField(id, 'template', JSON.stringify(template));
      
      // Create metadata for easier searching
      const metadata = {
        title: template.name,
        description: template.description || '',
        timestamp: template.created,
        type: 'prompt_template',
        category: template.category || 'general'
      };
      
      await redis.storeScanMetadata(id, metadata);
      
      return id;
    } catch (error) {
      console.error('Error creating prompt template:', error);
      throw error;
    }
  }
  
  /**
   * Get a prompt template by ID
   * 
   * @param {string} id - ID of the template
   * @returns {Promise<Object>} - The prompt template
   */
  async getTemplate(id) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Get template from Redis
      const templateJson = await redis.getCachedReportField(id, 'template');
      
      if (!templateJson) {
        return null;
      }
      
      return JSON.parse(templateJson);
    } catch (error) {
      console.error('Error getting prompt template:', error);
      throw error;
    }
  }
  
  /**
   * Update a prompt template
   * 
   * @param {string} id - ID of the template to update
   * @param {Object} updates - Fields to update
   * @returns {Promise<boolean>} - Success status
   */
  async updateTemplate(id, updates) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Get existing template
      const templateJson = await redis.getCachedReportField(id, 'template');
      
      if (!templateJson) {
        throw new Error(`Template with ID ${id} not found`);
      }
      
      const template = JSON.parse(templateJson);
      
      // Update fields
      Object.assign(template, updates);
      
      // Update timestamp
      template.updated = new Date().toISOString();
      
      // Store updated template
      await redis.cacheReportField(id, 'template', JSON.stringify(template));
      
      // Update metadata if name or description changed
      if (updates.name || updates.description || updates.category) {
        const metadata = await redis.getScanMetadata(id);
        
        if (metadata) {
          if (updates.name) metadata.title = updates.name;
          if (updates.description) metadata.description = updates.description;
          if (updates.category) metadata.category = updates.category;
          
          await redis.storeScanMetadata(id, metadata);
        }
      }
      
      return true;
    } catch (error) {
      console.error('Error updating prompt template:', error);
      throw error;
    }
  }
  
  /**
   * Delete a prompt template
   * 
   * @param {string} id - ID of the template to delete
   * @returns {Promise<boolean>} - Success status
   */
  async deleteTemplate(id) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Delete template
      await redis.deleteCachedReportField(id, 'template');
      
      // Delete metadata
      // Note: This doesn't delete all scan metadata, just removes the template association
      const metadata = await redis.getScanMetadata(id);
      
      if (metadata) {
        metadata.type = 'deleted_template';
        await redis.storeScanMetadata(id, metadata);
      }
      
      return true;
    } catch (error) {
      console.error('Error deleting prompt template:', error);
      throw error;
    }
  }
  
  /**
   * Import templates from a JSON file or object
   * 
   * @param {Object|Array} templates - Templates to import
   * @returns {Promise<Array<string>>} - IDs of imported templates
   */
  async importTemplates(templates) {
    try {
      // Handle array or object format
      const templateArray = Array.isArray(templates) ? templates : Object.values(templates);
      
      const importedIds = [];
      
      for (const template of templateArray) {
        const id = await this.createTemplate(template);
        importedIds.push(id);
      }
      
      return importedIds;
    } catch (error) {
      console.error('Error importing templates:', error);
      throw error;
    }
  }
  
  /**
   * Export all templates
   * 
   * @param {number} limit - Maximum number of templates to export
   * @returns {Promise<Object>} - Object containing all templates
   */
  async exportTemplates(limit = 500) {
    try {
      // Ensure Redis connection
      await redis.ensureConnection();
      
      // Get all scan IDs
      const scanIds = await redis.getAllScanIds(limit, 0);
      
      const templates = {};
      
      for (const id of scanIds) {
        const metadata = await redis.getScanMetadata(id);
        
        // Only include prompt templates
        if (metadata && metadata.type === 'prompt_template') {
          const templateJson = await redis.getCachedReportField(id, 'template');
          
          if (templateJson) {
            try {
              templates[id] = JSON.parse(templateJson);
            } catch (e) {
              console.error(`Error parsing template for ID ${id}:`, e);
            }
          }
        }
      }
      
      return templates;
    } catch (error) {
      console.error('Error exporting templates:', error);
      throw error;
    }
  }
}

module.exports = new PromptManager();
