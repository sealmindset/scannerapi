/**
 * MCP Admin JavaScript
 * 
 * Client-side code for the MCP Admin interface
 */

document.addEventListener('DOMContentLoaded', function() {
  // Variables
  const templatesPerPage = 10;
  let currentPage = 1;
  let currentCategory = 'all';
  let templates = [];
  let filteredTemplates = [];
  
  // DOM Elements
  const templateCategories = document.getElementById('template-categories');
  const templatesTableBody = document.getElementById('templates-table-body');
  const pagination = document.getElementById('pagination');
  const templateCount = document.getElementById('template-count');
  const currentPageEl = document.getElementById('current-page');
  const totalPagesEl = document.getElementById('total-pages');
  const templateSearch = document.getElementById('template-search');
  const searchBtn = document.getElementById('search-btn');
  const newTemplateBtn = document.getElementById('new-template-btn');
  const importTemplatesBtn = document.getElementById('import-templates-btn');
  const exportTemplatesBtn = document.getElementById('export-templates-btn');
  
  // Template Modal Elements
  const templateModalEl = document.getElementById('template-modal');
  const templateModal = new bootstrap.Modal(templateModalEl);
  const templateForm = document.getElementById('template-form');
  const templateId = document.getElementById('template-id');
  const templateName = document.getElementById('template-name');
  const templateCategory = document.getElementById('template-category');
  const templateDescription = document.getElementById('template-description');
  const templateContent = document.getElementById('template-content');
  const saveTemplateBtn = document.getElementById('save-template-btn');
  const deleteTemplateBtn = document.getElementById('delete-template-btn');
  
  // Import Modal Elements
  const importModalEl = document.getElementById('import-modal');
  const importModal = new bootstrap.Modal(importModalEl);
  const importFile = document.getElementById('import-file');
  const overwriteExisting = document.getElementById('overwrite-existing');
  const importBtn = document.getElementById('import-btn');
  
  // Initialize
  loadTemplates();
  
  // Initialize tabs if they exist
  const tabEl = document.querySelector('button[data-bs-toggle="tab"]');
  if (tabEl) {
    tabEl.addEventListener('shown.bs.tab', function (event) {
      // Handle tab change events if needed
      const activeTab = event.target.getAttribute('id');
      if (activeTab === 'templates-tab') {
        loadTemplates();
      }
    });
  }
  
  // Event Listeners
  templateCategories.addEventListener('click', handleCategoryClick);
  searchBtn.addEventListener('click', handleSearch);
  templateSearch.addEventListener('keyup', function(e) {
    if (e.key === 'Enter') {
      handleSearch();
    }
  });
  
  newTemplateBtn.addEventListener('click', createNewTemplate);
  importTemplatesBtn.addEventListener('click', () => importModal.show());
  exportTemplatesBtn.addEventListener('click', exportTemplates);
  
  saveTemplateBtn.addEventListener('click', saveTemplate);
  deleteTemplateBtn.addEventListener('click', deleteTemplate);
  importBtn.addEventListener('click', importTemplates);
  
  // Functions
  function loadTemplates() {
    showLoading();
    
    fetch('/admin/mcp/api/templates')
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          templates = data.templates;
          updateCategoryCounts();
          filterTemplates();
        } else {
          showError('Failed to load templates');
        }
      })
      .catch(error => {
        console.error('Error loading templates:', error);
        showError('Failed to load templates');
      });
  }
  
  function updateCategoryCounts() {
    // Count templates by category
    const counts = {
      all: templates.length,
      main: 0,
      section: 0,
      vulnerability: 0,
      scan: 0,
      report: 0
    };
    
    templates.forEach(template => {
      const category = template.category || 'uncategorized';
      if (counts[category] !== undefined) {
        counts[category]++;
      }
    });
    
    // Update category badges
    for (const category in counts) {
      const badge = document.getElementById(`${category}-count`);
      if (badge) {
        badge.textContent = counts[category];
      }
    }
  }
  
  function filterTemplates() {
    // Filter templates by category
    filteredTemplates = currentCategory === 'all' 
      ? [...templates] 
      : templates.filter(template => template.category === currentCategory);
    
    // Filter by search term if present
    const searchTerm = templateSearch.value.trim().toLowerCase();
    if (searchTerm) {
      filteredTemplates = filteredTemplates.filter(template => 
        template.name.toLowerCase().includes(searchTerm) || 
        (template.description && template.description.toLowerCase().includes(searchTerm))
      );
    }
    
    // Update UI
    updateTemplateCount();
    renderPagination();
    renderTemplates();
  }
  
  function updateTemplateCount() {
    templateCount.textContent = filteredTemplates.length;
    const totalPages = Math.ceil(filteredTemplates.length / templatesPerPage) || 1;
    
    // Reset current page if it's out of bounds
    if (currentPage > totalPages) {
      currentPage = 1;
    }
    
    currentPageEl.textContent = currentPage;
    totalPagesEl.textContent = totalPages;
  }
  
  function renderPagination() {
    const totalPages = Math.ceil(filteredTemplates.length / templatesPerPage) || 1;
    
    let paginationHTML = '';
    
    // Previous button
    paginationHTML += `
      <li class="page-item ${currentPage === 1 ? 'disabled' : ''}">
        <a class="page-link" href="#" data-page="${currentPage - 1}" aria-label="Previous">
          <span aria-hidden="true">&laquo;</span>
        </a>
      </li>
    `;
    
    // Page numbers
    for (let i = 1; i <= totalPages; i++) {
      // Show limited page numbers to avoid cluttering
      if (i === 1 || i === totalPages || (i >= currentPage - 2 && i <= currentPage + 2)) {
        paginationHTML += `
          <li class="page-item ${i === currentPage ? 'active' : ''}">
            <a class="page-link" href="#" data-page="${i}">${i}</a>
          </li>
        `;
      } else if (i === currentPage - 3 || i === currentPage + 3) {
        paginationHTML += `
          <li class="page-item disabled">
            <a class="page-link" href="#">...</a>
          </li>
        `;
      }
    }
    
    // Next button
    paginationHTML += `
      <li class="page-item ${currentPage === totalPages ? 'disabled' : ''}">
        <a class="page-link" href="#" data-page="${currentPage + 1}" aria-label="Next">
          <span aria-hidden="true">&raquo;</span>
        </a>
      </li>
    `;
    
    pagination.innerHTML = paginationHTML;
    
    // Add event listeners to pagination links
    pagination.querySelectorAll('.page-link').forEach(link => {
      link.addEventListener('click', function(e) {
        e.preventDefault();
        const page = parseInt(this.dataset.page);
        if (!isNaN(page) && page >= 1 && page <= totalPages) {
          currentPage = page;
          updateTemplateCount();
          renderTemplates();
        }
      });
    });
  }
  
  function renderTemplates() {
    // Calculate slice indices
    const startIndex = (currentPage - 1) * templatesPerPage;
    const endIndex = startIndex + templatesPerPage;
    const pageTemplates = filteredTemplates.slice(startIndex, endIndex);
    
    if (pageTemplates.length === 0) {
      templatesTableBody.innerHTML = `
        <tr>
          <td colspan="4" class="text-center">No templates found</td>
        </tr>
      `;
      return;
    }
    
    let tableHTML = '';
    
    pageTemplates.forEach(template => {
      const updatedAt = template.updatedAt 
        ? new Date(template.updatedAt).toLocaleString() 
        : 'N/A';
      
      tableHTML += `
        <tr>
          <td>${escapeHtml(template.name)}</td>
          <td>${escapeHtml(template.category || 'Uncategorized')}</td>
          <td>${updatedAt}</td>
          <td>
            <button class="btn btn-sm btn-primary edit-template" data-id="${template.id}">
              <i class="bi bi-pencil"></i> Edit
            </button>
          </td>
        </tr>
      `;
    });
    
    templatesTableBody.innerHTML = tableHTML;
    
    // Add event listeners to edit buttons
    templatesTableBody.querySelectorAll('.edit-template').forEach(button => {
      button.addEventListener('click', function() {
        const id = this.dataset.id;
        editTemplate(id);
      });
    });
  }
  
  function handleCategoryClick(e) {
    e.preventDefault();
    
    const target = e.target.closest('.list-group-item');
    if (!target) return;
    
    // Update active class
    templateCategories.querySelectorAll('.list-group-item').forEach(item => {
      item.classList.remove('active');
    });
    target.classList.add('active');
    
    // Update current category
    currentCategory = target.dataset.category;
    currentPage = 1;
    
    // Filter templates
    filterTemplates();
  }
  
  function handleSearch() {
    currentPage = 1;
    filterTemplates();
  }
  
  function createNewTemplate() {
    // Clear form
    templateForm.reset();
    templateId.value = '';
    
    // Update modal title
    document.getElementById('template-modal-label').textContent = 'Create New Template';
    
    // Hide delete button
    deleteTemplateBtn.style.display = 'none';
    
    // Show modal
    templateModal.show();
  }
  
  function editTemplate(id) {
    // Find template
    const template = templates.find(t => t.id === id);
    if (!template) {
      showError('Template not found');
      return;
    }
    
    // Fill form
    templateId.value = template.id;
    templateName.value = template.name;
    templateCategory.value = template.category || 'main';
    templateDescription.value = template.description || '';
    templateContent.value = template.template || '';
    
    // Update modal title
    document.getElementById('template-modal-label').textContent = 'Edit Template';
    
    // Show delete button
    deleteTemplateBtn.style.display = 'block';
    
    // Show modal
    templateModal.show();
  }
  
  function saveTemplate() {
    // Validate form
    if (!templateForm.checkValidity()) {
      templateForm.reportValidity();
      return;
    }
    
    // Prepare template data
    const template = {
      name: templateName.value,
      category: templateCategory.value,
      description: templateDescription.value,
      template: templateContent.value
    };
    
    // Add ID if editing existing template
    if (templateId.value) {
      template.id = templateId.value;
    }
    
    // API endpoint and method
    const url = '/admin/mcp/api/templates';
    const method = template.id ? 'PUT' : 'POST';
    
    // Save template
    fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(template)
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          // Close modal
          templateModal.hide();
          
          // Show success message
          showSuccess(template.id ? 'Template updated' : 'Template created');
          
          // Reload templates
          loadTemplates();
        } else {
          showError(data.error || 'Failed to save template');
        }
      })
      .catch(error => {
        console.error('Error saving template:', error);
        showError('Failed to save template');
      });
  }
  
  function deleteTemplate() {
    // Confirm deletion
    if (!confirm('Are you sure you want to delete this template?')) {
      return;
    }
    
    const id = templateId.value;
    if (!id) {
      showError('Template ID not found');
      return;
    }
    
    // Delete template
    fetch(`/admin/mcp/api/templates/${id}`, {
      method: 'DELETE'
    })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          // Close modal
          templateModal.hide();
          
          // Show success message
          showSuccess('Template deleted');
          
          // Reload templates
          loadTemplates();
        } else {
          showError(data.error || 'Failed to delete template');
        }
      })
      .catch(error => {
        console.error('Error deleting template:', error);
        showError('Failed to delete template');
      });
  }
  
  function importTemplates() {
    const fileInput = importFile;
    
    if (!fileInput.files || fileInput.files.length === 0) {
      showError('Please select a file');
      return;
    }
    
    const file = fileInput.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
      try {
        const templates = JSON.parse(e.target.result);
        
        // Send to API
        fetch('/admin/mcp/api/templates/import', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            templates: Array.isArray(templates) ? templates : Object.values(templates),
            overwrite: overwriteExisting.checked
          })
        })
          .then(response => response.json())
          .then(data => {
            if (data.success) {
              // Close modal
              importModal.hide();
              
              // Show success message
              showSuccess(`Imported ${data.count} templates`);
              
              // Reload templates
              loadTemplates();
            } else {
              showError(data.error || 'Failed to import templates');
            }
          })
          .catch(error => {
            console.error('Error importing templates:', error);
            showError('Failed to import templates');
          });
      } catch (error) {
        console.error('Error parsing JSON:', error);
        showError('Invalid JSON file');
      }
    };
    
    reader.readAsText(file);
  }
  
  function exportTemplates() {
    fetch('/admin/mcp/api/templates/export')
      .then(response => response.json())
      .then(data => {
        if (data.success && data.templates) {
          // Create download link
          const blob = new Blob([JSON.stringify(data.templates, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `mcp_templates_${new Date().toISOString().split('T')[0]}.json`;
          a.click();
          
          // Clean up
          URL.revokeObjectURL(url);
          
          showSuccess('Templates exported');
        } else {
          showError(data.error || 'Failed to export templates');
        }
      })
      .catch(error => {
        console.error('Error exporting templates:', error);
        showError('Failed to export templates');
      });
  }
  
  function showLoading() {
    templatesTableBody.innerHTML = `
      <tr>
        <td colspan="4" class="text-center">
          <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">Loading...</span>
          </div>
        </td>
      </tr>
    `;
  }
  
  function showError(message) {
    const alertHTML = `
      <div class="alert alert-danger alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    `;
    
    document.querySelector('.container-fluid').insertAdjacentHTML('afterbegin', alertHTML);
  }
  
  function showSuccess(message) {
    const alertHTML = `
      <div class="alert alert-success alert-dismissible fade show" role="alert">
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
      </div>
    `;
    
    document.querySelector('.container-fluid').insertAdjacentHTML('afterbegin', alertHTML);
  }
  
  function escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
});
