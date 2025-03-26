/**
 * Simple in-memory session store for tracking scan progress
 * In a production environment, this would be replaced with Redis or another persistent store
 */

// In-memory store for scan sessions
const sessions = {};

/**
 * Create or update a scan session
 * @param {string} sessionId - Session ID
 * @param {object} data - Session data
 */
function setSession(sessionId, data) {
  sessions[sessionId] = {
    ...sessions[sessionId],
    ...data,
    lastUpdated: Date.now()
  };
  
  return sessions[sessionId];
}

/**
 * Get a scan session
 * @param {string} sessionId - Session ID
 * @returns {object|null} - Session data or null if not found
 */
function getSession(sessionId) {
  return sessions[sessionId] || null;
}

/**
 * Delete a scan session
 * @param {string} sessionId - Session ID
 */
function deleteSession(sessionId) {
  delete sessions[sessionId];
}

/**
 * Get all active scan sessions
 * @returns {object} - All sessions
 */
function getAllSessions() {
  return sessions;
}

/**
 * Clean up expired sessions (older than 24 hours)
 */
function cleanupSessions() {
  const now = Date.now();
  const expiry = 24 * 60 * 60 * 1000; // 24 hours
  
  Object.keys(sessions).forEach(sessionId => {
    if (now - sessions[sessionId].lastUpdated > expiry) {
      deleteSession(sessionId);
    }
  });
}

/**
 * Append output to a specific output type in a session
 * @param {string} sessionId - Session ID
 * @param {string} outputType - Output type (config, scan, report)
 * @param {string} data - Output data to append
 */
function appendSessionOutput(sessionId, outputType, data) {
  if (!sessions[sessionId]) {
    sessions[sessionId] = {
      lastUpdated: Date.now(),
      currentStep: outputType,
      status: 'running'
    };
  }
  
  // Initialize output field if it doesn't exist
  if (!sessions[sessionId][`${outputType}Output`]) {
    sessions[sessionId][`${outputType}Output`] = '';
  }
  
  // Append the data
  sessions[sessionId][`${outputType}Output`] += data;
  sessions[sessionId].lastUpdated = Date.now();
  sessions[sessionId].currentStep = outputType;
  
  return sessions[sessionId];
}

/**
 * Update session status
 * @param {string} sessionId - Session ID
 * @param {string} status - Session status (running, paused, stopped, complete, error)
 * @param {object} additionalData - Additional data to store
 */
function updateSessionStatus(sessionId, status, additionalData = {}) {
  if (!sessions[sessionId]) {
    return null;
  }
  
  sessions[sessionId] = {
    ...sessions[sessionId],
    ...additionalData,
    status,
    lastUpdated: Date.now()
  };
  
  return sessions[sessionId];
}

// Run cleanup every hour
setInterval(cleanupSessions, 60 * 60 * 1000);

/**
 * Pause a scan session
 * @param {string} sessionId - Session ID
 * @returns {boolean} - Whether the operation was successful
 */
function pauseSession(sessionId) {
  const session = getSession(sessionId);
  
  if (!session || session.status !== 'running') {
    return false;
  }
  
  // Update session status to paused
  updateSessionStatus(sessionId, 'paused', {
    pausedAt: Date.now()
  });
  
  return true;
}

/**
 * Resume a paused scan session
 * @param {string} sessionId - Session ID
 * @returns {boolean} - Whether the operation was successful
 */
function resumeSession(sessionId) {
  const session = getSession(sessionId);
  
  if (!session || session.status !== 'paused') {
    return false;
  }
  
  // Calculate total pause duration for metrics
  const pauseDuration = Date.now() - (session.pausedAt || 0);
  
  // Update session status to running
  updateSessionStatus(sessionId, 'running', {
    pausedAt: null,
    totalPauseDuration: (session.totalPauseDuration || 0) + pauseDuration
  });
  
  return true;
}

/**
 * Stop a scan session
 * @param {string} sessionId - Session ID
 * @returns {boolean} - Whether the operation was successful
 */
function stopSession(sessionId) {
  const session = getSession(sessionId);
  
  if (!session || (session.status !== 'running' && session.status !== 'paused')) {
    return false;
  }
  
  // Update session status to stopped
  updateSessionStatus(sessionId, 'stopped', {
    stoppedAt: Date.now()
  });
  
  return true;
}

module.exports = {
  setSession,
  getSession,
  deleteSession,
  getAllSessions,
  cleanupSessions,
  appendSessionOutput,
  updateSessionStatus,
  pauseSession,
  resumeSession,
  stopSession
};
