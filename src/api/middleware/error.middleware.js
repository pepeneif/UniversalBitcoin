/**
 * Universal Bitcoin - Error Handling Middleware
 * 
 * Centralized error handling with security-focused error responses.
 * Prevents information leakage while providing useful debugging info.
 * 
 * @author Universal Bitcoin Team
 */

import logger, { logError, logSecurityEvent } from '../../utils/logger.util.js';
import config from '../../config/index.js';

/**
 * Custom error classes
 */
export class ValidationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = 400;
    this.details = details;
  }
}

export class AuthenticationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'AuthenticationError';
    this.statusCode = 401;
    this.details = details;
  }
}

export class AuthorizationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'AuthorizationError';
    this.statusCode = 403;
    this.details = details;
  }
}

export class NotFoundError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'NotFoundError';
    this.statusCode = 404;
    this.details = details;
  }
}

export class RateLimitError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'RateLimitError';
    this.statusCode = 429;
    this.details = details;
  }
}

export class SecurityError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'SecurityError';
    this.statusCode = 403;
    this.details = details;
  }
}

export class GuardianConsensusError extends Error {
  constructor(message, guardianResponses = []) {
    super(message);
    this.name = 'GuardianConsensusError';
    this.statusCode = 503;
    this.guardianResponses = guardianResponses;
  }
}

export class BitcoinOperationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'BitcoinOperationError';
    this.statusCode = 500;
    this.details = details;
  }
}

/**
 * Main error handling middleware
 */
export function errorHandler(err, req, res, next) {
  // Set default values
  let statusCode = err.statusCode || 500;
  let message = err.message || 'Internal Server Error';
  let details = err.details || {};
  
  // Generate unique error ID for tracking
  const errorId = generateErrorId();
  
  // Context for logging
  const context = {
    errorId,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user?.id,
    validationId: req.validationId,
    timestamp: new Date().toISOString()
  };
  
  // Log the error with appropriate level
  logError(err, context);
  
  // Handle specific error types
  switch (err.name) {
    case 'ValidationError':
      statusCode = 400;
      break;
      
    case 'AuthenticationError':
      statusCode = 401;
      logSecurityEvent('authentication_failure', {
        ...context,
        reason: err.message
      });
      break;
      
    case 'AuthorizationError':
      statusCode = 403;
      logSecurityEvent('authorization_failure', {
        ...context,
        reason: err.message
      });
      break;
      
    case 'SecurityError':
      statusCode = 403;
      logSecurityEvent('security_violation', {
        ...context,
        violation: err.message,
        details: err.details
      });
      message = 'Security violation detected';
      details = {}; // Don't expose security details
      break;
      
    case 'RateLimitError':
      statusCode = 429;
      res.set({
        'Retry-After': Math.ceil((details.retryAfter || 3600) / 1000),
        'X-RateLimit-Limit': details.limit,
        'X-RateLimit-Remaining': 0,
        'X-RateLimit-Reset': details.resetTime
      });
      break;
      
    case 'GuardianConsensusError':
      statusCode = 503;
      logSecurityEvent('guardian_consensus_failure', {
        ...context,
        guardianResponses: err.guardianResponses?.length || 0
      });
      message = 'Guardian consensus could not be reached';
      details = {}; // Don't expose Guardian details
      break;
      
    case 'BitcoinOperationError':
      statusCode = 500;
      logSecurityEvent('bitcoin_operation_failure', {
        ...context,
        operation: details.operation
      });
      break;
      
    case 'JsonWebTokenError':
      statusCode = 401;
      message = 'Invalid authentication token';
      details = {};
      break;
      
    case 'TokenExpiredError':
      statusCode = 401;
      message = 'Authentication token expired';
      details = {};
      break;
      
    case 'CastError':
      statusCode = 400;
      message = 'Invalid request format';
      details = {};
      break;
      
    case 'MulterError':
      statusCode = 400;
      message = 'File upload error';
      details = {};
      break;
      
    default:
      // Database errors
      if (err.code === '23505') { // PostgreSQL unique violation
        statusCode = 409;
        message = 'Resource already exists';
        details = {};
      } else if (err.code === '23503') { // PostgreSQL foreign key violation
        statusCode = 400;
        message = 'Invalid reference';
        details = {};
      } else if (err.code === 'ECONNREFUSED') {
        statusCode = 503;
        message = 'Service temporarily unavailable';
        details = {};
      }
  }
  
  // Prepare response
  const response = {
    error: {
      id: errorId,
      message,
      statusCode,
      timestamp: new Date().toISOString()
    }
  };
  
  // Add details in development mode only
  if (config.environment === 'development' && Object.keys(details).length > 0) {
    response.error.details = details;
  }
  
  // Add stack trace in development mode
  if (config.environment === 'development') {
    response.error.stack = err.stack;
  }
  
  // Add rate limit info for rate limit errors
  if (err.name === 'RateLimitError' && details.retryAfter) {
    response.error.retryAfter = details.retryAfter;
  }
  
  // Add validation errors for validation failures
  if (err.name === 'ValidationError' && details.errors) {
    response.error.validationErrors = details.errors;
  }
  
  // Set security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block'
  });
  
  // Send error response
  res.status(statusCode).json(response);
  
  // Log critical errors for monitoring
  if (statusCode >= 500) {
    logger.error('Critical system error', {
      errorId,
      statusCode,
      error: err.message,
      ...context
    });
  }
}

/**
 * Generate unique error ID for tracking
 */
function generateErrorId() {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `err_${timestamp}_${random}`;
}

/**
 * Async error wrapper for route handlers
 */
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/**
 * Create custom error
 */
export function createError(statusCode, message, details = {}) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.details = details;
  return error;
}

/**
 * Validation error helper
 */
export function validationError(message, errors = []) {
  return new ValidationError(message, { errors });
}

/**
 * Security error helper
 */
export function securityError(message, details = {}) {
  return new SecurityError(message, details);
}

/**
 * Guardian consensus error helper
 */
export function guardianConsensusError(message, guardianResponses = []) {
  return new GuardianConsensusError(message, guardianResponses);
}

export default {
  errorHandler,
  asyncHandler,
  createError,
  validationError,
  securityError,
  guardianConsensusError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  SecurityError,
  GuardianConsensusError,
  BitcoinOperationError
};