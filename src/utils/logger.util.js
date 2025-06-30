/**
 * Universal Bitcoin - Logger Utility
 * 
 * Centralized logging system with structured JSON logging, rotation, and security.
 * Follows security guidelines - never logs sensitive data like private keys.
 * 
 * @author Universal Bitcoin Team
 */

import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import config from '../config/index.js';

/**
 * Custom log format for structured logging
 */
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, service = 'universal-bitcoin', ...meta }) => {
    const logEntry = {
      timestamp,
      level,
      service,
      message,
      ...meta
    };
    
    // Security: Remove sensitive data from logs
    return JSON.stringify(sanitizeLogData(logEntry));
  })
);

/**
 * Sanitize sensitive data from log entries
 * Following .kilocode/rules/SECURITY-GUIDELINES.md
 */
function sanitizeLogData(data) {
  const sensitiveKeys = [
    'password',
    'privateKey',
    'private_key',
    'secretKey',
    'secret_key',
    'signature',
    'token',
    'authorization',
    'cookie',
    'session',
    'jwt',
    'key',
    'secret'
  ];
  
  const sanitized = JSON.parse(JSON.stringify(data));
  
  function recursiveSanitize(obj) {
    if (typeof obj !== 'object' || obj === null) {
      return obj;
    }
    
    for (const key in obj) {
      if (sensitiveKeys.some(sensitive => 
        key.toLowerCase().includes(sensitive.toLowerCase())
      )) {
        obj[key] = '***REDACTED***';
      } else if (typeof obj[key] === 'object') {
        recursiveSanitize(obj[key]);
      }
    }
    
    return obj;
  }
  
  return recursiveSanitize(sanitized);
}

/**
 * Create daily rotate file transport
 */
function createFileTransport(filename, level = 'info') {
  return new DailyRotateFile({
    filename: `logs/${filename}-%DATE%.log`,
    datePattern: 'YYYY-MM-DD',
    zippedArchive: true,
    maxSize: config.monitoring.maxLogSize,
    maxFiles: config.monitoring.maxLogFiles,
    level,
    format: logFormat,
    auditFile: `logs/.${filename}-audit.json`
  });
}

/**
 * Create console transport with color coding
 */
function createConsoleTransport() {
  return new winston.transports.Console({
    level: config.monitoring.logLevel,
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({
        format: 'HH:mm:ss.SSS'
      }),
      winston.format.printf(({ timestamp, level, message, service = 'universal-bitcoin', ...meta }) => {
        const metaString = Object.keys(meta).length ? ` ${JSON.stringify(meta)}` : '';
        return `[${timestamp}] ${level} [${service}]: ${message}${metaString}`;
      })
    )
  });
}

/**
 * Winston logger configuration
 */
const logger = winston.createLogger({
  level: config.monitoring.logLevel,
  format: logFormat,
  defaultMeta: {
    service: 'universal-bitcoin',
    version: process.env.npm_package_version || '1.0.0',
    environment: config.environment
  },
  transports: [
    // Console transport for development
    createConsoleTransport(),
    
    // File transports for all environments
    createFileTransport('combined', 'info'),
    createFileTransport('error', 'error'),
    createFileTransport('security', 'warn'), // Security events
  ],
  
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    createFileTransport('exceptions', 'error')
  ],
  rejectionHandlers: [
    createFileTransport('rejections', 'error')
  ],
  
  exitOnError: false
});

/**
 * Security audit logging
 * Special logger for security-related events
 */
export const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        event_type: 'security_audit',
        message,
        ...sanitizeLogData(meta)
      });
    })
  ),
  transports: [
    createFileTransport('security-audit', 'info'),
    new winston.transports.Console({
      level: 'warn',
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

/**
 * Guardian Angels audit logging
 * Special logger for Guardian Angels operations
 */
export const guardianLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        event_type: 'guardian_audit',
        message,
        ...sanitizeLogData(meta)
      });
    })
  ),
  transports: [
    createFileTransport('guardian-audit', 'info'),
    new winston.transports.Console({
      level: 'info',
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

/**
 * Performance logging utility
 */
export function createPerformanceLogger(operation) {
  const start = Date.now();
  
  return {
    end: (additionalData = {}) => {
      const duration = Date.now() - start;
      
      logger.info('Performance metric', {
        operation,
        duration,
        ...additionalData
      });
      
      return duration;
    }
  };
}

/**
 * Request logging middleware helper
 */
export function logRequest(req, res, responseTime) {
  const logData = {
    method: req.method,
    url: req.originalUrl,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    statusCode: res.statusCode,
    responseTime,
    contentLength: res.get('Content-Length'),
    userId: req.user?.id,
    validationId: req.validationId
  };
  
  // Log based on status code
  if (res.statusCode >= 500) {
    logger.error('Server error response', logData);
  } else if (res.statusCode >= 400) {
    logger.warn('Client error response', logData);
  } else {
    logger.info('Request completed', logData);
  }
}

/**
 * Security event logging
 */
export function logSecurityEvent(event, details = {}) {
  securityLogger.warn('Security event detected', {
    event,
    timestamp: new Date().toISOString(),
    ...details
  });
}

/**
 * Guardian Angels event logging
 */
export function logGuardianEvent(event, guardianId, details = {}) {
  guardianLogger.info('Guardian Angels event', {
    event,
    guardianId,
    timestamp: new Date().toISOString(),
    ...details
  });
}

/**
 * Bitcoin operation logging
 */
export function logBitcoinOperation(operation, details = {}) {
  logger.info('Bitcoin operation', {
    operation,
    timestamp: new Date().toISOString(),
    ...details
  });
  
  // Also log to security logger for audit trail
  securityLogger.info('Bitcoin operation audit', {
    operation,
    timestamp: new Date().toISOString(),
    ...details
  });
}

/**
 * Error logging with context
 */
export function logError(error, context = {}) {
  const errorData = {
    error: error.message,
    stack: error.stack,
    name: error.name,
    code: error.code,
    ...context
  };
  
  logger.error('Application error', errorData);
  
  // Log critical errors to security logger
  if (error.name === 'SecurityError' || error.name === 'ValidationError') {
    securityLogger.error('Critical security error', errorData);
  }
}

// Export the main logger as default
export default logger;