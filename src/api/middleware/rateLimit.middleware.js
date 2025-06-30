/**
 * Universal Bitcoin - Rate Limiting Middleware
 * 
 * Multi-layer rate limiting with security monitoring and revenue preservation.
 * Implements global, per-IP, and per-user rate limits with intelligent queuing.
 * 
 * @author Universal Bitcoin Team
 */

import rateLimit from 'express-rate-limit';
import RedisStore from 'rate-limit-redis';
import { redis } from '../../config/redis.js';
import { RateLimitError, SecurityError } from './error.middleware.js';
import { logSecurityEvent } from '../../utils/logger.util.js';
import config from '../../config/index.js';

/**
 * Rate limit configurations
 */
const RATE_LIMITS = {
  global: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1000,                // 1000 requests per hour globally
    message: 'Global rate limit exceeded',
    standardHeaders: true,
    legacyHeaders: false
  },
  
  perIP: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100,                 // 100 requests per hour per IP
    message: 'IP rate limit exceeded',
    standardHeaders: true,
    legacyHeaders: false
  },
  
  validation: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,                  // 10 validations per hour per IP
    message: 'Validation rate limit exceeded',
    standardHeaders: true,
    legacyHeaders: false
  },
  
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,                   // 5 auth attempts per 15 minutes
    message: 'Authentication rate limit exceeded',
    standardHeaders: true,
    legacyHeaders: false
  }
};

/**
 * Suspicious activity thresholds
 */
const SECURITY_THRESHOLDS = {
  violations: 5,           // Max violations before blocking
  suspiciousRequests: 50,  // Requests that trigger monitoring
  blockDuration: 24 * 60 * 60 * 1000 // 24 hour block
};

/**
 * Redis store configuration
 */
const redisStore = new RedisStore({
  sendCommand: (...args) => redis.call(...args),
  prefix: 'rl:',
});

/**
 * Enhanced rate limiter class
 */
class EnhancedRateLimiter {
  constructor() {
    this.blocklist = new Set();
    this.suspiciousIPs = new Map();
    this.violationCounts = new Map();
    
    // Load blocklist from Redis on startup
    this.loadBlocklist();
    
    // Periodic cleanup
    setInterval(() => this.cleanup(), 60 * 60 * 1000); // Every hour
  }
  
  /**
   * Load blocklist from Redis
   */
  async loadBlocklist() {
    try {
      const blocked = await redis.smembers('security:blocklist');
      blocked.forEach(ip => this.blocklist.add(ip));
    } catch (error) {
      console.error('Failed to load blocklist:', error);
    }
  }
  
  /**
   * Check if IP is blocked
   */
  isBlocked(ip) {
    return this.blocklist.has(ip);
  }
  
  /**
   * Block an IP address
   */
  async blockIP(ip, reason, duration = SECURITY_THRESHOLDS.blockDuration) {
    this.blocklist.add(ip);
    
    // Store in Redis with expiration
    await redis.sadd('security:blocklist', ip);
    await redis.expire('security:blocklist', Math.floor(duration / 1000));
    
    // Log security event
    logSecurityEvent('ip_blocked', {
      ip,
      reason,
      duration,
      timestamp: Date.now()
    });
    
    // Set auto-unblock
    setTimeout(() => {
      this.unblockIP(ip);
    }, duration);
  }
  
  /**
   * Unblock an IP address
   */
  async unblockIP(ip) {
    this.blocklist.delete(ip);
    await redis.srem('security:blocklist', ip);
    
    logSecurityEvent('ip_unblocked', {
      ip,
      timestamp: Date.now()
    });
  }
  
  /**
   * Handle rate limit exceeded
   */
  async handleRateLimitExceeded(ip, endpoint, userAgent) {
    // Increment violation count
    const violations = (this.violationCounts.get(ip) || 0) + 1;
    this.violationCounts.set(ip, violations);
    
    // Log security event
    logSecurityEvent('rate_limit_exceeded', {
      ip,
      endpoint,
      userAgent,
      violations,
      timestamp: Date.now()
    });
    
    // Block IP if too many violations
    if (violations >= SECURITY_THRESHOLDS.violations) {
      await this.blockIP(ip, `Excessive rate limit violations: ${violations}`);
    }
    
    // Mark as suspicious
    this.suspiciousIPs.set(ip, {
      violations,
      lastViolation: Date.now(),
      endpoints: (this.suspiciousIPs.get(ip)?.endpoints || []).concat(endpoint)
    });
  }
  
  /**
   * Check for suspicious patterns
   */
  analyzeSuspiciousActivity(ip, req) {
    const suspicious = this.suspiciousIPs.get(ip);
    if (!suspicious) return false;
    
    const patterns = [
      // Too many different endpoints
      suspicious.endpoints.length > 10,
      
      // High violation rate
      suspicious.violations > 3,
      
      // Suspicious user agent
      !req.get('User-Agent') || 
      req.get('User-Agent').includes('bot') ||
      req.get('User-Agent').includes('curl') ||
      req.get('User-Agent').includes('wget'),
      
      // Missing common headers
      !req.get('Accept') || !req.get('Accept-Language')
    ];
    
    return patterns.filter(Boolean).length >= 2;
  }
  
  /**
   * Cleanup old data
   */
  cleanup() {
    const now = Date.now();
    const oldThreshold = now - (24 * 60 * 60 * 1000); // 24 hours
    
    // Clean violation counts
    for (const [ip, count] of this.violationCounts.entries()) {
      if (now - (count.lastUpdate || 0) > oldThreshold) {
        this.violationCounts.delete(ip);
      }
    }
    
    // Clean suspicious IPs
    for (const [ip, data] of this.suspiciousIPs.entries()) {
      if (now - data.lastViolation > oldThreshold) {
        this.suspiciousIPs.delete(ip);
      }
    }
  }
}

// Global rate limiter instance
const rateLimiter = new EnhancedRateLimiter();

/**
 * Create rate limiter middleware
 */
function createRateLimiter(options = {}) {
  const settings = { ...RATE_LIMITS.perIP, ...options };
  
  return rateLimit({
    store: redisStore,
    ...settings,
    keyGenerator: (req) => {
      // Use IP as default key
      return req.ip || req.connection.remoteAddress;
    },
    
    // Custom handler for rate limit exceeded
    handler: async (req, res, next) => {
      const ip = req.ip || req.connection.remoteAddress;
      const endpoint = req.originalUrl;
      const userAgent = req.get('User-Agent');
      
      // Handle the violation
      await rateLimiter.handleRateLimitExceeded(ip, endpoint, userAgent);
      
      // Check for suspicious activity
      if (rateLimiter.analyzeSuspiciousActivity(ip, req)) {
        await rateLimiter.blockIP(ip, 'Suspicious activity detected');
        throw new SecurityError('Suspicious activity detected');
      }
      
      // Create rate limit error with queue information
      const error = new RateLimitError(settings.message, {
        limit: settings.max,
        window: settings.windowMs,
        retryAfter: settings.windowMs,
        resetTime: Date.now() + settings.windowMs
      });
      
      next(error);
    },
    
    // Skip function for blocked IPs
    skip: (req) => {
      const ip = req.ip || req.connection.remoteAddress;
      
      if (rateLimiter.isBlocked(ip)) {
        throw new SecurityError('IP address blocked');
      }
      
      return false;
    }
  });
}

/**
 * Security check middleware
 */
export function securityCheck(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  
  // Check if IP is blocked
  if (rateLimiter.isBlocked(ip)) {
    logSecurityEvent('blocked_ip_access_attempt', {
      ip,
      url: req.originalUrl,
      userAgent: req.get('User-Agent'),
      timestamp: Date.now()
    });
    
    throw new SecurityError('Access denied');
  }
  
  next();
}

/**
 * Specific rate limiters
 */
export const globalRateLimit = createRateLimiter(RATE_LIMITS.global);

export const ipRateLimit = createRateLimiter(RATE_LIMITS.perIP);

export const validationRateLimit = createRateLimiter({
  ...RATE_LIMITS.validation,
  keyGenerator: (req) => {
    // More restrictive for validation endpoints
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || 'unknown';
    return `${ip}:${userAgent.substring(0, 50)}`;
  }
});

export const authRateLimit = createRateLimiter({
  ...RATE_LIMITS.auth,
  keyGenerator: (req) => {
    // Rate limit by IP and attempted username for auth
    const ip = req.ip || req.connection.remoteAddress;
    const username = req.body?.username || req.body?.email || 'unknown';
    return `${ip}:${username}`;
  }
});

/**
 * Dynamic rate limiter based on endpoint
 */
export function dynamicRateLimit(req, res, next) {
  const endpoint = req.route?.path || req.originalUrl;
  
  let limiter;
  
  if (endpoint.includes('/auth') || endpoint.includes('/login')) {
    limiter = authRateLimit;
  } else if (endpoint.includes('/validate')) {
    limiter = validationRateLimit;
  } else {
    limiter = ipRateLimit;
  }
  
  limiter(req, res, next);
}

/**
 * Revenue preservation middleware
 * Ensures paid validations are queued rather than rejected
 */
export function revenuePreservation(req, res, next) {
  const originalHandler = res.locals.rateLimitHandler;
  
  // Override rate limit handler for validation endpoints
  if (req.originalUrl.includes('/validate') && req.body?.txHash) {
    res.locals.rateLimitHandler = async (req, res, next) => {
      // Instead of rejecting, add to queue
      const queuePosition = await addToValidationQueue(req.body);
      
      res.status(429).json({
        error: {
          message: 'Rate limit exceeded - validation queued',
          queuePosition,
          estimatedProcessingTime: queuePosition * 30, // 30 seconds per validation
          retryAfter: queuePosition * 30
        }
      });
    };
  }
  
  next();
}

/**
 * Add validation to queue (placeholder - will be implemented with queue service)
 */
async function addToValidationQueue(validationData) {
  // TODO: Implement with queue service
  const queueKey = 'validation:queue';
  const position = await redis.lpush(queueKey, JSON.stringify({
    ...validationData,
    timestamp: Date.now(),
    id: generateQueueId()
  }));
  
  return position;
}

/**
 * Generate queue ID
 */
function generateQueueId() {
  return `queue_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

/**
 * Get rate limit status for monitoring
 */
export async function getRateLimitStatus(req, res) {
  const ip = req.ip || req.connection.remoteAddress;
  
  try {
    const [globalCount, ipCount, validationCount] = await Promise.all([
      redis.get(`rl:global:${Date.now()}`),
      redis.get(`rl:${ip}`),
      redis.get(`rl:validation:${ip}`)
    ]);
    
    res.json({
      ip,
      limits: {
        global: {
          used: parseInt(globalCount) || 0,
          limit: RATE_LIMITS.global.max,
          window: RATE_LIMITS.global.windowMs
        },
        ip: {
          used: parseInt(ipCount) || 0,
          limit: RATE_LIMITS.perIP.max,
          window: RATE_LIMITS.perIP.windowMs
        },
        validation: {
          used: parseInt(validationCount) || 0,
          limit: RATE_LIMITS.validation.max,
          window: RATE_LIMITS.validation.windowMs
        }
      },
      blocked: rateLimiter.isBlocked(ip),
      suspicious: rateLimiter.suspiciousIPs.has(ip)
    });
  } catch (error) {
    res.status(500).json({
      error: 'Failed to get rate limit status'
    });
  }
}

export default {
  createRateLimiter,
  securityCheck,
  globalRateLimit,
  ipRateLimit,
  validationRateLimit,
  authRateLimit,
  dynamicRateLimit,
  revenuePreservation,
  getRateLimitStatus
};