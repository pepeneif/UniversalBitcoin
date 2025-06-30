/**
 * Universal Bitcoin - Main API Router
 * 
 * Central routing configuration for all API endpoints.
 * Implements security middleware, rate limiting, and request logging.
 * 
 * @author Universal Bitcoin Team
 */

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { rateLimit } from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

// Import middleware
import { errorHandler } from '../middleware/error.middleware.js';
import { globalRateLimit, securityCheck } from '../middleware/rateLimit.middleware.js';
import { optionalAuth } from '../middleware/auth.middleware.js';
import logger from '../../utils/logger.util.js';

// Import routes
import validationRoutes from './validation.routes.js';
import reservesRoutes from './reserves.routes.js';

const router = express.Router();

/**
 * Security middleware
 */
router.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false
}));

/**
 * CORS configuration
 */
router.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    
    // In production, configure allowed origins
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

/**
 * Request preprocessing
 */
router.use(compression());
router.use(express.json({ limit: '10mb' }));
router.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * Request logging middleware
 */
router.use((req, res, next) => {
  const startTime = Date.now();
  
  // Log request
  logger.info('API request received', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    requestId: req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  });
  
  // Log response
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    logger.info('API request completed', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      requestId: req.headers['x-request-id']
    });
  });
  
  next();
});

/**
 * Security checks
 */
router.use(securityCheck);

/**
 * Global rate limiting
 */
router.use(globalRateLimit);

/**
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime()
  });
});

/**
 * API information endpoint
 */
router.get('/info', optionalAuth, (req, res) => {
  res.json({
    name: 'Universal Bitcoin API',
    version: '1.0.0',
    description: 'Multi-chain proof-of-reserves system with Guardian Angels security',
    documentation: '/api/docs',
    endpoints: {
      validation: '/api/v1/validate',
      reserves: '/api/v1/reserves',
      authentication: '/api/v1/auth'
    },
    supportedChains: ['ethereum', 'solana', 'polygon', 'arbitrum', 'bsc'],
    features: [
      'Pay-per-validation Bitcoin signing',
      'Guardian Angels multi-signature security',
      'Real-time proof-of-reserves',
      'Multi-chain token support',
      'Rate limiting with revenue preservation'
    ],
    security: {
      guardianThreshold: 3,
      totalGuardians: 5,
      rateLimit: {
        global: '1000 requests/hour',
        perIP: '100 requests/hour',
        validation: '10 requests/hour'
      }
    },
    contact: {
      website: 'https://universalbitcoin.org',
      email: 'support@universalbitcoin.org',
      github: 'https://github.com/universalbitcoin/api'
    }
  });
});

/**
 * Test endpoint for development
 */
if (process.env.NODE_ENV === 'development') {
  router.post('/test', [
    body('message').notEmpty().withMessage('Message is required'),
    body('data').optional().isObject().withMessage('Data must be an object')
  ], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array()
      });
    }
    
    res.json({
      success: true,
      echo: {
        message: req.body.message,
        data: req.body.data,
        timestamp: new Date().toISOString(),
        ip: req.ip,
        userAgent: req.get('User-Agent')
      }
    });
  });
}

/**
 * Mount route modules
 */
router.use('/validate', validationRoutes);
router.use('/reserves', reservesRoutes);

/**
 * Authentication routes (placeholder)
 */
router.use('/auth', (req, res) => {
  res.status(501).json({
    success: false,
    message: 'Authentication endpoints not yet implemented',
    availableEndpoints: [
      'POST /api/v1/auth/login',
      'POST /api/v1/auth/register',
      'POST /api/v1/auth/refresh',
      'POST /api/v1/auth/logout'
    ]
  });
});

/**
 * Guardian Angels routes (placeholder)
 */
router.use('/guardians', (req, res) => {
  res.status(501).json({
    success: false,
    message: 'Guardian Angels endpoints not yet implemented',
    availableEndpoints: [
      'GET /api/v1/guardians/status',
      'POST /api/v1/guardians/consensus',
      'GET /api/v1/guardians/health'
    ]
  });
});

/**
 * Admin routes (placeholder)
 */
router.use('/admin', (req, res) => {
  res.status(501).json({
    success: false,
    message: 'Admin endpoints not yet implemented',
    availableEndpoints: [
      'GET /api/v1/admin/stats',
      'POST /api/v1/admin/reserves/update',
      'GET /api/v1/admin/logs',
      'POST /api/v1/admin/maintenance'
    ]
  });
});

/**
 * Catch-all for undefined routes
 */
router.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      message: 'Endpoint not found',
      path: req.originalUrl,
      method: req.method,
      timestamp: new Date().toISOString()
    },
    documentation: '/api/v1/info'
  });
});

/**
 * Error handling middleware (must be last)
 */
router.use(errorHandler);

export default router;