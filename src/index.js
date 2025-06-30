/**
 * Universal Bitcoin - Main Application Entry Point
 * 
 * Multi-chain proof-of-reserves system with Guardian Angels multi-signature security.
 * Provides pay-per-validation Bitcoin message signing across multiple blockchain networks.
 * 
 * @author Universal Bitcoin Team
 */

import express from 'express';
import http from 'http';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import config from './config/index.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';
import { connectRedis, disconnectRedis } from './config/redis.js';
import logger from './utils/logger.util.js';
import apiRoutes from './api/routes/index.js';

// ES Module compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Universal Bitcoin Application Class
 */
class UniversalBitcoinApp {
  constructor() {
    this.app = express();
    this.server = null;
    this.isShuttingDown = false;
    
    // Initialize application
    this.init();
  }
  
  /**
   * Initialize the application
   */
  async init() {
    try {
      logger.info('Initializing Universal Bitcoin application', {
        version: config.app.version,
        environment: config.environment,
        nodeVersion: process.version
      });
      
      // Setup middleware
      this.setupMiddleware();
      
      // Setup routes
      this.setupRoutes();
      
      // Setup error handling
      this.setupErrorHandling();
      
      // Connect to external services
      await this.connectServices();
      
      // Initialize core services
      await this.initializeServices();
      
      logger.info('Universal Bitcoin application initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize application', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Setup Express middleware
   */
  setupMiddleware() {
    // Trust proxy for accurate IP addresses
    this.app.set('trust proxy', config.security.trustProxy || 1);
    
    // Request timeout
    this.app.use((req, res, next) => {
      req.setTimeout(config.server.requestTimeout || 30000);
      next();
    });
    
    // Request ID middleware
    this.app.use((req, res, next) => {
      req.requestId = req.headers['x-request-id'] || 
                     `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      res.setHeader('X-Request-ID', req.requestId);
      next();
    });
    
    // Security headers
    this.app.use((req, res, next) => {
      res.setHeader('X-Powered-By', 'Universal Bitcoin');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      next();
    });
    
    logger.info('Express middleware configured');
  }
  
  /**
   * Setup application routes
   */
  setupRoutes() {
    // Root endpoint
    this.app.get('/', (req, res) => {
      res.json({
        name: 'Universal Bitcoin API',
        version: config.app.version,
        description: 'Multi-chain proof-of-reserves system with Guardian Angels security',
        status: 'operational',
        timestamp: new Date().toISOString(),
        endpoints: {
          api: '/api/v1',
          health: '/api/v1/health',
          info: '/api/v1/info',
          validation: '/api/v1/validate',
          reserves: '/api/v1/reserves'
        },
        documentation: {
          openapi: '/api/docs',
          readme: '/api/readme',
          github: 'https://github.com/universalbitcoin/api'
        }
      });
    });
    
    // API routes
    this.app.use('/api/v1', apiRoutes);
    
    // Documentation (placeholder)
    this.app.get('/api/docs', (req, res) => {
      res.json({
        message: 'API documentation',
        swagger: 'OpenAPI documentation not yet implemented',
        endpoints: {
          validation: {
            'POST /api/v1/validate': 'Submit validation request',
            'GET /api/v1/validate/:id': 'Get validation status',
            'GET /api/v1/validate/pricing': 'Get pricing information'
          },
          reserves: {
            'GET /api/v1/reserves': 'Get current reserves',
            'GET /api/v1/reserves/proof': 'Get proof of reserves',
            'GET /api/v1/reserves/history': 'Get historical data'
          }
        }
      });
    });
    
    // Favicon
    this.app.get('/favicon.ico', (req, res) => {
      res.status(204).end();
    });
    
    logger.info('Application routes configured');
  }
  
  /**
   * Setup error handling
   */
  setupErrorHandling() {
    // Handle 404 errors
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        error: {
          message: 'Resource not found',
          path: req.originalUrl,
          method: req.method,
          timestamp: new Date().toISOString()
        },
        help: {
          documentation: '/api/docs',
          support: 'support@universalbitcoin.org'
        }
      });
    });
    
    // Global error handler
    this.app.use((error, req, res, next) => {
      const statusCode = error.statusCode || 500;
      const message = error.message || 'Internal Server Error';
      
      logger.error('Unhandled application error', {
        error: message,
        statusCode,
        stack: error.stack,
        url: req.originalUrl,
        method: req.method,
        ip: req.ip,
        requestId: req.requestId
      });
      
      res.status(statusCode).json({
        success: false,
        error: {
          message: config.environment === 'development' ? message : 'Internal Server Error',
          requestId: req.requestId,
          timestamp: new Date().toISOString()
        }
      });
    });
    
    logger.info('Error handling configured');
  }
  
  /**
   * Connect to external services
   */
  async connectServices() {
    try {
      // Connect to database
      logger.info('Connecting to database...');
      await connectDatabase();
      logger.info('Database connected successfully');
      
      // Connect to Redis
      logger.info('Connecting to Redis...');
      await connectRedis();
      logger.info('Redis connected successfully');
      
    } catch (error) {
      logger.error('Failed to connect to external services', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Initialize core services
   */
  async initializeServices() {
    try {
      // Initialize Bitcoin service
      logger.info('Initializing Bitcoin service...');
      const BitcoinService = await import('./services/bitcoin.service.js');
      const bitcoinService = new BitcoinService.default();
      
      // Get Bitcoin address for receiving payments
      const bitcoinAddress = await bitcoinService.getBitcoinAddress();
      logger.info('Bitcoin service initialized', { address: bitcoinAddress });
      
      // Initialize validation processor
      logger.info('Initializing validation processor...');
      const { ValidationProcessor } = await import('./validation/processor.service.js');
      const validationProcessor = new ValidationProcessor();
      logger.info('Validation processor initialized');
      
      // Store service instances globally for access by routes
      this.app.locals.bitcoinService = bitcoinService;
      this.app.locals.validationProcessor = validationProcessor;
      
      // Run system health check
      await this.performHealthCheck();
      
    } catch (error) {
      logger.error('Failed to initialize core services', { error: error.message });
      throw error;
    }
  }
  
  /**
   * Perform system health check
   */
  async performHealthCheck() {
    try {
      const healthStatus = {
        database: 'unknown',
        redis: 'unknown',
        bitcoin: 'unknown',
        guardians: 'unknown'
      };
      
      // Check database
      try {
        // TODO: Implement database health check
        healthStatus.database = 'healthy';
      } catch (error) {
        healthStatus.database = 'unhealthy';
        logger.warn('Database health check failed', { error: error.message });
      }
      
      // Check Redis
      try {
        // TODO: Implement Redis health check
        healthStatus.redis = 'healthy';
      } catch (error) {
        healthStatus.redis = 'unhealthy';
        logger.warn('Redis health check failed', { error: error.message });
      }
      
      // Check Bitcoin service
      try {
        const bitcoinService = this.app.locals.bitcoinService;
        await bitcoinService.getBitcoinAddress();
        healthStatus.bitcoin = 'healthy';
      } catch (error) {
        healthStatus.bitcoin = 'unhealthy';
        logger.warn('Bitcoin service health check failed', { error: error.message });
      }
      
      // Check Guardian Angels
      try {
        const bitcoinService = this.app.locals.bitcoinService;
        const guardianStatus = bitcoinService.getGuardianStatus();
        healthStatus.guardians = guardianStatus.summary.consensusCapable ? 'healthy' : 'degraded';
      } catch (error) {
        healthStatus.guardians = 'unhealthy';
        logger.warn('Guardian Angels health check failed', { error: error.message });
      }
      
      logger.info('System health check completed', healthStatus);
      
      // Store health status for monitoring
      this.app.locals.healthStatus = {
        ...healthStatus,
        lastCheck: new Date().toISOString()
      };
      
    } catch (error) {
      logger.error('Health check failed', { error: error.message });
    }
  }
  
  /**
   * Start the HTTP server
   */
  async start() {
    return new Promise((resolve, reject) => {
      try {
        const port = config.server.port;
        const host = config.server.host || '0.0.0.0';
        
        this.server = http.createServer(this.app);
        
        // Server event handlers
        this.server.on('error', (error) => {
          if (error.code === 'EADDRINUSE') {
            logger.error(`Port ${port} is already in use`);
          } else {
            logger.error('Server error', { error: error.message });
          }
          reject(error);
        });
        
        this.server.on('listening', () => {
          const address = this.server.address();
          logger.info('Universal Bitcoin server started', {
            host: address.address,
            port: address.port,
            environment: config.environment,
            version: config.app.version
          });
          resolve();
        });
        
        // Start server
        this.server.listen(port, host);
        
      } catch (error) {
        logger.error('Failed to start server', { error: error.message });
        reject(error);
      }
    });
  }
  
  /**
   * Graceful shutdown
   */
  async shutdown() {
    if (this.isShuttingDown) {
      return;
    }
    
    this.isShuttingDown = true;
    
    logger.info('Shutting down Universal Bitcoin server...');
    
    try {
      // Stop accepting new connections
      if (this.server) {
        await new Promise((resolve) => {
          this.server.close(resolve);
        });
        logger.info('HTTP server closed');
      }
      
      // Disconnect from services
      await disconnectRedis();
      logger.info('Redis disconnected');
      
      await disconnectDatabase();
      logger.info('Database disconnected');
      
      logger.info('Universal Bitcoin server shutdown complete');
      
    } catch (error) {
      logger.error('Error during shutdown', { error: error.message });
    }
  }
}

/**
 * Application startup
 */
async function startApplication() {
  try {
    const app = new UniversalBitcoinApp();
    await app.start();
    
    // Graceful shutdown handlers
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM received, shutting down gracefully');
      await app.shutdown();
      process.exit(0);
    });
    
    process.on('SIGINT', async () => {
      logger.info('SIGINT received, shutting down gracefully');
      await app.shutdown();
      process.exit(0);
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', { error: error.message, stack: error.stack });
      process.exit(1);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled promise rejection', { reason, promise });
      process.exit(1);
    });
    
  } catch (error) {
    logger.error('Failed to start application', { error: error.message });
    process.exit(1);
  }
}

// Start the application if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  startApplication();
}

export default UniversalBitcoinApp;