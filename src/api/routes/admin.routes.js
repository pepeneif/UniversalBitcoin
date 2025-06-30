/**
 * Universal Bitcoin - Admin Routes
 * 
 * Complete admin API endpoints for system management, monitoring, and configuration.
 * Provides secure access to admin-only functionality with comprehensive logging.
 * 
 * @author Universal Bitcoin Team
 */

import express from 'express';
import { query, body, validationResult } from 'express-validator';
import { asyncHandler, validationError } from '../middleware/error.middleware.js';
import { requireAdmin, requireAnyRole, ROLES } from '../middleware/auth.middleware.js';
import { ipRateLimit } from '../middleware/rateLimit.middleware.js';
import { logSecurityEvent } from '../../utils/logger.util.js';
import logger from '../../utils/logger.util.js';
import { redis } from '../../config/redis.js';
import config from '../../config/index.js';

const router = express.Router();

/**
 * @api {get} /api/v1/admin/stats Get System Statistics
 * @apiName GetAdminStats
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get comprehensive system statistics and metrics
 * @apiPermission Admin
 */
router.get('/stats',
  requireAdmin,
  ipRateLimit,
  asyncHandler(async (req, res) => {
    try {
      // Get system statistics
      const stats = await getSystemStats();
      
      logSecurityEvent('admin_stats_accessed', {
        userId: req.user.id,
        ip: req.ip,
        timestamp: Date.now()
      });
      
      res.json({
        success: true,
        data: stats,
        meta: {
          generatedAt: new Date().toISOString(),
          adminUser: req.user.id
        }
      });
      
    } catch (error) {
      logger.error('Failed to get admin stats', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/admin/logs Get System Logs
 * @apiName GetAdminLogs
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get system logs with filtering and pagination
 * @apiPermission Admin
 */
router.get('/logs',
  requireAdmin,
  ipRateLimit,
  [
    query('level').optional().isIn(['error', 'warn', 'info', 'debug']).withMessage('Invalid log level'),
    query('category').optional().isIn(['security', 'bitcoin', 'validation', 'system']).withMessage('Invalid category'),
    query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Invalid limit'),
    query('offset').optional().isInt({ min: 0 }).withMessage('Invalid offset'),
    query('startDate').optional().isISO8601().withMessage('Invalid start date'),
    query('endDate').optional().isISO8601().withMessage('Invalid end date')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid query parameters', errors.array());
    }
    
    try {
      const {
        level,
        category,
        limit = 100,
        offset = 0,
        startDate,
        endDate
      } = req.query;
      
      const logs = await getSystemLogs({
        level,
        category,
        limit: parseInt(limit),
        offset: parseInt(offset),
        startDate,
        endDate
      });
      
      logSecurityEvent('admin_logs_accessed', {
        userId: req.user.id,
        filters: { level, category, limit, offset },
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: logs,
        meta: {
          total: logs.total,
          limit: parseInt(limit),
          offset: parseInt(offset),
          generatedAt: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.error('Failed to get admin logs', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {post} /api/v1/admin/maintenance Maintenance Mode
 * @apiName SetMaintenanceMode
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Enable/disable maintenance mode
 * @apiPermission Admin
 */
router.post('/maintenance',
  requireAdmin,
  [
    body('enabled').isBoolean().withMessage('Enabled must be boolean'),
    body('message').optional().isString().withMessage('Message must be string'),
    body('estimatedDuration').optional().isInt({ min: 0 }).withMessage('Invalid duration')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid request data', errors.array());
    }
    
    try {
      const { enabled, message, estimatedDuration } = req.body;
      
      const maintenanceData = {
        enabled,
        message: message || 'System maintenance in progress',
        estimatedDuration: estimatedDuration || 3600, // 1 hour default
        startedAt: new Date().toISOString(),
        startedBy: req.user.id
      };
      
      // Store maintenance mode in Redis
      if (enabled) {
        await redis.setex('system:maintenance', 86400, JSON.stringify(maintenanceData));
      } else {
        await redis.del('system:maintenance');
      }
      
      logSecurityEvent('maintenance_mode_changed', {
        userId: req.user.id,
        enabled,
        message,
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: {
          maintenanceMode: enabled,
          message: maintenanceData.message,
          estimatedDuration: maintenanceData.estimatedDuration,
          startedAt: maintenanceData.startedAt
        },
        message: `Maintenance mode ${enabled ? 'enabled' : 'disabled'}`
      });
      
    } catch (error) {
      logger.error('Failed to set maintenance mode', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/admin/users Get Users
 * @apiName GetUsers
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get list of system users
 * @apiPermission Admin
 */
router.get('/users',
  requireAdmin,
  [
    query('role').optional().isIn(Object.values(ROLES)).withMessage('Invalid role'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Invalid limit'),
    query('offset').optional().isInt({ min: 0 }).withMessage('Invalid offset')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid query parameters', errors.array());
    }
    
    try {
      const { role, limit = 50, offset = 0 } = req.query;
      
      const users = await getSystemUsers({
        role,
        limit: parseInt(limit),
        offset: parseInt(offset)
      });
      
      logSecurityEvent('admin_users_accessed', {
        userId: req.user.id,
        filters: { role, limit, offset },
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: users,
        meta: {
          total: users.total,
          limit: parseInt(limit),
          offset: parseInt(offset),
          generatedAt: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.error('Failed to get users', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {post} /api/v1/admin/users Create User
 * @apiName CreateUser
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Create a new system user
 * @apiPermission Admin
 */
router.post('/users',
  requireAdmin,
  [
    body('email').isEmail().withMessage('Valid email required'),
    body('role').isIn(Object.values(ROLES)).withMessage('Invalid role'),
    body('name').isString().isLength({ min: 2, max: 100 }).withMessage('Name required (2-100 chars)'),
    body('guardianId').optional().isString().withMessage('Guardian ID must be string')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid user data', errors.array());
    }
    
    try {
      const { email, role, name, guardianId } = req.body;
      
      // Validate Guardian ID for Guardian role
      if (role === ROLES.GUARDIAN && !guardianId) {
        throw validationError('Guardian ID required for Guardian role');
      }
      
      const newUser = await createSystemUser({
        email,
        role,
        name,
        guardianId,
        createdBy: req.user.id
      });
      
      logSecurityEvent('admin_user_created', {
        userId: req.user.id,
        newUserId: newUser.id,
        newUserRole: role,
        ip: req.ip
      });
      
      res.status(201).json({
        success: true,
        data: newUser,
        message: 'User created successfully'
      });
      
    } catch (error) {
      logger.error('Failed to create user', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {put} /api/v1/admin/users/:id Update User
 * @apiName UpdateUser
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Update a system user
 * @apiPermission Admin
 */
router.put('/users/:id',
  requireAdmin,
  [
    body('email').optional().isEmail().withMessage('Valid email required'),
    body('role').optional().isIn(Object.values(ROLES)).withMessage('Invalid role'),
    body('name').optional().isString().isLength({ min: 2, max: 100 }).withMessage('Name required (2-100 chars)'),
    body('active').optional().isBoolean().withMessage('Active must be boolean')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid user data', errors.array());
    }
    
    try {
      const { id } = req.params;
      const updateData = req.body;
      
      const updatedUser = await updateSystemUser(id, {
        ...updateData,
        updatedBy: req.user.id
      });
      
      logSecurityEvent('admin_user_updated', {
        userId: req.user.id,
        targetUserId: id,
        updates: Object.keys(updateData),
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: updatedUser,
        message: 'User updated successfully'
      });
      
    } catch (error) {
      logger.error('Failed to update user', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {delete} /api/v1/admin/users/:id Delete User
 * @apiName DeleteUser
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Delete a system user
 * @apiPermission Admin
 */
router.delete('/users/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const { id } = req.params;
      
      // Prevent deleting self
      if (id === req.user.id) {
        throw validationError('Cannot delete your own account');
      }
      
      await deleteSystemUser(id);
      
      logSecurityEvent('admin_user_deleted', {
        userId: req.user.id,
        deletedUserId: id,
        ip: req.ip
      });
      
      res.json({
        success: true,
        message: 'User deleted successfully'
      });
      
    } catch (error) {
      logger.error('Failed to delete user', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/admin/config Get System Configuration
 * @apiName GetSystemConfig
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get system configuration
 * @apiPermission Admin
 */
router.get('/config',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const systemConfig = await getSystemConfig();
      
      logSecurityEvent('admin_config_accessed', {
        userId: req.user.id,
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: systemConfig,
        meta: {
          generatedAt: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.error('Failed to get system config', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {put} /api/v1/admin/config Update System Configuration
 * @apiName UpdateSystemConfig
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Update system configuration
 * @apiPermission Admin
 */
router.put('/config',
  requireAdmin,
  [
    body('rateLimit').optional().isObject().withMessage('Rate limit must be object'),
    body('guardians').optional().isObject().withMessage('Guardians config must be object'),
    body('maintenance').optional().isObject().withMessage('Maintenance config must be object')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid configuration data', errors.array());
    }
    
    try {
      const configUpdates = req.body;
      
      const updatedConfig = await updateSystemConfig({
        ...configUpdates,
        updatedBy: req.user.id,
        updatedAt: new Date().toISOString()
      });
      
      logSecurityEvent('admin_config_updated', {
        userId: req.user.id,
        updates: Object.keys(configUpdates),
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: updatedConfig,
        message: 'Configuration updated successfully'
      });
      
    } catch (error) {
      logger.error('Failed to update system config', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/admin/guardians Get Guardian Angels Status
 * @apiName GetGuardianStatus
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get Guardian Angels status and consensus information
 * @apiPermission Admin
 */
router.get('/guardians',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const guardianStatus = await getGuardianStatus();
      
      logSecurityEvent('admin_guardians_accessed', {
        userId: req.user.id,
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: guardianStatus,
        meta: {
          generatedAt: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.error('Failed to get guardian status', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {post} /api/v1/admin/guardians/test Test Guardian Consensus
 * @apiName TestGuardianConsensus
 * @apiGroup Admin
 * @apiVersion 1.0.0
 * 
 * @apiDescription Test Guardian Angels consensus mechanism
 * @apiPermission Admin
 */
router.post('/guardians/test',
  requireAdmin,
  [
    body('message').isString().isLength({ min: 1, max: 500 }).withMessage('Test message required (1-500 chars)')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid test data', errors.array());
    }
    
    try {
      const { message } = req.body;
      
      const testResult = await testGuardianConsensus(message);
      
      logSecurityEvent('admin_guardian_test_executed', {
        userId: req.user.id,
        testMessage: message,
        success: testResult.success,
        ip: req.ip
      });
      
      res.json({
        success: true,
        data: testResult,
        message: 'Guardian consensus test completed'
      });
      
    } catch (error) {
      logger.error('Failed to test guardian consensus', { error: error.message });
      throw error;
    }
  })
);

/**
 * Helper functions
 */

async function getSystemStats() {
  // Simulate system statistics
  return {
    system: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      nodeVersion: process.version,
      environment: config.environment
    },
    bitcoin: {
      network: config.bitcoin.network,
      balance: 10.5, // Simulated
      address: 'bc1qxyz123...' // Simulated
    },
    validations: {
      total: 1250,
      today: 45,
      pending: 3,
      success_rate: 99.2
    },
    revenue: {
      total_eth: 125.5,
      total_sol: 2500.0,
      total_usd: 425000.0
    },
    guardians: {
      total: 5,
      online: 5,
      consensus_capable: true,
      last_consensus: new Date().toISOString()
    },
    chains: {
      ethereum: { active: true, balance: 5.2 },
      solana: { active: true, balance: 2.8 },
      polygon: { active: true, balance: 1.5 },
      arbitrum: { active: true, balance: 0.8 },
      bsc: { active: true, balance: 0.2 }
    }
  };
}

async function getSystemLogs(filters) {
  // Simulate log retrieval
  const logs = [];
  for (let i = 0; i < filters.limit; i++) {
    logs.push({
      id: `log_${Date.now()}_${i}`,
      timestamp: new Date(Date.now() - (i * 60000)).toISOString(),
      level: ['info', 'warn', 'error'][Math.floor(Math.random() * 3)],
      category: ['system', 'bitcoin', 'validation', 'security'][Math.floor(Math.random() * 4)],
      message: `Sample log message ${i + 1}`,
      metadata: {
        ip: '192.168.1.1',
        userAgent: 'Admin/1.0'
      }
    });
  }
  
  return {
    logs,
    total: 10000 // Simulated total
  };
}

async function getSystemUsers(filters) {
  // Simulate user retrieval
  const users = [];
  for (let i = 0; i < filters.limit; i++) {
    users.push({
      id: `user_${i + 1}`,
      email: `user${i + 1}@example.com`,
      name: `User ${i + 1}`,
      role: Object.values(ROLES)[Math.floor(Math.random() * Object.values(ROLES).length)],
      active: Math.random() > 0.1,
      createdAt: new Date(Date.now() - (i * 86400000)).toISOString(),
      lastLogin: new Date(Date.now() - (Math.random() * 86400000)).toISOString()
    });
  }
  
  return {
    users,
    total: 50 // Simulated total
  };
}

async function createSystemUser(userData) {
  // Simulate user creation
  return {
    id: `user_${Date.now()}`,
    email: userData.email,
    name: userData.name,
    role: userData.role,
    guardianId: userData.guardianId,
    active: true,
    createdAt: new Date().toISOString(),
    createdBy: userData.createdBy
  };
}

async function updateSystemUser(id, updateData) {
  // Simulate user update
  return {
    id,
    ...updateData,
    updatedAt: new Date().toISOString()
  };
}

async function deleteSystemUser(id) {
  // Simulate user deletion
  return true;
}

async function getSystemConfig() {
  // Return sanitized system configuration
  return {
    rateLimit: {
      global: config.rateLimit.global,
      perIP: config.rateLimit.perIP,
      validation: config.rateLimit.validation
    },
    guardians: {
      threshold: config.guardians.threshold,
      total: config.guardians.total,
      timeout: config.guardians.timeout
    },
    blockchains: {
      ethereum: {
        minimumPayment: config.blockchains.ethereum.minimumPayment,
        confirmations: config.blockchains.ethereum.confirmations
      },
      solana: {
        minimumPayment: config.blockchains.solana.minimumPayment,
        confirmations: config.blockchains.solana.confirmations
      }
    },
    cache: config.cache
  };
}

async function updateSystemConfig(configData) {
  // Simulate configuration update
  return {
    ...configData,
    updatedAt: new Date().toISOString()
  };
}

async function getGuardianStatus() {
  // Simulate Guardian Angels status
  return {
    summary: {
      total: 5,
      online: 5,
      consensusCapable: true,
      threshold: 3,
      lastConsensus: new Date().toISOString()
    },
    guardians: [
      {
        id: 'guardian_1',
        name: 'Guardian Alpha',
        status: 'online',
        lastSeen: new Date().toISOString(),
        publicKey: 'pubkey_alpha_123...',
        location: 'US-East'
      },
      {
        id: 'guardian_2',
        name: 'Guardian Beta',
        status: 'online',
        lastSeen: new Date().toISOString(),
        publicKey: 'pubkey_beta_456...',
        location: 'EU-West'
      },
      {
        id: 'guardian_3',
        name: 'Guardian Gamma',
        status: 'online',
        lastSeen: new Date().toISOString(),
        publicKey: 'pubkey_gamma_789...',
        location: 'Asia-Pacific'
      },
      {
        id: 'guardian_4',
        name: 'Guardian Delta',
        status: 'online',
        lastSeen: new Date().toISOString(),
        publicKey: 'pubkey_delta_abc...',
        location: 'US-West'
      },
      {
        id: 'guardian_5',
        name: 'Guardian Epsilon',
        status: 'online',
        lastSeen: new Date().toISOString(),
        publicKey: 'pubkey_epsilon_def...',
        location: 'EU-Central'
      }
    ],
    consensusHistory: [
      {
        timestamp: new Date().toISOString(),
        message: 'Test consensus message',
        signatures: 5,
        result: 'success'
      }
    ]
  };
}

async function testGuardianConsensus(message) {
  // Simulate Guardian consensus test
  return {
    success: true,
    message,
    timestamp: new Date().toISOString(),
    signatures: {
      received: 5,
      required: 3,
      threshold_met: true
    },
    guardians: [
      { id: 'guardian_1', signed: true, timestamp: new Date().toISOString() },
      { id: 'guardian_2', signed: true, timestamp: new Date().toISOString() },
      { id: 'guardian_3', signed: true, timestamp: new Date().toISOString() },
      { id: 'guardian_4', signed: true, timestamp: new Date().toISOString() },
      { id: 'guardian_5', signed: true, timestamp: new Date().toISOString() }
    ],
    consensus_time: 1250, // milliseconds
    final_signature: 'H1234567890abcdef...'
  };
}

export default router;