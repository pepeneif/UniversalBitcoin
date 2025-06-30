/**
 * Universal Bitcoin - Maintenance Mode Middleware
 * 
 * Middleware to check and enforce system maintenance mode.
 * Blocks API access when maintenance is enabled with informative responses.
 * 
 * @author Universal Bitcoin Team
 */

import { redis } from '../../config/redis.js';
import logger from '../../utils/logger.util.js';

/**
 * Maintenance mode check middleware
 */
export async function maintenanceCheck(req, res, next) {
  try {
    // Skip maintenance check for admin endpoints and health checks
    const exemptPaths = [
      '/api/v1/admin',
      '/api/v1/health',
      '/api/v1/auth/login',
      '/api/v1/info'
    ];
    
    const isExempt = exemptPaths.some(path => req.path.startsWith(path));
    
    if (isExempt) {
      return next();
    }
    
    // Check if maintenance mode is enabled
    const maintenanceData = await redis.get('system:maintenance');
    
    if (maintenanceData) {
      const maintenance = JSON.parse(maintenanceData);
      
      logger.info('API request blocked due to maintenance mode', {
        ip: req.ip,
        path: req.path,
        userAgent: req.get('User-Agent')
      });
      
      return res.status(503).json({
        success: false,
        error: {
          code: 'MAINTENANCE_MODE',
          message: 'System is currently under maintenance',
          details: {
            maintenanceMessage: maintenance.message,
            estimatedDuration: maintenance.estimatedDuration,
            startedAt: maintenance.startedAt,
            startedBy: maintenance.startedBy
          }
        },
        retryAfter: maintenance.estimatedDuration
      });
    }
    
    next();
    
  } catch (error) {
    // If Redis is down, log error but don't block requests
    logger.error('Failed to check maintenance status', { 
      error: error.message,
      path: req.path 
    });
    next();
  }
}

/**
 * Check if system is in maintenance mode
 */
export async function isMaintenanceMode() {
  try {
    const maintenanceData = await redis.get('system:maintenance');
    return maintenanceData ? JSON.parse(maintenanceData) : null;
  } catch (error) {
    logger.error('Failed to check maintenance status', { error: error.message });
    return null;
  }
}

/**
 * Enable maintenance mode
 */
export async function enableMaintenanceMode(config) {
  try {
    const maintenanceData = {
      enabled: true,
      message: config.message || 'System maintenance in progress',
      estimatedDuration: config.estimatedDuration || 3600,
      startedAt: new Date().toISOString(),
      startedBy: config.startedBy || 'system'
    };
    
    await redis.setex('system:maintenance', 86400, JSON.stringify(maintenanceData));
    
    logger.info('Maintenance mode enabled', maintenanceData);
    
    return maintenanceData;
  } catch (error) {
    logger.error('Failed to enable maintenance mode', { error: error.message });
    throw error;
  }
}

/**
 * Disable maintenance mode
 */
export async function disableMaintenanceMode() {
  try {
    await redis.del('system:maintenance');
    
    logger.info('Maintenance mode disabled');
    
    return { enabled: false };
  } catch (error) {
    logger.error('Failed to disable maintenance mode', { error: error.message });
    throw error;
  }
}

export default {
  maintenanceCheck,
  isMaintenanceMode,
  enableMaintenanceMode,
  disableMaintenanceMode
};