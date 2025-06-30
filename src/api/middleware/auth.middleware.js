/**
 * Universal Bitcoin - Authentication & Authorization Middleware
 * 
 * JWT-based authentication with role-based access control.
 * Integrates with Guardian Angels multi-signature security model.
 * 
 * @author Universal Bitcoin Team
 */

import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { AuthenticationError, AuthorizationError, SecurityError } from './error.middleware.js';
import { logSecurityEvent } from '../../utils/logger.util.js';
import config from '../../config/index.js';
import { redis } from '../../config/redis.js';

/**
 * User roles and permissions
 */
export const ROLES = {
  PUBLIC: 'public',
  USER: 'user',
  ADMIN: 'admin',
  GUARDIAN: 'guardian',
  SYSTEM: 'system'
};

export const PERMISSIONS = {
  [ROLES.PUBLIC]: [],
  [ROLES.USER]: ['validate:request', 'status:view'],
  [ROLES.ADMIN]: [
    'validate:request', 'status:view', 'reserves:manage', 
    'config:update', 'users:manage'
  ],
  [ROLES.GUARDIAN]: [
    'validate:request', 'status:view', 'signatures:create', 
    'consensus:participate', 'operations:approve'
  ],
  [ROLES.SYSTEM]: ['*'] // All permissions
};

/**
 * JWT Configuration
 */
const JWT_CONFIG = {
  algorithm: 'HS256',
  expiresIn: '1h',
  refreshExpiresIn: '7d',
  issuer: 'universal-bitcoin',
  audience: 'universal-bitcoin-api'
};

/**
 * Secure JWT implementation
 */
class SecureJWT {
  constructor() {
    this.secret = config.security.jwtSecret;
    this.refreshSecret = config.security.jwtRefreshSecret;
    this.blacklistedTokens = new Set();
    
    // Load blacklisted tokens from Redis
    this.loadBlacklist();
  }
  
  /**
   * Load blacklisted tokens from Redis
   */
  async loadBlacklist() {
    try {
      const blacklisted = await redis.smembers('auth:blacklist');
      blacklisted.forEach(token => this.blacklistedTokens.add(token));
    } catch (error) {
      console.error('Failed to load token blacklist:', error);
    }
  }
  
  /**
   * Generate access token
   */
  generateAccessToken(payload) {
    const tokenPayload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
      jti: crypto.randomUUID(),
      iss: JWT_CONFIG.issuer,
      aud: JWT_CONFIG.audience,
      type: 'access'
    };
    
    return jwt.sign(tokenPayload, this.secret, {
      algorithm: JWT_CONFIG.algorithm
    });
  }
  
  /**
   * Generate refresh token
   */
  generateRefreshToken(payload) {
    const tokenPayload = {
      userId: payload.userId,
      role: payload.role,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + (7 * 24 * 3600), // 7 days
      jti: crypto.randomUUID(),
      iss: JWT_CONFIG.issuer,
      aud: JWT_CONFIG.audience,
      type: 'refresh'
    };
    
    return jwt.sign(tokenPayload, this.refreshSecret, {
      algorithm: JWT_CONFIG.algorithm
    });
  }
  
  /**
   * Verify access token
   */
  verifyAccessToken(token) {
    if (this.blacklistedTokens.has(token)) {
      throw new AuthenticationError('Token has been revoked');
    }
    
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: [JWT_CONFIG.algorithm],
        issuer: JWT_CONFIG.issuer,
        audience: JWT_CONFIG.audience
      });
      
      if (decoded.type !== 'access') {
        throw new AuthenticationError('Invalid token type');
      }
      
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new AuthenticationError('Token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new AuthenticationError('Invalid token');
      }
      throw error;
    }
  }
  
  /**
   * Verify refresh token
   */
  verifyRefreshToken(token) {
    if (this.blacklistedTokens.has(token)) {
      throw new AuthenticationError('Refresh token has been revoked');
    }
    
    try {
      const decoded = jwt.verify(token, this.refreshSecret, {
        algorithms: [JWT_CONFIG.algorithm],
        issuer: JWT_CONFIG.issuer,
        audience: JWT_CONFIG.audience
      });
      
      if (decoded.type !== 'refresh') {
        throw new AuthenticationError('Invalid refresh token type');
      }
      
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new AuthenticationError('Refresh token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new AuthenticationError('Invalid refresh token');
      }
      throw error;
    }
  }
  
  /**
   * Blacklist a token
   */
  async blacklistToken(token) {
    this.blacklistedTokens.add(token);
    
    // Store in Redis with expiration
    await redis.sadd('auth:blacklist', token);
    await redis.expire('auth:blacklist', 7 * 24 * 3600); // 7 days
    
    logSecurityEvent('token_blacklisted', {
      tokenJti: this.extractJti(token),
      timestamp: Date.now()
    });
  }
  
  /**
   * Extract JTI from token
   */
  extractJti(token) {
    try {
      const decoded = jwt.decode(token);
      return decoded?.jti || 'unknown';
    } catch {
      return 'invalid';
    }
  }
}

// Global JWT manager
const jwtManager = new SecureJWT();

/**
 * Authentication middleware
 */
export function authenticate(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthenticationError('Authentication token required');
    }
    
    const token = authHeader.substring(7);
    
    if (!token) {
      throw new AuthenticationError('Authentication token required');
    }
    
    const decoded = jwtManager.verifyAccessToken(token);
    
    // Add user info to request
    req.user = {
      id: decoded.userId,
      role: decoded.role,
      permissions: PERMISSIONS[decoded.role] || [],
      tokenJti: decoded.jti,
      guardianId: decoded.guardianId // For Guardian Angels
    };
    
    // Add token to request for potential blacklisting
    req.token = token;
    
    // Log successful authentication
    logSecurityEvent('authentication_success', {
      userId: decoded.userId,
      role: decoded.role,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl
    });
    
    next();
  } catch (error) {
    logSecurityEvent('authentication_failure', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
      error: error.message
    });
    
    next(error);
  }
}

/**
 * Optional authentication middleware
 */
export function optionalAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No authentication provided, continue as public user
      req.user = {
        role: ROLES.PUBLIC,
        permissions: PERMISSIONS[ROLES.PUBLIC]
      };
      return next();
    }
    
    // Try to authenticate
    authenticate(req, res, next);
  } catch (error) {
    // Authentication failed, continue as public user
    req.user = {
      role: ROLES.PUBLIC,
      permissions: PERMISSIONS[ROLES.PUBLIC]
    };
    next();
  }
}

/**
 * Authorization middleware factory
 */
export function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      throw new AuthenticationError('Authentication required');
    }
    
    const userPermissions = req.user.permissions || [];
    
    // System role has all permissions
    if (userPermissions.includes('*')) {
      return next();
    }
    
    if (!userPermissions.includes(permission)) {
      logSecurityEvent('authorization_failure', {
        userId: req.user.id,
        role: req.user.role,
        requiredPermission: permission,
        userPermissions,
        ip: req.ip,
        endpoint: req.originalUrl
      });
      
      throw new AuthorizationError(`Permission '${permission}' required`);
    }
    
    next();
  };
}

/**
 * Role-based authorization middleware
 */
export function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      throw new AuthenticationError('Authentication required');
    }
    
    if (req.user.role !== role) {
      logSecurityEvent('authorization_failure', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRole: role,
        ip: req.ip,
        endpoint: req.originalUrl
      });
      
      throw new AuthorizationError(`Role '${role}' required`);
    }
    
    next();
  };
}

/**
 * Guardian Angels authorization
 */
export function requireGuardian(req, res, next) {
  if (!req.user || req.user.role !== ROLES.GUARDIAN) {
    throw new AuthorizationError('Guardian access required');
  }
  
  if (!req.user.guardianId) {
    throw new SecurityError('Invalid Guardian credentials');
  }
  
  next();
}

/**
 * Admin authorization
 */
export function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== ROLES.ADMIN) {
    throw new AuthorizationError('Admin access required');
  }
  
  next();
}

/**
 * Multiple role authorization
 */
export function requireAnyRole(roles) {
  return (req, res, next) => {
    if (!req.user) {
      throw new AuthenticationError('Authentication required');
    }
    
    if (!roles.includes(req.user.role)) {
      logSecurityEvent('authorization_failure', {
        userId: req.user.id,
        userRole: req.user.role,
        allowedRoles: roles,
        ip: req.ip,
        endpoint: req.originalUrl
      });
      
      throw new AuthorizationError(`One of roles [${roles.join(', ')}] required`);
    }
    
    next();
  };
}

/**
 * Token generation endpoint
 */
export async function generateTokens(req, res) {
  const { userId, role, guardianId } = req.body;
  
  // Validate input
  if (!userId || !role) {
    throw new ValidationError('User ID and role are required');
  }
  
  if (!Object.values(ROLES).includes(role)) {
    throw new ValidationError('Invalid role');
  }
  
  const payload = { userId, role };
  
  // Add guardian ID for Guardian role
  if (role === ROLES.GUARDIAN) {
    if (!guardianId) {
      throw new ValidationError('Guardian ID required for Guardian role');
    }
    payload.guardianId = guardianId;
  }
  
  const accessToken = jwtManager.generateAccessToken(payload);
  const refreshToken = jwtManager.generateRefreshToken(payload);
  
  // Store refresh token
  await redis.setex(`refresh:${userId}`, 7 * 24 * 3600, refreshToken);
  
  logSecurityEvent('tokens_generated', {
    userId,
    role,
    guardianId,
    ip: req.ip
  });
  
  res.json({
    accessToken,
    refreshToken,
    expiresIn: 3600,
    tokenType: 'Bearer'
  });
}

/**
 * Token refresh endpoint
 */
export async function refreshTokens(req, res) {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    throw new AuthenticationError('Refresh token required');
  }
  
  const decoded = jwtManager.verifyRefreshToken(refreshToken);
  
  // Check if refresh token exists in Redis
  const storedToken = await redis.get(`refresh:${decoded.userId}`);
  if (storedToken !== refreshToken) {
    throw new AuthenticationError('Invalid refresh token');
  }
  
  // Generate new tokens
  const payload = {
    userId: decoded.userId,
    role: decoded.role,
    guardianId: decoded.guardianId
  };
  
  const newAccessToken = jwtManager.generateAccessToken(payload);
  const newRefreshToken = jwtManager.generateRefreshToken(payload);
  
  // Update stored refresh token
  await redis.setex(`refresh:${decoded.userId}`, 7 * 24 * 3600, newRefreshToken);
  
  // Blacklist old refresh token
  await jwtManager.blacklistToken(refreshToken);
  
  logSecurityEvent('tokens_refreshed', {
    userId: decoded.userId,
    role: decoded.role,
    ip: req.ip
  });
  
  res.json({
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    expiresIn: 3600,
    tokenType: 'Bearer'
  });
}

/**
 * Logout endpoint
 */
export async function logout(req, res) {
  const token = req.token;
  
  if (token) {
    // Blacklist access token
    await jwtManager.blacklistToken(token);
  }
  
  if (req.user?.id) {
    // Remove refresh token
    await redis.del(`refresh:${req.user.id}`);
    
    logSecurityEvent('user_logout', {
      userId: req.user.id,
      ip: req.ip
    });
  }
  
  res.json({
    message: 'Logout successful'
  });
}

/**
 * User info endpoint
 */
export function userInfo(req, res) {
  if (!req.user) {
    throw new AuthenticationError('Authentication required');
  }
  
  res.json({
    id: req.user.id,
    role: req.user.role,
    permissions: req.user.permissions,
    guardianId: req.user.guardianId
  });
}

export default {
  authenticate,
  optionalAuth,
  requirePermission,
  requireRole,
  requireGuardian,
  requireAdmin,
  requireAnyRole,
  generateTokens,
  refreshTokens,
  logout,
  userInfo,
  ROLES,
  PERMISSIONS
};