/**
 * Universal Bitcoin - Authentication Routes
 * 
 * Handles user authentication including login, logout, and token verification.
 * Integrates with the existing JWT authentication system.
 * 
 * @author Universal Bitcoin Team
 */

import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { authenticateToken } from '../middleware/auth.middleware.js';
import logger from '../../utils/logger.util.js';

const router = express.Router();

// Mock user database (replace with actual database)
const users = [
  {
    id: 1,
    username: 'admin',
    email: 'admin@universalbitcoin.com',
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'ADMIN',
    createdAt: new Date('2024-01-01'),
    lastLogin: null
  },
  {
    id: 2,
    username: 'guardian1',
    email: 'guardian1@universalbitcoin.com',
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'GUARDIAN',
    createdAt: new Date('2024-01-01'),
    lastLogin: null
  },
  {
    id: 3,
    username: 'user1',
    email: 'user1@example.com',
    password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password
    role: 'USER',
    createdAt: new Date('2024-01-01'),
    lastLogin: null
  }
];

/**
 * @api {post} /api/v1/auth/login User Login
 * @apiName LoginUser
 * @apiGroup Authentication
 * @apiVersion 1.0.0
 * 
 * @apiDescription Authenticate user and return JWT token
 * 
 * @apiParam {String} username Username or email
 * @apiParam {String} password User password
 * 
 * @apiSuccess {Boolean} success Request success status
 * @apiSuccess {String} token JWT authentication token
 * @apiSuccess {Object} user User information
 * @apiSuccess {Number} user.id User ID
 * @apiSuccess {String} user.username Username
 * @apiSuccess {String} user.email Email address
 * @apiSuccess {String} user.role User role
 * 
 * @apiError {Boolean} success false
 * @apiError {Object} error Error details
 * @apiError {String} error.message Error message
 */
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: {
          message: 'Username and password are required'
        }
      });
    }

    // Find user by username or email
    const user = users.find(u => 
      u.username === username || u.email === username
    );

    if (!user) {
      logger.warn('Login attempt with invalid username', {
        username,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(401).json({
        success: false,
        error: {
          message: 'Invalid credentials'
        }
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      logger.warn('Login attempt with invalid password', {
        userId: user.id,
        username: user.username,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      return res.status(401).json({
        success: false,
        error: {
          message: 'Invalid credentials'
        }
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET || 'your-secret-key',
      {
        expiresIn: process.env.JWT_EXPIRES_IN || '24h'
      }
    );

    // Update last login
    user.lastLogin = new Date();

    logger.info('User logged in successfully', {
      userId: user.id,
      username: user.username,
      role: user.role,
      ip: req.ip
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    logger.error('Login error', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error'
      }
    });
  }
});

/**
 * @api {post} /api/v1/auth/logout User Logout
 * @apiName LogoutUser
 * @apiGroup Authentication
 * @apiVersion 1.0.0
 * 
 * @apiDescription Logout user (token invalidation)
 * 
 * @apiSuccess {Boolean} success Request success status
 * @apiSuccess {String} message Success message
 */
router.post('/logout', authenticateToken, (req, res) => {
  try {
    // In a real implementation, you would add the token to a blacklist
    // For now, we'll just log the logout event
    
    logger.info('User logged out', {
      userId: req.user.id,
      username: req.user.username,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    logger.error('Logout error', {
      error: error.message,
      userId: req.user?.id,
      ip: req.ip
    });

    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error'
      }
    });
  }
});

/**
 * @api {get} /api/v1/auth/me Get Current User
 * @apiName GetCurrentUser
 * @apiGroup Authentication
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get current authenticated user information
 * 
 * @apiSuccess {Boolean} success Request success status
 * @apiSuccess {Object} user User information
 * @apiSuccess {Number} user.id User ID
 * @apiSuccess {String} user.username Username
 * @apiSuccess {String} user.email Email address
 * @apiSuccess {String} user.role User role
 * @apiSuccess {Date} user.lastLogin Last login timestamp
 */
router.get('/me', authenticateToken, (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          message: 'User not found'
        }
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    logger.error('Get current user error', {
      error: error.message,
      userId: req.user?.id,
      ip: req.ip
    });

    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error'
      }
    });
  }
});

/**
 * @api {post} /api/v1/auth/verify Verify Token
 * @apiName VerifyToken
 * @apiGroup Authentication
 * @apiVersion 1.0.0
 * 
 * @apiDescription Verify if JWT token is valid
 * 
 * @apiSuccess {Boolean} success Request success status
 * @apiSuccess {Boolean} valid Token validity status
 * @apiSuccess {Object} user User information (if valid)
 */
router.post('/verify', (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.json({
        success: true,
        valid: false,
        error: 'No token provided'
      });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, decoded) => {
      if (err) {
        return res.json({
          success: true,
          valid: false,
          error: err.message
        });
      }

      const user = users.find(u => u.id === decoded.id);

      res.json({
        success: true,
        valid: true,
        user: user ? {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role
        } : null
      });
    });

  } catch (error) {
    logger.error('Token verification error', {
      error: error.message,
      ip: req.ip
    });

    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error'
      }
    });
  }
});

/**
 * @api {post} /api/v1/auth/refresh Refresh Token
 * @apiName RefreshToken
 * @apiGroup Authentication
 * @apiVersion 1.0.0
 * 
 * @apiDescription Refresh JWT token
 * 
 * @apiSuccess {Boolean} success Request success status
 * @apiSuccess {String} token New JWT token
 * @apiSuccess {Object} user User information
 */
router.post('/refresh', authenticateToken, (req, res) => {
  try {
    const user = users.find(u => u.id === req.user.id);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: {
          message: 'User not found'
        }
      });
    }

    // Generate new JWT token
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET || 'your-secret-key',
      {
        expiresIn: process.env.JWT_EXPIRES_IN || '24h'
      }
    );

    logger.info('Token refreshed', {
      userId: user.id,
      username: user.username,
      ip: req.ip
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    logger.error('Token refresh error', {
      error: error.message,
      userId: req.user?.id,
      ip: req.ip
    });

    res.status(500).json({
      success: false,
      error: {
        message: 'Internal server error'
      }
    });
  }
});

export default router;