/**
 * Universal Bitcoin - Validation Routes
 * 
 * REST API endpoints for validation requests and status checking.
 * Implements pay-per-validation model with Guardian Angels security.
 * 
 * @author Universal Bitcoin Team
 */

import express from 'express';
import { body, param, query, validationResult } from 'express-validator';
import { ValidationProcessor } from '../../validation/processor.service.js';
import { asyncHandler, validationError } from '../middleware/error.middleware.js';
import { optionalAuth, requirePermission } from '../middleware/auth.middleware.js';
import { validationRateLimit, revenuePreservation } from '../middleware/rateLimit.middleware.js';
import { logValidationEvent } from '../../utils/logger.util.js';
import config from '../../config/index.js';

const router = express.Router();
const validationProcessor = new ValidationProcessor();

/**
 * Input validation schemas
 */
const validationRequestSchema = [
  body('chain')
    .isIn(['ethereum', 'solana', 'polygon', 'arbitrum', 'bsc'])
    .withMessage('Invalid blockchain network'),
  
  body('txHash')
    .notEmpty()
    .withMessage('Transaction hash is required')
    .custom((value, { req }) => {
      const { chain } = req.body;
      const patterns = {
        ethereum: /^0x[a-fA-F0-9]{64}$/,
        solana: /^[1-9A-HJ-NP-Za-km-z]{43,44}$/,
        polygon: /^0x[a-fA-F0-9]{64}$/,
        arbitrum: /^0x[a-fA-F0-9]{64}$/,
        bsc: /^0x[a-fA-F0-9]{64}$/
      };
      
      if (chain && patterns[chain] && !patterns[chain].test(value)) {
        throw new Error(`Invalid transaction hash format for ${chain}`);
      }
      
      return true;
    }),
  
  body('fromAddress')
    .notEmpty()
    .withMessage('From address is required')
    .isLength({ min: 26, max: 128 })
    .withMessage('Invalid address format'),
  
  body('message')
    .notEmpty()
    .withMessage('Message is required')
    .isLength({ min: 1, max: 500 })
    .withMessage('Message must be between 1 and 500 characters')
    .trim()
    .escape(),
  
  body('type')
    .optional()
    .isIn(['proof_of_reserves', 'custom_message', 'wallet_verification'])
    .withMessage('Invalid validation type')
];

const statusQuerySchema = [
  param('validationId')
    .matches(/^val_[a-z0-9]+_[a-f0-9]{8}$/)
    .withMessage('Invalid validation ID format')
];

/**
 * @api {post} /api/v1/validate Submit Validation Request
 * @apiName SubmitValidation
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Submit a validation request after making payment to trigger Bitcoin proof generation
 * 
 * @apiParam {String} chain Blockchain network (ethereum, solana, polygon, arbitrum, bsc)
 * @apiParam {String} txHash Transaction hash of the payment
 * @apiParam {String} fromAddress Address that made the payment
 * @apiParam {String} message Custom message to be signed as proof (max 500 chars)
 * @apiParam {String} [type=proof_of_reserves] Validation type
 * 
 * @apiSuccess {String} validationId Unique validation request ID
 * @apiSuccess {String} status Current status (pending, processing, completed)
 * @apiSuccess {Number} queuePosition Position in processing queue
 * @apiSuccess {Number} estimatedProcessingTime Estimated completion time in seconds
 * 
 * @apiError {Object} 400 Invalid request parameters
 * @apiError {Object} 429 Rate limit exceeded (request queued)
 * @apiError {Object} 500 Internal server error
 */
router.post('/validate',
  validationRateLimit,
  revenuePreservation,
  optionalAuth,
  validationRequestSchema,
  asyncHandler(async (req, res) => {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid validation request', errors.array());
    }
    
    const { chain, txHash, fromAddress, message, type } = req.body;
    
    // Create validation request
    const validationRequest = {
      chain,
      txHash,
      fromAddress,
      message,
      type: type || 'proof_of_reserves',
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      userId: req.user?.id,
      requestId: req.headers['x-request-id'] || `req_${Date.now()}`
    };
    
    logValidationEvent('validation_request_received', {
      chain,
      fromAddress,
      messageLength: message.length,
      ip: req.ip,
      userId: req.user?.id
    });
    
    // Submit validation
    const result = await validationProcessor.submitValidation(validationRequest);
    
    res.status(202).json({
      success: true,
      data: {
        validationId: result.validationId,
        status: result.status,
        queuePosition: result.queuePosition,
        estimatedProcessingTime: result.estimatedProcessingTime,
        message: 'Validation request submitted successfully'
      },
      meta: {
        chain,
        type: validationRequest.type,
        timestamp: new Date().toISOString()
      }
    });
  })
);

/**
 * @api {get} /api/v1/validate/:validationId Get Validation Status
 * @apiName GetValidationStatus
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get the current status and result of a validation request
 * 
 * @apiParam {String} validationId Unique validation ID
 * 
 * @apiSuccess {String} id Validation ID
 * @apiSuccess {String} status Current status
 * @apiSuccess {String} type Validation type
 * @apiSuccess {String} chain Blockchain network
 * @apiSuccess {String} createdAt Creation timestamp
 * @apiSuccess {String} updatedAt Last update timestamp
 * @apiSuccess {String} expiresAt Expiration timestamp
 * @apiSuccess {Object} [result] Validation result (if completed)
 * @apiSuccess {String} [result.signature] Bitcoin signature
 * @apiSuccess {String} [result.bitcoinAddress] Bitcoin address used for signing
 * @apiSuccess {String} [result.message] Signed message
 * @apiSuccess {Number} [result.amount] Payment amount verified
 * @apiSuccess {Number} [result.fee] Validation fee
 * 
 * @apiError {Object} 404 Validation not found
 * @apiError {Object} 500 Internal server error
 */
router.get('/validate/:validationId',
  statusQuerySchema,
  asyncHandler(async (req, res) => {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid validation ID', errors.array());
    }
    
    const { validationId } = req.params;
    
    // Get validation status
    const validation = await validationProcessor.getValidationStatus(validationId);
    
    logValidationEvent('validation_status_requested', {
      validationId,
      status: validation.status,
      ip: req.ip
    });
    
    // Prepare response based on status
    const response = {
      success: true,
      data: {
        id: validation.id,
        status: validation.status,
        type: validation.type,
        chain: validation.chain,
        createdAt: validation.createdAt,
        updatedAt: validation.updatedAt,
        expiresAt: validation.expiresAt
      }
    };
    
    // Add queue information for pending validations
    if (validation.status === 'pending') {
      response.data.queue = {
        position: validation.queuePosition,
        estimatedProcessingTime: validation.estimatedProcessingTime
      };
    }
    
    // Add result for completed validations
    if (validation.status === 'completed') {
      response.data.result = {
        signature: validation.signature,
        bitcoinAddress: validation.bitcoinAddress,
        message: validation.message,
        amount: validation.amount,
        fee: validation.fee
      };
    }
    
    // Add error for failed validations
    if (validation.status === 'failed') {
      response.data.error = validation.error;
    }
    
    res.json(response);
  })
);

/**
 * @api {get} /api/v1/validate Get Validation List
 * @apiName GetValidationList
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get a list of validation requests (requires authentication)
 * 
 * @apiParam {Number} [page=1] Page number
 * @apiParam {Number} [limit=10] Items per page (max 100)
 * @apiParam {String} [status] Filter by status
 * @apiParam {String} [chain] Filter by blockchain
 * @apiParam {String} [type] Filter by validation type
 * 
 * @apiSuccess {Object[]} validations Array of validation objects
 * @apiSuccess {Object} pagination Pagination information
 * 
 * @apiError {Object} 401 Authentication required
 * @apiError {Object} 500 Internal server error
 */
router.get('/validate',
  optionalAuth,
  requirePermission('status:view'),
  [
    query('page').optional().isInt({ min: 1 }).withMessage('Invalid page number'),
    query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Invalid limit'),
    query('status').optional().isIn(['pending', 'processing', 'completed', 'failed', 'expired']),
    query('chain').optional().isIn(['ethereum', 'solana', 'polygon', 'arbitrum', 'bsc']),
    query('type').optional().isIn(['proof_of_reserves', 'custom_message', 'wallet_verification'])
  ],
  asyncHandler(async (req, res) => {
    // Check validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid query parameters', errors.array());
    }
    
    const {
      page = 1,
      limit = 10,
      status,
      chain,
      type
    } = req.query;
    
    // Build filters
    const filters = {};
    if (status) filters.status = status;
    if (chain) filters.chain = chain;
    if (type) filters.type = type;
    
    // For regular users, only show their validations
    if (req.user && req.user.role === 'user') {
      filters.userId = req.user.id;
    }
    
    // Get validations (placeholder - implement with actual database query)
    const validations = []; // TODO: Implement database query
    const total = 0; // TODO: Implement count query
    
    res.json({
      success: true,
      data: validations,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      },
      filters
    });
  })
);

/**
 * @api {get} /api/v1/validate/pricing Get Validation Pricing
 * @apiName GetValidationPricing
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get current validation pricing for all supported chains
 * 
 * @apiSuccess {Object} pricing Pricing information per chain
 * @apiSuccess {Object} fees Fee structure
 */
router.get('/pricing',
  asyncHandler(async (req, res) => {
    const pricing = {
      ethereum: {
        validationFee: config.pricing?.ethereum?.validationFee || 0.01,
        currency: 'ETH',
        usdEquivalent: null // TODO: Get from price oracle
      },
      solana: {
        validationFee: config.pricing?.solana?.validationFee || 0.1,
        currency: 'SOL',
        usdEquivalent: null
      },
      polygon: {
        validationFee: config.pricing?.polygon?.validationFee || 10,
        currency: 'MATIC',
        usdEquivalent: null
      },
      arbitrum: {
        validationFee: config.pricing?.arbitrum?.validationFee || 0.01,
        currency: 'ETH',
        usdEquivalent: null
      },
      bsc: {
        validationFee: config.pricing?.bsc?.validationFee || 0.05,
        currency: 'BNB',
        usdEquivalent: null
      }
    };
    
    res.json({
      success: true,
      data: {
        pricing,
        lastUpdated: new Date().toISOString(),
        rateLimits: {
          validationsPerHour: 10,
          queueProcessingTime: '30-60 seconds'
        }
      }
    });
  })
);

/**
 * @api {get} /api/v1/validate/stats Get Validation Statistics
 * @apiName GetValidationStats
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get validation statistics and system metrics
 */
router.get('/stats',
  asyncHandler(async (req, res) => {
    // TODO: Implement actual statistics from database
    const stats = {
      total: {
        validations: 1250,
        successful: 1198,
        failed: 42,
        pending: 10
      },
      byChain: {
        ethereum: 650,
        solana: 300,
        polygon: 200,
        arbitrum: 75,
        bsc: 25
      },
      performance: {
        averageProcessingTime: 45, // seconds
        successRate: 95.8, // percentage
        queueLength: 5
      },
      revenue: {
        totalFees: 156.7, // USD equivalent
        last24h: 23.4,
        last7d: 178.9
      }
    };
    
    res.json({
      success: true,
      data: stats,
      generatedAt: new Date().toISOString()
    });
  })
);

/**
 * @api {post} /api/v1/validate/:validationId/verify Verify Signature
 * @apiName VerifySignature
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Verify a Bitcoin signature independently
 */
router.post('/validate/:validationId/verify',
  statusQuerySchema,
  [
    body('signature').notEmpty().withMessage('Signature is required'),
    body('message').notEmpty().withMessage('Message is required'),
    body('address').notEmpty().withMessage('Bitcoin address is required')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid verification request', errors.array());
    }
    
    const { validationId } = req.params;
    const { signature, message, address } = req.body;
    
    // Import Bitcoin service for verification
    const BitcoinService = await import('../../services/bitcoin.service.js');
    const bitcoinService = new BitcoinService.default();
    
    // Verify signature
    const isValid = bitcoinService.verifyBitcoinMessage(message, address, signature);
    
    logValidationEvent('signature_verified', {
      validationId,
      isValid,
      address,
      ip: req.ip
    });
    
    res.json({
      success: true,
      data: {
        valid: isValid,
        signature,
        message,
        address,
        verifiedAt: new Date().toISOString()
      }
    });
  })
);

export default router;