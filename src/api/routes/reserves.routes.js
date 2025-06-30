/**
 * Universal Bitcoin - Reserves Routes
 * 
 * REST API endpoints for proof-of-reserves functionality.
 * Provides transparent access to Bitcoin reserves and token supply data.
 * 
 * @author Universal Bitcoin Team
 */

import express from 'express';
import { query, validationResult } from 'express-validator';
import { asyncHandler, validationError } from '../middleware/error.middleware.js';
import { optionalAuth, requirePermission, requireAdmin } from '../middleware/auth.middleware.js';
import { ipRateLimit } from '../middleware/rateLimit.middleware.js';
import { logBitcoinOperation } from '../../utils/logger.util.js';
import logger from '../../utils/logger.util.js';
import { redis } from '../../config/redis.js';
import config from '../../config/index.js';

const router = express.Router();

/**
 * Cache durations for different data types
 */
const CACHE_DURATION = {
  RESERVES: 30,        // 30 seconds for reserves data
  SUPPLY: 60,          // 1 minute for token supply
  RATIO: 30,           // 30 seconds for reserve ratio
  HISTORICAL: 300      // 5 minutes for historical data
};

/**
 * @api {get} /api/v1/reserves Get Current Reserves
 * @apiName GetReserves
 * @apiGroup Reserves
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get current Bitcoin reserves and proof-of-reserves data
 * 
 * @apiSuccess {Object} bitcoin Bitcoin reserves information
 * @apiSuccess {String} bitcoin.address Bitcoin wallet address
 * @apiSuccess {Number} bitcoin.balance Current BTC balance
 * @apiSuccess {Number} bitcoin.utxos Number of UTXOs
 * @apiSuccess {String} bitcoin.lastUpdated Last update timestamp
 * @apiSuccess {Number} bitcoin.blockHeight Current block height
 * @apiSuccess {Object} tokens Token supply across all chains
 * @apiSuccess {Object} ratio Reserve ratio information
 * @apiSuccess {Number} ratio.current Current reserve ratio
 * @apiSuccess {String} ratio.status Health status (healthy, warning, critical)
 * @apiSuccess {Boolean} ratio.fullyBacked Whether tokens are fully backed
 */
router.get('/',
  ipRateLimit,
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cacheKey = 'reserves:current';
    
    try {
      // Try to get from cache first
      let reservesData = await redis.get(cacheKey);
      
      if (reservesData) {
        reservesData = JSON.parse(reservesData);
        reservesData.cached = true;
        
        return res.json({
          success: true,
          data: reservesData,
          meta: {
            cached: true,
            generatedAt: reservesData.generatedAt
          }
        });
      }
      
      // Generate fresh data
      const [bitcoinReserves, tokenSupply] = await Promise.all([
        getBitcoinReserves(),
        getTokenSupply()
      ]);
      
      // Calculate reserve ratio
      const reserveRatio = calculateReserveRatio(bitcoinReserves.balance, tokenSupply.total);
      
      const data = {
        bitcoin: bitcoinReserves,
        tokens: tokenSupply,
        ratio: reserveRatio,
        generatedAt: new Date().toISOString(),
        cached: false
      };
      
      // Cache the result
      await redis.setex(cacheKey, CACHE_DURATION.RESERVES, JSON.stringify(data));
      
      logBitcoinOperation('reserves_data_served', {
        bitcoinBalance: bitcoinReserves.balance,
        tokenSupply: tokenSupply.total,
        reserveRatio: reserveRatio.current,
        cached: false
      });
      
      res.json({
        success: true,
        data,
        meta: {
          cached: false,
          generatedAt: data.generatedAt
        }
      });
      
    } catch (error) {
      logger.error('Failed to get reserves data', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/reserves/proof Get Proof of Reserves
 * @apiName GetProofOfReserves
 * @apiGroup Reserves
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get cryptographic proof of Bitcoin reserves
 * 
 * @apiSuccess {Object} proof Proof of reserves data
 * @apiSuccess {String} proof.message Signed message
 * @apiSuccess {String} proof.signature Bitcoin signature
 * @apiSuccess {String} proof.address Bitcoin address
 * @apiSuccess {Number} proof.balance Proven balance
 * @apiSuccess {String} proof.timestamp Proof timestamp
 * @apiSuccess {Object} verification Verification instructions
 */
router.get('/proof',
  ipRateLimit,
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cacheKey = 'reserves:proof';
    
    try {
      // Try to get from cache
      let proofData = await redis.get(cacheKey);
      
      if (proofData) {
        proofData = JSON.parse(proofData);
        
        return res.json({
          success: true,
          data: proofData,
          meta: {
            cached: true,
            generatedAt: proofData.generatedAt
          }
        });
      }
      
      // Generate fresh proof
      const proof = await generateProofOfReserves();
      
      // Cache the proof
      await redis.setex(cacheKey, CACHE_DURATION.RESERVES, JSON.stringify(proof));
      
      logBitcoinOperation('proof_of_reserves_generated', {
        address: proof.address,
        balance: proof.balance,
        signatureLength: proof.signature.length
      });
      
      res.json({
        success: true,
        data: proof,
        meta: {
          cached: false,
          generatedAt: proof.generatedAt
        }
      });
      
    } catch (error) {
      logger.error('Failed to generate proof of reserves', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/reserves/history Get Reserves History
 * @apiName GetReservesHistory
 * @apiGroup Reserves
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get historical reserves and ratio data
 * 
 * @apiParam {String} [timeframe=24h] Time frame (1h, 24h, 7d, 30d)
 * @apiParam {Number} [limit=100] Number of data points (max 1000)
 */
router.get('/history',
  ipRateLimit,
  optionalAuth,
  [
    query('timeframe').optional().isIn(['1h', '24h', '7d', '30d']).withMessage('Invalid timeframe'),
    query('limit').optional().isInt({ min: 1, max: 1000 }).withMessage('Invalid limit')
  ],
  asyncHandler(async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw validationError('Invalid query parameters', errors.array());
    }
    
    const { timeframe = '24h', limit = 100 } = req.query;
    const cacheKey = `reserves:history:${timeframe}:${limit}`;
    
    try {
      // Try to get from cache
      let historyData = await redis.get(cacheKey);
      
      if (historyData) {
        historyData = JSON.parse(historyData);
        
        return res.json({
          success: true,
          data: historyData,
          meta: {
            cached: true,
            timeframe,
            limit: parseInt(limit)
          }
        });
      }
      
      // Generate fresh history data
      const history = await getReservesHistory(timeframe, parseInt(limit));
      
      // Cache the history
      await redis.setex(cacheKey, CACHE_DURATION.HISTORICAL, JSON.stringify(history));
      
      res.json({
        success: true,
        data: history,
        meta: {
          cached: false,
          timeframe,
          limit: parseInt(limit),
          generatedAt: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.error('Failed to get reserves history', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {get} /api/v1/reserves/chains Get Multi-chain Supply
 * @apiName GetMultiChainSupply
 * @apiGroup Reserves
 * @apiVersion 1.0.0
 * 
 * @apiDescription Get token supply breakdown across all supported chains
 */
router.get('/chains',
  ipRateLimit,
  optionalAuth,
  asyncHandler(async (req, res) => {
    const cacheKey = 'reserves:chains';
    
    try {
      // Try to get from cache
      let chainsData = await redis.get(cacheKey);
      
      if (chainsData) {
        chainsData = JSON.parse(chainsData);
        
        return res.json({
          success: true,
          data: chainsData,
          meta: {
            cached: true,
            generatedAt: chainsData.generatedAt
          }
        });
      }
      
      // Generate fresh chains data
      const chains = await getMultiChainSupply();
      
      // Cache the data
      await redis.setex(cacheKey, CACHE_DURATION.SUPPLY, JSON.stringify(chains));
      
      res.json({
        success: true,
        data: chains,
        meta: {
          cached: false,
          generatedAt: chains.generatedAt
        }
      });
      
    } catch (error) {
      logger.error('Failed to get multi-chain supply', { error: error.message });
      throw error;
    }
  })
);

/**
 * @api {post} /api/v1/reserves/update Update Reserves
 * @apiName UpdateReserves
 * @apiGroup Reserves
 * @apiVersion 1.0.0
 * 
 * @apiDescription Manually trigger reserves update (Admin only)
 */
router.post('/update',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      // Clear caches
      const cacheKeys = [
        'reserves:current',
        'reserves:proof',
        'reserves:chains'
      ];
      
      await Promise.all(cacheKeys.map(key => redis.del(key)));
      
      // Force refresh of reserves data
      const [bitcoinReserves, tokenSupply] = await Promise.all([
        getBitcoinReserves(true), // Force refresh
        getTokenSupply(true)      // Force refresh
      ]);
      
      const reserveRatio = calculateReserveRatio(bitcoinReserves.balance, tokenSupply.total);
      
      logBitcoinOperation('reserves_manually_updated', {
        userId: req.user.id,
        bitcoinBalance: bitcoinReserves.balance,
        tokenSupply: tokenSupply.total,
        reserveRatio: reserveRatio.current
      });
      
      res.json({
        success: true,
        data: {
          bitcoin: bitcoinReserves,
          tokens: tokenSupply,
          ratio: reserveRatio,
          updatedAt: new Date().toISOString(),
          updatedBy: req.user.id
        },
        message: 'Reserves data updated successfully'
      });
      
    } catch (error) {
      logger.error('Failed to update reserves', { 
        error: error.message, 
        userId: req.user.id 
      });
      throw error;
    }
  })
);

/**
 * Helper functions
 */

/**
 * Get Bitcoin reserves data
 */
async function getBitcoinReserves(forceRefresh = false) {
  try {
    // Import Bitcoin service
    const BitcoinService = await import('../../services/bitcoin.service.js');
    const bitcoinService = new BitcoinService.default();
    
    // Get current reserves
    const reserves = await bitcoinService.calculateReserves();
    
    return {
      address: reserves.address,
      balance: reserves.balance,
      utxos: reserves.utxos,
      lastUpdated: reserves.lastUpdated,
      blockHeight: reserves.blockHeight,
      network: config.bitcoin.network || 'mainnet'
    };
    
  } catch (error) {
    logger.error('Failed to get Bitcoin reserves', { error: error.message });
    throw error;
  }
}

/**
 * Get token supply across all chains
 */
async function getTokenSupply(forceRefresh = false) {
  try {
    // In production, this would query actual blockchain contracts
    // For development, we'll simulate the data
    
    const chains = {
      ethereum: {
        supply: 5.2,
        contract: '0x1234567890123456789012345678901234567890',
        lastUpdated: new Date().toISOString()
      },
      solana: {
        supply: 2.8,
        contract: 'So11111111111111111111111111111111111111112',
        lastUpdated: new Date().toISOString()
      },
      polygon: {
        supply: 1.5,
        contract: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
        lastUpdated: new Date().toISOString()
      },
      arbitrum: {
        supply: 0.8,
        contract: '0x9876543210987654321098765432109876543210',
        lastUpdated: new Date().toISOString()
      },
      bsc: {
        supply: 0.2,
        contract: '0x5555555555555555555555555555555555555555',
        lastUpdated: new Date().toISOString()
      }
    };
    
    const total = Object.values(chains).reduce((sum, chain) => sum + chain.supply, 0);
    
    return {
      chains,
      total,
      lastUpdated: new Date().toISOString()
    };
    
  } catch (error) {
    logger.error('Failed to get token supply', { error: error.message });
    throw error;
  }
}

/**
 * Calculate reserve ratio
 */
function calculateReserveRatio(bitcoinBalance, tokenSupply) {
  if (tokenSupply === 0) {
    return {
      current: 0,
      status: 'no_tokens',
      fullyBacked: true,
      message: 'No tokens in circulation'
    };
  }
  
  const ratio = (bitcoinBalance / tokenSupply) * 100;
  
  let status = 'healthy';
  let message = 'Reserves are healthy';
  
  if (ratio < 100) {
    status = 'critical';
    message = 'Reserves below 100% - tokens not fully backed';
  } else if (ratio < 110) {
    status = 'warning';
    message = 'Reserves below 110% - monitoring required';
  }
  
  return {
    current: Math.round(ratio * 100) / 100, // Round to 2 decimal places
    status,
    fullyBacked: ratio >= 100,
    message,
    bitcoinBalance,
    tokenSupply,
    excess: Math.max(0, bitcoinBalance - tokenSupply)
  };
}

/**
 * Generate proof of reserves
 */
async function generateProofOfReserves() {
  try {
    // Import Bitcoin service
    const BitcoinService = await import('../../services/bitcoin.service.js');
    const bitcoinService = new BitcoinService.default();
    
    // Get current reserves
    const reserves = await bitcoinService.calculateReserves();
    
    // Create proof message
    const timestamp = new Date().toISOString();
    const message = `Universal Bitcoin Proof of Reserves - ${timestamp} - Balance: ${reserves.balance} BTC - Address: ${reserves.address}`;
    
    // Generate signature with Guardian consensus
    const signature = await bitcoinService.signWithGuardianConsensus(message);
    
    return {
      message,
      signature: signature.signature,
      address: signature.address,
      balance: reserves.balance,
      timestamp,
      blockHeight: reserves.blockHeight,
      verification: {
        instructions: 'Verify this signature using any Bitcoin message verification tool',
        command: `bitcoin-cli verifymessage ${signature.address} "${signature.signature}" "${message}"`,
        onlineTools: [
          'https://www.bitcoin.com/tools/verify-message/',
          'https://bitcoinaddress.org/verify'
        ]
      },
      generatedAt: new Date().toISOString()
    };
    
  } catch (error) {
    logger.error('Failed to generate proof of reserves', { error: error.message });
    throw error;
  }
}

/**
 * Get reserves history
 */
async function getReservesHistory(timeframe, limit) {
  try {
    // In production, this would query TimescaleDB
    // For development, we'll simulate historical data
    
    const now = Date.now();
    const intervals = {
      '1h': 60 * 1000,        // 1 minute intervals
      '24h': 60 * 60 * 1000,  // 1 hour intervals
      '7d': 6 * 60 * 60 * 1000, // 6 hour intervals
      '30d': 24 * 60 * 60 * 1000 // 1 day intervals
    };
    
    const interval = intervals[timeframe];
    const dataPoints = [];
    
    for (let i = 0; i < limit; i++) {
      const timestamp = new Date(now - (i * interval));
      
      // Simulate historical data with some variation
      const baseBalance = 10.5;
      const variation = (Math.random() - 0.5) * 0.2; // ±0.1 BTC variation
      const bitcoinBalance = baseBalance + variation;
      
      const baseSupply = 10.5;
      const supplyVariation = (Math.random() - 0.5) * 0.1;
      const tokenSupply = baseSupply + supplyVariation;
      
      const ratio = (bitcoinBalance / tokenSupply) * 100;
      
      dataPoints.unshift({
        timestamp: timestamp.toISOString(),
        bitcoinBalance: Math.round(bitcoinBalance * 100000000) / 100000000, // 8 decimal places
        tokenSupply: Math.round(tokenSupply * 100000000) / 100000000,
        ratio: Math.round(ratio * 100) / 100,
        status: ratio >= 100 ? 'healthy' : 'warning'
      });
    }
    
    return {
      timeframe,
      dataPoints,
      summary: {
        count: dataPoints.length,
        avgRatio: dataPoints.reduce((sum, dp) => sum + dp.ratio, 0) / dataPoints.length,
        minRatio: Math.min(...dataPoints.map(dp => dp.ratio)),
        maxRatio: Math.max(...dataPoints.map(dp => dp.ratio))
      },
      generatedAt: new Date().toISOString()
    };
    
  } catch (error) {
    logger.error('Failed to get reserves history', { error: error.message });
    throw error;
  }
}

/**
 * Get multi-chain supply data
 */
async function getMultiChainSupply() {
  try {
    const tokenSupply = await getTokenSupply();
    const bitcoinBalance = (await getBitcoinReserves()).balance;
    
    // Add additional metrics per chain
    const enhancedChains = {};
    
    for (const [chainName, chainData] of Object.entries(tokenSupply.chains)) {
      const chainRatio = (bitcoinBalance * (chainData.supply / tokenSupply.total)) / chainData.supply * 100;
      
      enhancedChains[chainName] = {
        ...chainData,
        percentageOfTotal: (chainData.supply / tokenSupply.total) * 100,
        allocatedReserves: bitcoinBalance * (chainData.supply / tokenSupply.total),
        ratio: chainRatio,
        holders: Math.floor(Math.random() * 1000) + 100, // Simulated
        transactions24h: Math.floor(Math.random() * 100) + 10 // Simulated
      };
    }
    
    return {
      chains: enhancedChains,
      summary: {
        totalSupply: tokenSupply.total,
        totalReserves: bitcoinBalance,
        overallRatio: (bitcoinBalance / tokenSupply.total) * 100,
        supportedChains: Object.keys(enhancedChains).length
      },
      generatedAt: new Date().toISOString()
    };
    
  } catch (error) {
    logger.error('Failed to get multi-chain supply', { error: error.message });
    throw error;
  }
}

export default router;