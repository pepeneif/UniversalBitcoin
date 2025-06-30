/**
 * Universal Bitcoin - Redis Configuration
 * 
 * Redis connection management for caching, session storage, and queue management.
 * Includes connection pooling, error handling, and health monitoring.
 * 
 * @author Universal Bitcoin Team
 */

import Redis from 'ioredis';
import config from './index.js';
import logger from '../utils/logger.util.js';

let redis;
let subscriber;
let publisher;

/**
 * Redis connection configuration
 */
const redisConfig = {
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  db: config.redis.db,
  maxRetriesPerRequest: config.redis.maxRetriesPerRequest,
  retryDelayOnFailover: config.redis.retryDelayOnFailover,
  connectTimeout: config.redis.connectTimeout,
  lazyConnect: config.redis.lazyConnect,
  
  // Connection pool settings
  family: 4, // IPv4
  keepAlive: true,
  maxConnections: 10,
  
  // Retry strategy
  retryDelayOnClusterDown: 300,
  retryDelayOnDowngrade: null,
  maxConnections: 10,
  
  // Additional settings for production
  commandTimeout: 5000,
  enableReadyCheck: true,
  enableOfflineQueue: false,
};

/**
 * Connect to Redis
 */
export async function connectRedis() {
  try {
    // Main Redis connection
    redis = new Redis(redisConfig);
    
    // Publisher/Subscriber connections for pub/sub operations
    publisher = new Redis(redisConfig);
    subscriber = new Redis(redisConfig);
    
    // Test the connection
    await redis.ping();
    
    logger.info('Redis connections established successfully', {
      host: config.redis.host,
      port: config.redis.port,
      db: config.redis.db
    });
    
    // Set up event handlers
    setupRedisEventHandlers(redis, 'main');
    setupRedisEventHandlers(publisher, 'publisher');
    setupRedisEventHandlers(subscriber, 'subscriber');
    
    return { redis, publisher, subscriber };
  } catch (error) {
    logger.error('Failed to connect to Redis', {
      error: error.message,
      stack: error.stack,
      host: config.redis.host,
      port: config.redis.port
    });
    throw error;
  }
}

/**
 * Set up Redis event handlers
 */
function setupRedisEventHandlers(client, type) {
  client.on('connect', () => {
    logger.debug(`Redis ${type} client connected`, {
      host: config.redis.host,
      port: config.redis.port
    });
  });
  
  client.on('ready', () => {
    logger.info(`Redis ${type} client ready`, {
      host: config.redis.host,
      port: config.redis.port
    });
  });
  
  client.on('error', (error) => {
    logger.error(`Redis ${type} client error`, {
      error: error.message,
      stack: error.stack
    });
  });
  
  client.on('close', () => {
    logger.warn(`Redis ${type} client connection closed`);
  });
  
  client.on('reconnecting', (delay) => {
    logger.info(`Redis ${type} client reconnecting`, { delay });
  });
  
  client.on('end', () => {
    logger.warn(`Redis ${type} client connection ended`);
  });
}

/**
 * Get Redis client instances
 */
export function getRedis() {
  if (!redis) {
    throw new Error('Redis not connected. Call connectRedis() first.');
  }
  return redis;
}

export function getPublisher() {
  if (!publisher) {
    throw new Error('Redis publisher not connected. Call connectRedis() first.');
  }
  return publisher;
}

export function getSubscriber() {
  if (!subscriber) {
    throw new Error('Redis subscriber not connected. Call connectRedis() first.');
  }
  return subscriber;
}

/**
 * Cache utility functions
 */
export const cache = {
  /**
   * Set a value with TTL
   */
  async set(key, value, ttl = config.cache.ttl.apiResponse) {
    try {
      const serialized = JSON.stringify(value);
      await redis.setex(key, ttl, serialized);
      
      logger.debug('Cache set', { key, ttl });
    } catch (error) {
      logger.error('Cache set failed', {
        key,
        error: error.message
      });
      throw error;
    }
  },
  
  /**
   * Get a value from cache
   */
  async get(key) {
    try {
      const value = await redis.get(key);
      
      if (value === null) {
        logger.debug('Cache miss', { key });
        return null;
      }
      
      logger.debug('Cache hit', { key });
      return JSON.parse(value);
    } catch (error) {
      logger.error('Cache get failed', {
        key,
        error: error.message
      });
      return null; // Return null on error to allow fallback
    }
  },
  
  /**
   * Delete a key from cache
   */
  async del(key) {
    try {
      const result = await redis.del(key);
      logger.debug('Cache delete', { key, deleted: result });
      return result;
    } catch (error) {
      logger.error('Cache delete failed', {
        key,
        error: error.message
      });
    }
  },
  
  /**
   * Check if key exists
   */
  async exists(key) {
    try {
      return await redis.exists(key);
    } catch (error) {
      logger.error('Cache exists check failed', {
        key,
        error: error.message
      });
      return false;
    }
  },
  
  /**
   * Set TTL for existing key
   */
  async expire(key, ttl) {
    try {
      return await redis.expire(key, ttl);
    } catch (error) {
      logger.error('Cache expire failed', {
        key,
        ttl,
        error: error.message
      });
      return false;
    }
  },
  
  /**
   * Increment a counter
   */
  async incr(key, amount = 1) {
    try {
      return await redis.incrby(key, amount);
    } catch (error) {
      logger.error('Cache increment failed', {
        key,
        amount,
        error: error.message
      });
      throw error;
    }
  },
  
  /**
   * Set with NX (only if not exists)
   */
  async setnx(key, value, ttl = config.cache.ttl.apiResponse) {
    try {
      const result = await redis.set(key, JSON.stringify(value), 'EX', ttl, 'NX');
      return result === 'OK';
    } catch (error) {
      logger.error('Cache setnx failed', {
        key,
        error: error.message
      });
      return false;
    }
  }
};

/**
 * Rate limiting utilities
 */
export const rateLimiting = {
  /**
   * Check and increment rate limit counter
   */
  async checkLimit(identifier, limit, windowMs) {
    const key = `ratelimit:${identifier}`;
    
    try {
      const current = await redis.incr(key);
      
      if (current === 1) {
        await redis.expire(key, Math.ceil(windowMs / 1000));
      }
      
      return {
        current,
        remaining: Math.max(0, limit - current),
        resetTime: Date.now() + windowMs
      };
    } catch (error) {
      logger.error('Rate limit check failed', {
        identifier,
        error: error.message
      });
      throw error;
    }
  },
  
  /**
   * Reset rate limit for identifier
   */
  async resetLimit(identifier) {
    const key = `ratelimit:${identifier}`;
    return await redis.del(key);
  }
};

/**
 * Session management utilities
 */
export const sessions = {
  /**
   * Store session data
   */
  async set(sessionId, data, ttl = 3600) {
    const key = `session:${sessionId}`;
    return await cache.set(key, data, ttl);
  },
  
  /**
   * Get session data
   */
  async get(sessionId) {
    const key = `session:${sessionId}`;
    return await cache.get(key);
  },
  
  /**
   * Delete session
   */
  async delete(sessionId) {
    const key = `session:${sessionId}`;
    return await cache.del(key);
  }
};

/**
 * Health check for Redis
 */
export async function healthCheck() {
  try {
    const start = Date.now();
    await redis.ping();
    const latency = Date.now() - start;
    
    const info = await redis.info('memory');
    const memoryMatch = info.match(/used_memory_human:(.+)/);
    const memory = memoryMatch ? memoryMatch[1].trim() : 'unknown';
    
    return {
      status: 'healthy',
      connected: true,
      latency,
      memory,
      connections: {
        main: redis.status,
        publisher: publisher.status,
        subscriber: subscriber.status
      }
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      connected: false,
      error: error.message
    };
  }
}

/**
 * Close Redis connections gracefully
 */
export async function closeRedis() {
  const promises = [];
  
  if (redis) {
    promises.push(redis.quit());
  }
  
  if (publisher) {
    promises.push(publisher.quit());
  }
  
  if (subscriber) {
    promises.push(subscriber.quit());
  }
  
  try {
    await Promise.all(promises);
    logger.info('Redis connections closed successfully');
  } catch (error) {
    logger.error('Error closing Redis connections', {
      error: error.message
    });
  }
}

export default {
  connectRedis,
  getRedis,
  getPublisher,
  getSubscriber,
  cache,
  rateLimiting,
  sessions,
  healthCheck,
  closeRedis
};