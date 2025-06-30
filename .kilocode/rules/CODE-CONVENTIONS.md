# Universal Bitcoin Code Conventions

## 🎯 Overview

This document establishes coding standards and conventions for the Universal Bitcoin proof-of-reserves system to ensure consistency, maintainability, and security across the codebase.

## 📝 General Principles

### 1. **Clarity Over Cleverness**
```javascript
// ❌ Avoid - Clever but unclear
const isValid = !!(payment?.amount > 0 && payment?.chain && payment?.tx);

// ✅ Prefer - Clear and explicit
function isValidPayment(payment) {
  return payment && 
         payment.amount > 0 && 
         payment.chain && 
         payment.tx;
}
```

### 2. **Security First**
```javascript
// ❌ Avoid - Potential security risk
const query = `SELECT * FROM validations WHERE id = ${id}`;

// ✅ Prefer - Parameterized queries
const query = 'SELECT * FROM validations WHERE id = $1';
const result = await db.query(query, [id]);
```

### 3. **Explicit Error Handling**
```javascript
// ❌ Avoid - Silent failures
try {
  const signature = await bitcoinService.signMessage(message);
  return signature;
} catch (error) {
  return null;
}

// ✅ Prefer - Explicit error handling
try {
  const signature = await bitcoinService.signMessage(message);
  return { success: true, signature };
} catch (error) {
  logger.error('Bitcoin signing failed', { error: error.message, message });
  return { success: false, error: error.message };
}
```

## 🏗️ Project Structure

### Directory Organization
```
src/
├── api/                    # HTTP API layer
│   ├── controllers/        # Request handlers
│   ├── middleware/         # Express middleware
│   ├── routes/             # Route definitions
│   └── validators/         # Input validation
├── services/               # Business logic
│   ├── bitcoin.service.js  # Bitcoin operations
│   ├── validation.service.js # Validation logic
│   ├── payment.service.js  # Payment processing
│   └── reserve.service.js  # Reserve management
├── blockchain/             # Blockchain integrations
│   ├── adapters/           # Chain-specific adapters
│   ├── monitoring/         # Payment monitoring
│   └── contracts/          # Smart contract interfaces
├── security/               # Security utilities
│   ├── encryption.util.js  # Encryption/decryption
│   ├── auth.middleware.js  # Authentication
│   └── guardian.service.js # Guardian Angels logic
├── validation/             # Core validation engine
│   ├── queue.service.js    # Queue management
│   ├── processor.service.js # Validation processing
│   └── signing.service.js  # Message signing
├── webhooks/               # Webhook system
│   ├── handlers/           # Event handlers
│   └── delivery.service.js # Webhook delivery
├── models/                 # Data models
├── utils/                  # Utility functions
├── config/                 # Configuration files
└── tests/                  # Test files
```

## 📋 Naming Conventions

### Files and Directories
```
# Files
bitcoin.service.js          # Service files
validation.controller.js    # Controller files
payment.model.js           # Model files
encryption.util.js         # Utility files
auth.middleware.js         # Middleware files

# Directories
lowercase-with-dashes/     # Directory names
camelCase/                 # Avoid
snake_case/                # Avoid
```

### Variables and Functions
```javascript
// Variables - camelCase
const bitcoinAddress = 'bc1q...';
const validationResult = await processValidation();

// Functions - camelCase with descriptive names
function validatePaymentAmount(amount, minimumRequired) { }
async function signBitcoinMessage(message, privateKey) { }

// Constants - SCREAMING_SNAKE_CASE
const MAX_VALIDATIONS_PER_HOUR = 10;
const BITCOIN_NETWORK = 'mainnet';
const GUARDIAN_THRESHOLD = 3;

// Classes - PascalCase
class ValidationService { }
class BitcoinWallet { }
class GuardianConsensus { }
```

### Database Schema
```sql
-- Tables - snake_case
CREATE TABLE validation_requests (
    id UUID PRIMARY KEY,
    chain_name VARCHAR(50) NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    from_address VARCHAR(128) NOT NULL
);

-- Columns - snake_case
payment_amount DECIMAL(20,8)
created_at TIMESTAMP
bitcoin_signature TEXT
guardian_approvals JSONB
```

## 🔧 Code Style

### TypeScript/JavaScript Style

#### Function Declarations
```javascript
// ✅ Prefer - Async/await for promises
async function processValidation(request) {
  try {
    const payment = await detectPayment(request.txHash);
    const signature = await signMessage(request.message);
    return { payment, signature };
  } catch (error) {
    throw new ValidationError('Processing failed', error);
  }
}

// ❌ Avoid - Promise chains when async/await is clearer
function processValidation(request) {
  return detectPayment(request.txHash)
    .then(payment => signMessage(request.message)
      .then(signature => ({ payment, signature })))
    .catch(error => {
      throw new ValidationError('Processing failed', error);
    });
}
```

#### Object and Array Handling
```javascript
// ✅ Prefer - Destructuring for readability
const { chain, amount, message } = validationRequest;
const [firstGuardian, ...otherGuardians] = guardianList;

// ✅ Prefer - Spread operator for immutability
const updatedRequest = {
  ...validationRequest,
  status: 'processed',
  signature: bitcoinSignature
};

// ✅ Prefer - Array methods over loops
const validChains = chainConfigs
  .filter(config => config.isActive)
  .map(config => config.name);
```

#### Error Handling Patterns
```javascript
// ✅ Custom error classes for different error types
class ValidationError extends Error {
  constructor(message, originalError) {
    super(message);
    this.name = 'ValidationError';
    this.originalError = originalError;
  }
}

class GuardianConsensusError extends Error {
  constructor(message, guardianResponses) {
    super(message);
    this.name = 'GuardianConsensusError';
    this.guardianResponses = guardianResponses;
  }
}

// ✅ Consistent error handling in services
async function validateReserves(chainName) {
  try {
    const reserves = await getBitcoinReserves();
    const supply = await getTokenSupply(chainName);
    
    if (reserves < supply) {
      throw new ValidationError('Insufficient reserves');
    }
    
    return { reserves, supply, ratio: reserves / supply };
  } catch (error) {
    logger.error('Reserve validation failed', {
      chain: chainName,
      error: error.message
    });
    throw error;
  }
}
```

### SQL Style
```sql
-- ✅ Consistent formatting
SELECT 
    v.id,
    v.chain_name,
    v.amount,
    v.status,
    v.created_at
FROM validation_requests v
JOIN bitcoin_wallets w ON v.wallet_id = w.id
WHERE v.status = 'pending'
    AND v.created_at > NOW() - INTERVAL '1 hour'
ORDER BY v.created_at ASC
LIMIT 100;

-- ✅ Use meaningful aliases
SELECT 
    vr.id AS validation_id,
    bw.address AS bitcoin_address,
    pm.amount AS payment_amount
FROM validation_requests vr
JOIN bitcoin_wallets bw ON vr.wallet_id = bw.id
JOIN payment_monitoring pm ON vr.tx_hash = pm.tx_hash;
```

## 🧪 Testing Conventions

### Test File Organization
```
tests/
├── unit/                   # Unit tests
│   ├── services/
│   ├── utils/
│   └── models/
├── integration/            # Integration tests
│   ├── api/
│   ├── blockchain/
│   └── database/
├── e2e/                    # End-to-end tests
│   ├── validation-flow.test.js
│   └── reserve-management.test.js
├── fixtures/               # Test data
└── helpers/                # Test utilities
```

### Test Naming
```javascript
// ✅ Descriptive test names
describe('ValidationService', () => {
  describe('processValidation', () => {
    it('should successfully process valid payment with correct message', async () => {
      // Test implementation
    });
    
    it('should throw ValidationError when payment amount is insufficient', async () => {
      // Test implementation
    });
    
    it('should queue validation when rate limit is exceeded', async () => {
      // Test implementation
    });
  });
});
```

### Test Structure (AAA Pattern)
```javascript
it('should generate valid Bitcoin signature for proof request', async () => {
  // Arrange
  const mockWallet = {
    address: 'bc1qtest123...',
    privateKey: 'encrypted_private_key'
  };
  const message = 'Prove reserves for 2024-01-01';
  
  // Act
  const result = await bitcoinService.signMessage(message, mockWallet);
  
  // Assert
  expect(result.signature).toBeDefined();
  expect(result.address).toBe(mockWallet.address);
  expect(result.message).toBe(message);
});
```

## 📝 Documentation Standards

### Function Documentation
```javascript
/**
 * Processes a validation request by verifying payment and generating Bitcoin proof
 * 
 * @param {Object} request - The validation request
 * @param {string} request.chain - Blockchain name (ethereum, solana, etc.)
 * @param {string} request.txHash - Transaction hash containing payment
 * @param {string} request.message - Message to be signed as proof
 * @param {string} request.fromAddress - Address that made the payment
 * 
 * @returns {Promise<ValidationResult>} Validation result with signature
 * @throws {ValidationError} When payment is invalid or insufficient
 * @throws {GuardianConsensusError} When Guardian consensus fails
 * 
 * @example
 * const result = await processValidation({
 *   chain: 'ethereum',
 *   txHash: '0x123...',
 *   message: 'Prove reserves for wallet bc1q...',
 *   fromAddress: '0xabc...'
 * });
 */
async function processValidation(request) {
  // Implementation
}
```

### API Documentation
```javascript
/**
 * @api {post} /api/v1/validate Submit Validation Request
 * @apiName SubmitValidation
 * @apiGroup Validation
 * @apiVersion 1.0.0
 * 
 * @apiDescription Submit a validation request after making payment
 * 
 * @apiParam {String} chain Blockchain name (ethereum, solana, polygon, etc.)
 * @apiParam {String} tx_hash Transaction hash of the payment
 * @apiParam {String} message Custom message to be signed as proof
 * 
 * @apiSuccess {String} validation_id Unique validation request ID
 * @apiSuccess {String} status Current status (pending, processing, completed)
 * @apiSuccess {Number} queue_position Position in processing queue
 * @apiSuccess {String} estimated_completion Estimated completion time
 * 
 * @apiError {Object} 400 Invalid request parameters
 * @apiError {Object} 429 Rate limit exceeded
 * @apiError {Object} 500 Internal server error
 */
```

## 🔒 Security Conventions

### Input Validation
```javascript
// ✅ Always validate and sanitize inputs
const validationSchema = {
  chain: { type: 'string', enum: ['ethereum', 'solana', 'polygon'] },
  txHash: { type: 'string', pattern: '^0x[a-fA-F0-9]{64}$' },
  message: { type: 'string', maxLength: 500 }
};

function validateRequest(request) {
  const errors = validate(request, validationSchema);
  if (errors.length > 0) {
    throw new ValidationError('Invalid request', errors);
  }
}
```

### Sensitive Data Handling
```javascript
// ✅ Never log sensitive data
logger.info('Processing validation', {
  validationId: request.id,
  chain: request.chain,
  // ❌ DON'T: privateKey: wallet.privateKey
  // ❌ DON'T: signature: result.signature
});

// ✅ Use secure comparison for sensitive values
const crypto = require('crypto');

function compareSecurely(a, b) {
  return crypto.timingSafeEqual(
    Buffer.from(a, 'utf8'),
    Buffer.from(b, 'utf8')
  );
}
```

### Rate Limiting Implementation
```javascript
// ✅ Implement rate limiting with proper error handling
const rateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Max 10 requests per hour per IP
  message: {
    error: 'Rate limit exceeded',
    retryAfter: 3600
  },
  standardHeaders: true,
  legacyHeaders: false
});
```

## 🚀 Performance Conventions

### Database Queries
```javascript
// ✅ Use connection pooling
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

// ✅ Use prepared statements
const getValidationQuery = 'SELECT * FROM validations WHERE id = $1';
const result = await pool.query(getValidationQuery, [validationId]);

// ✅ Implement proper indexing
CREATE INDEX idx_validations_status_created 
ON validations(status, created_at) 
WHERE status IN ('pending', 'processing');
```

### Caching Strategy
```javascript
// ✅ Cache expensive operations
const CACHE_TTL = {
  RESERVE_DATA: 30,      // 30 seconds
  VALIDATION_RESULT: 3600, // 1 hour
  CHAIN_CONFIG: 300      // 5 minutes
};

async function getCachedReserveData(chain) {
  const cacheKey = `reserves:${chain}`;
  
  let data = await redis.get(cacheKey);
  if (!data) {
    data = await calculateReserveData(chain);
    await redis.setex(cacheKey, CACHE_TTL.RESERVE_DATA, JSON.stringify(data));
  } else {
    data = JSON.parse(data);
  }
  
  return data;
}
```

## 📊 Logging Conventions

### Structured Logging
```javascript
// ✅ Use structured logging with context
const logger = require('./utils/logger');

// Log levels: error, warn, info, debug
logger.info('Validation request received', {
  validationId: request.id,
  chain: request.chain,
  amount: request.amount,
  userAgent: req.headers['user-agent']
});

logger.error('Bitcoin signing failed', {
  validationId: request.id,
  error: error.message,
  stack: error.stack,
  walletAddress: wallet.address // Safe to log
});
```

### Log Format
```javascript
// ✅ Consistent log format
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "level": "info",
  "message": "Validation completed successfully",
  "service": "validation-service",
  "validationId": "val_123456",
  "chain": "ethereum",
  "processingTime": 1250,
  "guardianApprovals": 3
}
```

## 🔄 Git Conventions

### Commit Messages
```
feat: add Guardian Angels consensus mechanism
fix: resolve Bitcoin signature verification issue
docs: update API documentation for validation endpoints
test: add integration tests for payment monitoring
refactor: optimize database queries for reserve calculations
perf: implement caching for frequent reserve data requests
security: add rate limiting to validation endpoints
```

### Branch Naming
```
feature/guardian-angels-integration
bugfix/bitcoin-signature-validation
hotfix/critical-security-patch
release/v1.2.0
```

---

## 🎯 Code Review Checklist

### Before Submitting PR
- [ ] All tests pass
- [ ] Code follows style conventions
- [ ] Security implications reviewed
- [ ] Performance impact assessed
- [ ] Documentation updated
- [ ] Error handling implemented
- [ ] Logging added for debugging

### During Code Review
- [ ] Business logic is correct
- [ ] Security vulnerabilities checked
- [ ] Performance bottlenecks identified
- [ ] Code is maintainable
- [ ] Tests cover edge cases
- [ ] Documentation is accurate

This document serves as the foundation for consistent, secure, and maintainable code across the Universal Bitcoin project.