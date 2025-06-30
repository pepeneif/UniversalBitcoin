# Universal Bitcoin Security Guidelines

## 🔒 Security-First Development Principles

This document establishes mandatory security practices for the Universal Bitcoin proof-of-reserves system. **ALL** code must follow these guidelines without exception.

## 🛡️ Guardian Angels Security Protocol

### 1. **Multi-Signature Operations**

```javascript
// ✅ REQUIRED - Guardian Angels consensus for Bitcoin operations
class GuardianConsensus {
  constructor(threshold = 3, total = 5) {
    this.threshold = threshold;
    this.total = total;
    this.guardians = new Map();
  }

  async requestSignature(message, validationId) {
    const request = {
      id: generateSecureId(),
      message,
      validationId,
      timestamp: Date.now(),
      signatures: new Map(),
      status: 'pending'
    };

    // Send to all guardians
    await this.broadcastToGuardians(request);
    
    // Wait for threshold signatures
    return await this.waitForConsensus(request.id);
  }

  validateGuardianSignature(guardianId, signature, message) {
    // Cryptographically verify guardian signature
    const publicKey = this.guardians.get(guardianId).publicKey;
    return bitcoin.verifyMessage(message, publicKey, signature);
  }
}
```

### 2. **Key Management Security**

```javascript
// ✅ MANDATORY - Encrypted key storage
class SecureKeyManager {
  constructor(masterKey) {
    this.masterKey = deriveKey(masterKey, 'key-management');
    this.keyCache = new Map();
  }

  async storePrivateKey(keyId, privateKey) {
    // NEVER store unencrypted private keys
    const encrypted = await this.encrypt(privateKey);
    const keyData = {
      id: keyId,
      encrypted,
      created: Date.now(),
      lastUsed: null
    };
    
    await db.storeKey(keyData);
    
    // Clear from memory immediately
    privateKey = null;
    encrypted = null;
  }

  async getPrivateKey(keyId) {
    const keyData = await db.getKey(keyId);
    if (!keyData) {
      throw new SecurityError('Private key not found');
    }

    const decrypted = await this.decrypt(keyData.encrypted);
    
    // Auto-clear from memory after use
    setTimeout(() => { decrypted = null; }, 1000);
    
    return decrypted;
  }
}
```

## 🔐 Cryptographic Security Standards

### 1. **Encryption Requirements**

```javascript
// ✅ REQUIRED - AES-256-GCM for symmetric encryption
const ENCRYPTION_CONFIG = {
  algorithm: 'aes-256-gcm',
  keyLength: 32,
  ivLength: 16,
  tagLength: 16
};

async function encryptSensitiveData(data, key) {
  const iv = crypto.randomBytes(ENCRYPTION_CONFIG.ivLength);
  const cipher = crypto.createCipher(ENCRYPTION_CONFIG.algorithm, key, iv);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// ✅ REQUIRED - Secure key derivation
function deriveKey(masterKey, purpose, iterations = 100000) {
  const salt = crypto.randomBytes(32);
  return crypto.pbkdf2Sync(masterKey, salt, iterations, 32, 'sha256');
}
```

### 2. **Bitcoin Message Signing**

```javascript
// ✅ REQUIRED - Secure message signing protocol
class BitcoinSigner {
  async signMessage(message, privateKey) {
    // Validate inputs
    if (!message || typeof message !== 'string') {
      throw new ValidationError('Invalid message');
    }
    
    if (!privateKey || !this.isValidPrivateKey(privateKey)) {
      throw new SecurityError('Invalid private key');
    }

    try {
      // Sign message using Bitcoin message signing standard
      const signature = bitcoin.signMessage(message, privateKey);
      
      // Verify signature immediately
      const publicKey = bitcoin.getPublicKey(privateKey);
      const isValid = bitcoin.verifyMessage(message, publicKey, signature);
      
      if (!isValid) {
        throw new SecurityError('Signature verification failed');
      }

      return {
        message,
        signature,
        address: bitcoin.getAddress(publicKey),
        timestamp: Date.now()
      };
    } finally {
      // Clear private key from memory
      privateKey = null;
    }
  }

  isValidPrivateKey(key) {
    try {
      bitcoin.getPublicKey(key);
      return true;
    } catch {
      return false;
    }
  }
}
```

## 🚫 Security Violations - NEVER DO THESE

### 1. **Key Security Violations**
```javascript
// ❌ NEVER - Store unencrypted private keys
const wallet = {
  privateKey: 'L1uyy5qTuGrVXrmrsvHWHgVzW9kKdrp27wBC7Vs6nZDTF2BRUVwy' // NEVER!
};

// ❌ NEVER - Log private keys or signatures
console.log('Private key:', privateKey); // SECURITY BREACH!
logger.info('Signature:', signature); // SECURITY BREACH!

// ❌ NEVER - Transmit keys over unencrypted channels
await fetch('/api/keys', {
  method: 'POST',
  body: JSON.stringify({ privateKey }) // SECURITY BREACH!
});
```

### 2. **Input Security Violations**
```javascript
// ❌ NEVER - SQL injection vulnerabilities
const query = `SELECT * FROM validations WHERE id = ${userId}`; // VULNERABLE!

// ❌ NEVER - Unvalidated user input
app.post('/validate', (req, res) => {
  const { message } = req.body;
  signMessage(message); // VULNERABLE!
});

// ❌ NEVER - Client-side security validation only
if (req.body.isAdmin) { // NEVER TRUST CLIENT!
  // Admin operations
}
```

## 🔍 Security Validation Requirements

### 1. **Input Validation Schema**
```javascript
// ✅ REQUIRED - Comprehensive input validation
const VALIDATION_SCHEMAS = {
  validationRequest: {
    chain: {
      type: 'string',
      enum: ['ethereum', 'solana', 'polygon', 'arbitrum', 'bsc'],
      required: true
    },
    txHash: {
      type: 'string',
      pattern: {
        ethereum: /^0x[a-fA-F0-9]{64}$/,
        solana: /^[1-9A-HJ-NP-Za-km-z]{43,44}$/
      },
      required: true
    },
    message: {
      type: 'string',
      minLength: 1,
      maxLength: 500,
      sanitize: true,
      required: true
    },
    fromAddress: {
      type: 'string',
      validate: 'blockchain_address',
      required: true
    }
  }
};

function validateInput(data, schema) {
  const errors = [];
  
  for (const [field, rules] of Object.entries(schema)) {
    const value = data[field];
    
    // Required field check
    if (rules.required && !value) {
      errors.push(`${field} is required`);
      continue;
    }
    
    // Type validation
    if (value && typeof value !== rules.type) {
      errors.push(`${field} must be ${rules.type}`);
    }
    
    // Enum validation
    if (rules.enum && !rules.enum.includes(value)) {
      errors.push(`${field} must be one of: ${rules.enum.join(', ')}`);
    }
    
    // Pattern validation
    if (rules.pattern && !rules.pattern.test(value)) {
      errors.push(`${field} format is invalid`);
    }
    
    // Length validation
    if (rules.minLength && value.length < rules.minLength) {
      errors.push(`${field} must be at least ${rules.minLength} characters`);
    }
    
    if (rules.maxLength && value.length > rules.maxLength) {
      errors.push(`${field} must be no more than ${rules.maxLength} characters`);
    }
  }
  
  if (errors.length > 0) {
    throw new ValidationError('Input validation failed', errors);
  }
  
  return true;
}
```

### 2. **Rate Limiting Security**
```javascript
// ✅ REQUIRED - Multi-layer rate limiting
class SecurityRateLimiter {
  constructor() {
    this.limits = {
      global: { requests: 1000, window: 3600000 }, // 1000/hour
      perIP: { requests: 100, window: 3600000 },   // 100/hour per IP
      perUser: { requests: 10, window: 3600000 }   // 10/hour per user
    };
    
    this.counters = new Map();
    this.blocklist = new Set();
  }

  async checkRateLimit(identifier, type = 'perIP') {
    const limit = this.limits[type];
    const key = `${type}:${identifier}`;
    const now = Date.now();
    
    // Check if blocked
    if (this.blocklist.has(identifier)) {
      throw new SecurityError('IP address blocked due to suspicious activity');
    }
    
    let counter = this.counters.get(key) || { count: 0, windowStart: now };
    
    // Reset window if expired
    if (now - counter.windowStart > limit.window) {
      counter = { count: 0, windowStart: now };
    }
    
    // Increment counter
    counter.count++;
    this.counters.set(key, counter);
    
    // Check if limit exceeded
    if (counter.count > limit.requests) {
      this.handleRateLimitExceeded(identifier, type);
      throw new RateLimitError('Rate limit exceeded', {
        limit: limit.requests,
        window: limit.window,
        retryAfter: limit.window - (now - counter.windowStart)
      });
    }
    
    return true;
  }

  handleRateLimitExceeded(identifier, type) {
    // Log security event
    logger.warn('Rate limit exceeded', {
      identifier,
      type,
      timestamp: Date.now()
    });
    
    // Auto-block on extreme violations
    const violations = this.getViolationCount(identifier);
    if (violations > 5) {
      this.blocklist.add(identifier);
      logger.error('IP blocked for excessive rate limit violations', {
        identifier,
        violations
      });
    }
  }
}
```

## 🔐 Access Control Requirements

### 1. **Authentication Security**
```javascript
// ✅ REQUIRED - Secure JWT implementation
class SecureAuth {
  constructor(secret) {
    this.secret = secret;
    this.algorithm = 'HS256';
    this.expiration = '1h';
  }

  generateToken(payload) {
    const securePayload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      jti: crypto.randomUUID() // Unique token ID
    };
    
    return jwt.sign(securePayload, this.secret, {
      algorithm: this.algorithm
    });
  }

  verifyToken(token) {
    try {
      const decoded = jwt.verify(token, this.secret, {
        algorithms: [this.algorithm]
      });
      
      // Additional security checks
      if (!decoded.jti) {
        throw new SecurityError('Invalid token format');
      }
      
      return decoded;
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new AuthenticationError('Token expired');
      }
      throw new AuthenticationError('Invalid token');
    }
  }
}
```

### 2. **Authorization Security**
```javascript
// ✅ REQUIRED - Role-based access control
const PERMISSIONS = {
  PUBLIC: [],
  USER: ['validate', 'view_status'],
  ADMIN: ['validate', 'view_status', 'manage_reserves'],
  GUARDIAN: ['validate', 'view_status', 'sign_messages', 'approve_operations']
};

function requirePermission(permission) {
  return (req, res, next) => {
    const user = req.user;
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication required'
      });
    }
    
    const userPermissions = PERMISSIONS[user.role] || [];
    
    if (!userPermissions.includes(permission)) {
      logger.warn('Unauthorized access attempt', {
        userId: user.id,
        role: user.role,
        requiredPermission: permission,
        ip: req.ip
      });
      
      return res.status(403).json({
        error: 'Insufficient permissions'
      });
    }
    
    next();
  };
}
```

## 🚨 Security Monitoring Requirements

### 1. **Threat Detection**
```javascript
// ✅ REQUIRED - Suspicious activity monitoring
class ThreatDetector {
  constructor() {
    this.suspiciousPatterns = [
      /SELECT.*FROM.*WHERE.*OR.*1=1/i, // SQL injection
      /<script.*>/i,                   // XSS attempts
      /\.\.\/.*\.\./,                  // Path traversal
      /union.*select/i                 // SQL injection
    ];
    
    this.alerts = new Map();
  }

  analyzeRequest(req) {
    const threats = [];
    
    // Check for injection patterns
    const allInputs = [
      req.url,
      JSON.stringify(req.body),
      JSON.stringify(req.query),
      ...Object.values(req.headers)
    ].join(' ');
    
    for (const pattern of this.suspiciousPatterns) {
      if (pattern.test(allInputs)) {
        threats.push({
          type: 'injection_attempt',
          pattern: pattern.toString(),
          input: allInputs.substring(0, 200)
        });
      }
    }
    
    // Check for brute force
    const clientId = req.ip;
    const alertKey = `brute_force:${clientId}`;
    const attempts = this.alerts.get(alertKey) || 0;
    
    if (attempts > 10) {
      threats.push({
        type: 'brute_force',
        attempts,
        ip: clientId
      });
    }
    
    if (threats.length > 0) {
      this.handleThreats(threats, req);
    }
    
    return threats;
  }

  handleThreats(threats, req) {
    logger.error('Security threats detected', {
      threats,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: Date.now()
    });
    
    // Alert security team
    this.sendSecurityAlert(threats, req);
  }
}
```

### 2. **Audit Logging**
```javascript
// ✅ REQUIRED - Comprehensive security audit logging
class SecurityAuditLogger {
  logSecurityEvent(event, details) {
    const auditRecord = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      event,
      severity: this.getSeverity(event),
      details,
      source: 'security-system'
    };
    
    // Store in secure audit log
    db.auditLogs.insert(auditRecord);
    
    // Alert on high severity events
    if (auditRecord.severity === 'HIGH' || auditRecord.severity === 'CRITICAL') {
      this.sendSecurityAlert(auditRecord);
    }
  }

  getSeverity(event) {
    const severityMap = {
      'authentication_failure': 'MEDIUM',
      'authorization_failure': 'MEDIUM',
      'rate_limit_exceeded': 'LOW',
      'suspicious_activity': 'HIGH',
      'key_access': 'HIGH',
      'guardian_signature': 'HIGH',
      'bitcoin_operation': 'CRITICAL'
    };
    
    return severityMap[event] || 'LOW';
  }
}
```

## 📋 Security Checklist

### Pre-Deployment Security Audit
- [ ] All private keys encrypted at rest
- [ ] No secrets in source code or logs
- [ ] Input validation on all endpoints
- [ ] Rate limiting implemented
- [ ] Authentication and authorization working
- [ ] SQL injection protection verified
- [ ] XSS protection enabled
- [ ] HTTPS enforced everywhere
- [ ] Security headers configured
- [ ] Guardian multi-sig tested
- [ ] Audit logging functional
- [ ] Intrusion detection active
- [ ] Backup security verified
- [ ] Key rotation procedures tested

### Security Code Review Requirements
- [ ] No hardcoded secrets
- [ ] Proper error handling (no info leakage)
- [ ] Input validation present
- [ ] Output encoding implemented
- [ ] Authentication checks in place
- [ ] Authorization verified
- [ ] Cryptographic operations secure
- [ ] Logging does not expose sensitive data
- [ ] Rate limiting appropriate
- [ ] Guardian consensus implemented

---

## 🚨 Security Incident Response

### Immediate Actions
1. **Isolate** affected systems
2. **Assess** scope of compromise
3. **Notify** Guardian Angels
4. **Preserve** evidence
5. **Implement** containment
6. **Communicate** with stakeholders

### Recovery Procedures
1. **Validate** system integrity
2. **Rotate** compromised credentials
3. **Update** security measures
4. **Test** all systems
5. **Monitor** for recurrence
6. **Document** lessons learned

**Remember: Security is everyone's responsibility, but with Guardian Angels multi-sig, we have distributed security by design.**