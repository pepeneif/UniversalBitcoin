# Universal Bitcoin System Architecture

## 🏗️ System Overview

The Universal Bitcoin proof-of-reserves system is designed as a transparent, scalable, and secure multi-chain validation platform. The architecture follows microservices principles with clear separation of concerns, ensuring high availability and maintainability.

## 🎯 Core Design Principles

### 1. **Transparency First**
- All reserve data publicly accessible
- Cryptographic proof of Bitcoin control
- Immutable audit trails
- Real-time validation statistics

### 2. **Security by Design**
- Defense in depth strategy
- Encrypted key storage
- Rate limiting and anti-spam
- Comprehensive access controls

### 3. **Multi-Chain Native**
- Blockchain-agnostic core engine
- Pluggable chain adapters
- Unified reserve management
- Cross-chain consistency

### 4. **High Availability**
- Redundant service architecture
- Graceful failure handling
- Queue-based processing
- Auto-scaling capabilities

### 5. **Guardian Angels Multi-Signature Security**
- Multiple trusted parties ("Guardian Angels") control Bitcoin signing
- M-of-N signature scheme for enhanced security
- Distributed key management across Guardian Angels
- Consensus-based validation approval process

## 🔧 System Components

### Core Services Architecture

```mermaid
graph TB
    subgraph "External Layer"
        UI[Public Dashboard]
        API[Public API]
        ADMIN[Admin Interface]
        WH[Webhook Consumers]
    end
    
    subgraph "API Gateway Layer"
        GW[API Gateway]
        AUTH[Authentication Service]
        RATE[Rate Limiter]
        CACHE[Response Cache]
    end
    
    subgraph "Application Layer"
        VS[Validation Service]
        PS[Payment Service]
        NS[Notification Service]
        RS[Reserve Service]
        AS[Analytics Service]
    end
    
    subgraph "Integration Layer"
        BCH[Blockchain Handler]
        BTC[Bitcoin Service]
        WHS[Webhook Service]
        QS[Queue Service]
    end
    
    subgraph "Data Layer"
        PG[(PostgreSQL)]
        RD[(Redis)]
        TS[(TimescaleDB)]
        FS[(File Storage)]
    end
    
    subgraph "Infrastructure Layer"
        MON[Monitoring]
        LOG[Logging]
        SEC[Security]
        BACKUP[Backup]
    end
    
    UI --> GW
    API --> GW
    ADMIN --> GW
    
    GW --> AUTH
    GW --> RATE
    GW --> CACHE
    
    AUTH --> VS
    RATE --> PS
    CACHE --> RS
    
    VS --> BCH
    PS --> BTC
    NS --> WHS
    RS --> QS
    AS --> TS
    
    BCH --> PG
    BTC --> RD
    WHS --> PG
    QS --> RD
    
    PG --> BACKUP
    RD --> MON
    TS --> LOG
    FS --> SEC
```

## 📊 Data Architecture

### Database Schema Design

#### Core Tables

**Validations Table**
```sql
CREATE TABLE validations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain VARCHAR(50) NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    from_address VARCHAR(128) NOT NULL,
    amount DECIMAL(20,8) NOT NULL,
    message TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    bitcoin_signature TEXT,
    bitcoin_address VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    processed_at TIMESTAMP,
    UNIQUE(chain, tx_hash)
);
```

**Bitcoin Wallets Table**
```sql
CREATE TABLE bitcoin_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address VARCHAR(64) NOT NULL UNIQUE,
    encrypted_private_key TEXT NOT NULL,
    balance DECIMAL(20,8) DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP
);
```

**Chain Tokens Table**
```sql
CREATE TABLE chain_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    chain VARCHAR(50) NOT NULL,
    contract_address VARCHAR(128),
    total_supply DECIMAL(20,8) DEFAULT 0,
    backed_by_wallet_id UUID REFERENCES bitcoin_wallets(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

**Audit Logs Table**
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    user_id UUID,
    resource_type VARCHAR(50),
    resource_id UUID,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Time-Series Data (TimescaleDB)

**Validation Metrics**
```sql
CREATE TABLE validation_metrics (
    time TIMESTAMPTZ NOT NULL,
    chain VARCHAR(50) NOT NULL,
    validations_count INTEGER DEFAULT 0,
    average_response_time INTERVAL,
    success_rate DECIMAL(5,4),
    total_fees DECIMAL(20,8)
);

SELECT create_hypertable('validation_metrics', 'time');
```

**Reserve Ratios**
```sql
CREATE TABLE reserve_ratios (
    time TIMESTAMPTZ NOT NULL,
    chain VARCHAR(50) NOT NULL,
    btc_reserves DECIMAL(20,8),
    token_supply DECIMAL(20,8),
    ratio DECIMAL(10,8),
    is_healthy BOOLEAN
);

SELECT create_hypertable('reserve_ratios', 'time');
```

### Cache Strategy (Redis)

```mermaid
graph TB
    subgraph "Cache Layers"
        L1[L1: API Response Cache]
        L2[L2: Database Query Cache]
        L3[L3: Blockchain Data Cache]
        L4[L4: Session Cache]
    end
    
    subgraph "Cache Patterns"
        LRU[LRU Eviction]
        TTL[TTL Expiration]
        INV[Cache Invalidation]
        WB[Write-Behind]
    end
    
    L1 --> TTL
    L2 --> LRU
    L3 --> INV
    L4 --> WB
```

**Cache Configuration**
```yaml
cache_config:
  api_responses:
    ttl: 300  # 5 minutes
    max_size: 10000
  
  blockchain_data:
    ttl: 60   # 1 minute
    max_size: 5000
  
  validation_results:
    ttl: 3600 # 1 hour
    max_size: 50000
  
  reserve_data:
    ttl: 30   # 30 seconds
    max_size: 1000
```

## 🔒 Security Architecture

### Key Management System

```mermaid
graph TB
    subgraph "Key Storage"
        MASTER[Master Key]
        DERIVED[Derived Keys]
        ENCRYPTED[Encrypted Storage]
    end
    
    subgraph "Access Control"
        RBAC[Role-Based Access]
        MFA[Multi-Factor Auth]
        AUDIT[Access Auditing]
    end
    
    subgraph "Encryption"
        AES[AES-256-GCM]
        PBKDF2[PBKDF2 Key Derivation]
        HSM[Future: Hardware HSM]
    end
    
    MASTER --> PBKDF2
    PBKDF2 --> DERIVED
    DERIVED --> AES
    AES --> ENCRYPTED
    
    RBAC --> AUDIT
    MFA --> AUDIT
    AUDIT --> ENCRYPTED
```

### Security Layers

1. **Network Security**
   - WAF (Web Application Firewall)
   - DDoS protection
   - IP allowlisting for admin functions
   - TLS 1.3 encryption

2. **Application Security**
   - Input validation and sanitization
   - SQL injection prevention
   - XSS protection
   - CSRF tokens

3. **Data Security**
   - Encryption at rest (AES-256)
   - Encryption in transit (TLS)
   - Key rotation policies
   - Secure key derivation

4. **Access Security**
   - JWT-based authentication
   - Role-based authorization
   - Session management
   - Rate limiting

## 🔄 Processing Flows

### Validation Request Flow

```mermaid
sequenceDiagram
    participant User
    participant Blockchain
    participant PaymentMonitor
    participant RateLimiter
    participant Queue
    participant ValidationService
    participant BitcoinService
    participant Database
    participant Webhook
    
    User->>Blockchain: Send payment with message
    PaymentMonitor->>Blockchain: Poll for transactions
    PaymentMonitor->>RateLimiter: Check rate limits
    
    alt Within Rate Limits
        RateLimiter->>Queue: Add to immediate queue
    else Rate Limited
        RateLimiter->>Queue: Add to delayed queue
        RateLimiter->>User: Send delay warning
    end
    
    Queue->>ValidationService: Process validation
    ValidationService->>BitcoinService: Request message signing
    BitcoinService->>BitcoinService: Sign with private key
    BitcoinService->>ValidationService: Return signature
    ValidationService->>Database: Store validation result
    ValidationService->>Webhook: Send notifications
    Webhook->>User: Deliver validation proof
```

### Reserve Management Flow

```mermaid
sequenceDiagram
    participant Admin
    participant AdminInterface
    participant ReserveService
    participant BitcoinWallet
    participant ChainContract
    participant Database
    participant Analytics
    
    Admin->>AdminInterface: Initiate reserve change
    AdminInterface->>ReserveService: Validate operation
    
    alt Adding Reserves
        ReserveService->>BitcoinWallet: Verify BTC deposit
        ReserveService->>ChainContract: Mint new tokens
    else Removing Reserves
        ReserveService->>ChainContract: Burn tokens
        ReserveService->>BitcoinWallet: Release BTC
    end
    
    ReserveService->>Database: Update balances
    ReserveService->>Analytics: Trigger metrics update
    Analytics->>AdminInterface: Update dashboard
```

## 🌐 Multi-Chain Integration

### Blockchain Adapter Pattern

```mermaid
graph TB
    subgraph "Core Engine"
        CE[Chain Engine]
        PA[Payment Abstraction]
        TA[Transaction Abstraction]
    end
    
    subgraph "Chain Adapters"
        ETH[Ethereum Adapter]
        SOL[Solana Adapter]
        POLY[Polygon Adapter]
        ARB[Arbitrum Adapter]
        BSC[BSC Adapter]
    end
    
    subgraph "Chain Networks"
        ETHN[Ethereum Network]
        SOLN[Solana Network]
        POLYN[Polygon Network]
        ARBN[Arbitrum Network]
        BSCN[BSC Network]
    end
    
    CE --> PA
    PA --> TA
    
    TA --> ETH
    TA --> SOL
    TA --> POLY
    TA --> ARB
    TA --> BSC
    
    ETH --> ETHN
    SOL --> SOLN
    POLY --> POLYN
    ARB --> ARBN
    BSC --> BSCN
```

### Chain Configuration

```typescript
interface ChainConfig {
  name: string;
  rpcUrl: string;
  contractAddress?: string;
  paymentAddress: string;
  minimumPayment: bigint;
  confirmations: number;
  gasSettings: {
    gasPrice?: bigint;
    gasLimit: bigint;
  };
}

const chainConfigs: Record<string, ChainConfig> = {
  ethereum: {
    name: "Ethereum",
    rpcUrl: process.env.ETHEREUM_RPC_URL,
    contractAddress: "0x...",
    paymentAddress: "0x...",
    minimumPayment: parseEther("0.001"),
    confirmations: 12,
    gasSettings: {
      gasLimit: 100000n
    }
  },
  solana: {
    name: "Solana",
    rpcUrl: process.env.SOLANA_RPC_URL,
    paymentAddress: "...",
    minimumPayment: 10000000n, // 0.01 SOL in lamports
    confirmations: 32,
    gasSettings: {
      gasLimit: 200000n
    }
  }
};
```

## 📈 Scalability Architecture

### Horizontal Scaling Strategy

```mermaid
graph TB
    subgraph "Load Balancer"
        LB[Nginx Load Balancer]
    end
    
    subgraph "API Layer (Auto-scaling)"
        API1[API Instance 1]
        API2[API Instance 2]
        API3[API Instance N]
    end
    
    subgraph "Processing Layer"
        VS1[Validation Service 1]
        VS2[Validation Service 2]
        PS1[Payment Service 1]
        PS2[Payment Service 2]
    end
    
    subgraph "Data Layer"
        PG_MASTER[(PostgreSQL Master)]
        PG_REPLICA[(PostgreSQL Replica)]
        REDIS_CLUSTER[(Redis Cluster)]
    end
    
    LB --> API1
    LB --> API2
    LB --> API3
    
    API1 --> VS1
    API2 --> VS2
    API3 --> PS1
    
    VS1 --> PG_MASTER
    VS2 --> PG_REPLICA
    PS1 --> REDIS_CLUSTER
    PS2 --> REDIS_CLUSTER
```

### Performance Optimization

1. **Database Optimization**
   - Read replicas for heavy queries
   - Connection pooling
   - Query optimization
   - Partitioning by chain/date

2. **Cache Optimization**
   - Multi-layer caching
   - Cache warming strategies
   - Intelligent invalidation
   - Edge caching (CDN)

3. **Queue Optimization**
   - Priority queues
   - Dead letter queues
   - Batch processing
   - Auto-scaling workers

## 📊 Monitoring & Observability

### Metrics Collection

```mermaid
graph TB
    subgraph "Application Metrics"
        BUSI[Business Metrics]
        PERF[Performance Metrics]
        ERROR[Error Metrics]
    end
    
    subgraph "Infrastructure Metrics"
        CPU[CPU Usage]
        MEM[Memory Usage]
        DISK[Disk I/O]
        NET[Network I/O]
    end
    
    subgraph "Collection Layer"
        PROM[Prometheus]
        GRAF[Grafana]
        ALERT[AlertManager]
    end
    
    BUSI --> PROM
    PERF --> PROM
    ERROR --> PROM
    CPU --> PROM
    MEM --> PROM
    DISK --> PROM
    NET --> PROM
    
    PROM --> GRAF
    PROM --> ALERT
```

### Key Performance Indicators

**Business Metrics**
- Validation requests per hour/day
- Revenue per chain
- Reserve ratio health
- Customer satisfaction scores

**Technical Metrics**
- API response times (p50, p95, p99)
- Database query performance
- Queue processing times
- Error rates by service

**Security Metrics**
- Rate limit violations
- Authentication failures
- Suspicious activity patterns
- Security audit compliance

## 🚀 Deployment Architecture

### Container Architecture

```dockerfile
# Multi-stage build for production
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine AS runtime
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .
USER nodejs
EXPOSE 3000
CMD ["node", "src/index.js"]
```

### Infrastructure as Code

```yaml
# docker-compose.yml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    depends_on:
      - postgres
      - redis
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        max_attempts: 3
  
  validation-service:
    build: .
    command: npm run start:validation
    environment:
      - NODE_ENV=production
    depends_on:
      - postgres
      - redis
    deploy:
      replicas: 2
  
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: universal_btc
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

## 🔄 Disaster Recovery

### Backup Strategy

1. **Database Backups**
   - Automated daily full backups
   - Hourly incremental backups
   - Point-in-time recovery capability
   - Cross-region backup replication

2. **Key Backups**
   - Encrypted key backups
   - Multi-location storage
   - Recovery procedures testing
   - Access control auditing

3. **Code & Configuration**
   - Git repository backups
   - Configuration management
   - Infrastructure as code
   - Rollback procedures

### Recovery Procedures

```mermaid
graph TB
    subgraph "Incident Detection"
        ALERT[Alert Triggered]
        ASSESS[Assess Impact]
        CLASSIFY[Classify Severity]
    end
    
    subgraph "Response Actions"
        ISOLATE[Isolate Problem]
        RESTORE[Restore Service]
        VERIFY[Verify Recovery]
    end
    
    subgraph "Post-Incident"
        ANALYZE[Root Cause Analysis]
        IMPROVE[Improve Procedures]
        DOCUMENT[Update Documentation]
    end
    
    ALERT --> ASSESS
    ASSESS --> CLASSIFY
    CLASSIFY --> ISOLATE
    ISOLATE --> RESTORE
    RESTORE --> VERIFY
    VERIFY --> ANALYZE
    ANALYZE --> IMPROVE
    IMPROVE --> DOCUMENT
```

## 🔮 Future Architecture Considerations

### Phase 2 Enhancements

1. **Hardware Security Modules**
   - Migration to HSM-based key storage
   - Enhanced cryptographic operations
   - Compliance with banking standards

2. **Advanced Analytics**
   - Machine learning for fraud detection
   - Predictive analytics for demand
   - Advanced reporting capabilities

3. **Governance Integration**
   - DAO governance mechanisms
   - Community voting systems
   - Decentralized administration

### Phase 3 Expansions

1. **Cross-Chain Bridges**
   - Native bridge integrations
   - Automated liquidity management
   - Cross-chain arbitrage prevention

2. **Enterprise Features**
   - White-label solutions
   - Custom SLA agreements
   - Dedicated infrastructure

3. **Regulatory Compliance**
   - AML/KYC integration
   - Regulatory reporting
   - Compliance monitoring

---

This architecture document provides the foundation for building a robust, scalable, and secure WrappedBitcoin proof-of-reserves system. The design emphasizes transparency, security, and multi-chain compatibility while maintaining operational efficiency and user experience.