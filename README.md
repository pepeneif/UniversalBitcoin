# Universal Bitcoin 
##Multi-Chain Proof-of-Reserves System

## 🚀 Overview

Universal Bitcoin is a revolutionary multi-blockchain proof-of-reserves system that provides **complete transparency** for UniversalBTC (uBTC) tokens. Our system allows anyone to cryptographically verify that uBTC tokens are backed by real Bitcoin reserves through a pay-per-validation model.

## 🎯 Key Features

### 🔍 **Proof-of-Reserves Validation**
- Anyone can request cryptographic proof that Bitcoin reserves match minted uBTC tokens in each of the supported chains
- Pay small fees (Lamports on Solana, Gwei on Ethereum) to trigger the issuance of an easy to verify signed Bitcoin message
- Real-time verification across multiple blockchains

### 🌐 **Multi-Chain Support**
- **Supported Chains**: Ethereum, Solana, Polygon, Arbitrum, BSC 
- **Separate Reserves** backing the tokens on each of the supported chains

### 📊 **Public Transparency Dashboard**
- Real-time reserve ratios for each blockchain
- 24/7 system health monitoring
- Historical validation statistics
- Cross-chain token distribution analytics

### 🔒 **Guardian Angels Security**
- Multi-signature Bitcoin wallets controlled by "Guardian Angels"
- Distributed consensus for all validation approvals
- Rate limiting and anti-spam protection
- Comprehensive audit trails

### 🔗 **Developer-Friendly Integration**
- RESTful API for external integrations
- Webhook support for real-time notifications
- Rate limiting with queue management
- Comprehensive documentation and SDKs

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Public Users  │    │   Blockchain     │    │  Bitcoin Network│
│                 │    │   Networks       │    │                 │
│ • Validators    │◄──►│ • Ethereum       │◄──►│ • Message       │
│ • Token Holders │    │ • Solana         │    │   Signing       │
│ • Auditors      │    │ • Polygon        │    │ • Reserve       │
└─────────────────┘    └──────────────────┘    │   Validation    │
                                               └─────────────────┘
           ▲                        ▲                     ▲
           │                        │                     │
           ▼                        ▼                     ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Public Dashboard│    │ Validation       │    │ Admin Interface │
│                 │    │ Engine           │    │                 │
│ • Live Metrics  │    │ • Payment Monitor│    │ • Minting       │
│ • Reserve Ratios│    │ • Queue System   │    │ • Burning       │
│ • Validation    │    │ • Rate Limiting  │    │ • Configuration │
│   Statistics    │    │ • Webhook Service│    │ • Audit Trails  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 💰 How It Works

### To validate our Reserves (Proof Requests)
1. **Make Payment**: Send small amount (e.g., 0.001 ETH or 0.01 SOL) to a specific address
2. **Include Message**: Specify the message you want signed in the validation user interface
3. **Guardian Review**: Multiple Guardian Angels independently review and approve the request
4. **Get Proof**: Receive an easy to verify Bitcoin message proving control of the reserves
5. **Verify Independently**: Use Bitcoin standard tools or wallets to verify the message

### For uBTC Token Holders
1. **Check Dashboard**: View real-time reserve ratios and system health
2. **Monitor Transparency**: Track historical validation data
3. **Integrate APIs**: Build custom monitoring solutions

### For Administrators
1. **Manage Reserves**: Coordinate with Guardian Angels for Bitcoin deposits/withdrawals
2. **Mint uBTC**: Create UniversalBTC tokens corresponding to Bitcoin deposits (requires Guardian approval)
3. **Burn uBTC**: Remove UniversalBTC tokens when Bitcoin is withdrawn (requires Guardian approval)
4. **Monitor System**: Track validations, manage rate limits, view audit trails
5. **Guardian Coordination**: Facilitate communication and consensus among Guardian Angels

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm
- PostgreSQL 13+
- Redis 6+
- Docker (optional)

### Installation

```bash
# Clone the repository
git clone https://github.com/pepeneif/UniversalBTC.git
cd UniversalBTC

# Install dependencies
npm install

# Setup environment variables
cp .env.example .env
# Edit .env with your configuration

# Setup database
npm run db:migrate
npm run db:seed

# Start development server
npm run dev
```

### Environment Configuration

```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/universal_btc
REDIS_URL=redis://localhost:6379

# Blockchain RPCs
ETHEREUM_RPC_URL=https://mainnet.infura.io/v3/your-key
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com

# Security
ENCRYPTION_KEY=your-32-byte-encryption-key
JWT_SECRET=your-jwt-secret

# Bitcoin Multi-Sig Configuration
BITCOIN_NETWORK=mainnet
MULTISIG_THRESHOLD=3
MULTISIG_TOTAL=5
GUARDIAN_ANGELS=["guardian1", "guardian2", "guardian3", "guardian4", "guardian5"]

# Rate Limiting
MAX_VALIDATIONS_PER_HOUR=10
GLOBAL_RATE_LIMIT=1000

# Webhooks
WEBHOOK_SECRET=your-webhook-secret
```

## 📡 API Reference

### Public Endpoints

#### Get Reserve Status
```http
GET /api/v1/reserves
```

Response:
```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "total_btc_reserves": "125.50000000",
  "chains": {
    "ethereum": {
      "total_supply": "45.25000000",
      "reserve_ratio": "1.0000"
    },
    "solana": {
      "total_supply": "80.25000000", 
      "reserve_ratio": "1.0000"
    }
  },
  "last_validation": "2024-01-01T00:00:00Z"
}
```

#### Request Validation
```http
POST /api/v1/validate
```

Request Body:
```json
{
  "chain": "ethereum",
  "tx_hash": "0x...",
  "message": "Prove reserves for 2024-01-01"
}
```

#### Get Validation Result
```http
GET /api/v1/validate/{validation_id}
```

### Webhook Events

```json
{
  "event": "validation.completed",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    "validation_id": "val_123456",
    "message": "Prove reserves for 2024-01-01",
    "signature": "H...",
    "bitcoin_address": "bc1q...",
    "chain": "ethereum"
  }
}
```

## 🔧 Configuration

### Rate Limiting
- **Per-Address**: 10 validations/hour
- **Global**: 1000 validations/hour
- **VIP Addresses**: Configurable higher limits
- **Queue Processing**: Delayed execution when limits exceeded

### Guardian Angels Security Settings
- **Multi-Sig Threshold**: 3-of-5 Guardian Angels required for signatures
- **Guardian Distribution**: Geographically and organizationally distributed
- **Consensus Protocol**: Byzantine fault-tolerant approval process
- **Access Control**: Role-based admin permissions + Guardian approvals
- **Audit Logging**: Complete Guardian activity tracking
- **Communication Security**: Encrypted Guardian-to-Guardian messaging

### Monitoring
- **Health Checks**: `/health` endpoint for uptime monitoring
- **Metrics**: Prometheus-compatible metrics at `/metrics`
- **Logging**: Structured JSON logging with Winston

## 🛠️ Development

### Project Structure
```
UniversalBTC/
├── src/
│   ├── api/                 # REST API routes
│   ├── services/            # Core business logic
│   ├── blockchain/          # Blockchain integrations
│   ├── security/            # Key management & encryption
│   ├── validation/          # Validation engine
│   └── webhooks/            # Webhook management
├── admin/                   # Admin dashboard
├── public/                  # Public dashboard
├── tests/                   # Test suites
├── docs/                    # Documentation
└── docker/                  # Container configurations
```

### Available Scripts
```bash
npm run dev          # Start development server
npm run build        # Build for production
npm run test         # Run test suite
npm run test:e2e     # End-to-end tests
npm run db:migrate   # Run database migrations
npm run db:seed      # Seed test data
npm run lint         # Code linting
npm run security     # Security audit
```

### Testing
```bash
# Unit tests
npm run test:unit

# Integration tests  
npm run test:integration

# Load testing
npm run test:load

# Security testing
npm run test:security
```

## 🚀 Deployment

### Docker Deployment
```bash
# Build and run with docker-compose
docker-compose up -d

# Scale services
docker-compose up --scale validation-service=3
```

### Production Checklist
- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] SSL certificates installed
- [ ] Rate limiting configured
- [ ] Monitoring dashboards setup
- [ ] Backup procedures tested
- [ ] Security audit completed

## 📊 Monitoring & Analytics

### Dashboard Metrics
- **Reserve Ratios**: Real-time BTC:Token ratios
- **Validation Statistics**: Requests, completions, queue times
- **System Health**: Uptime, response times, error rates
- **Financial Metrics**: Revenue, costs, profitability

### Alerts
- Reserve ratio below 100%
- High validation queue times
- System errors or downtime
- Suspicious validation patterns

## 🔐 Security

### Guardian Angels Security Best Practices
- Regular Guardian Angel security audits
- Distributed key management across Guardian Angels
- Multi-party computation for sensitive operations
- Rate limiting and DDoS protection
- Comprehensive Guardian activity logging
- Secure Guardian communication channels
- Regular Guardian Angel rotation policies

### Incident Response
1. **Detection**: Automated monitoring alerts
2. **Assessment**: Severity classification
3. **Response**: Automated & manual mitigation
4. **Recovery**: System restoration procedures
5. **Review**: Post-incident analysis

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [docs.universalbitcoin.com](https://docs.universalbitcoin.com)
- **API Reference**: [api.universalbitcoin.com](https://api.universalbitcoin.com)
- **Community**: [Discord](https://discord.gg/universalbitcoin)
- **Issues**: [GitHub Issues](https://github.com/your-org/UniversalBTC/issues)

## 🗺️ Roadmap

### Phase 1: Core System (Q2 2025)
- ✅ Multi-chain validation engine
- ✅ Public transparency dashboard
- ✅ Admin minting/burning interface
- ✅ Rate limiting and security

### Phase 2: Enhanced Features (Q3 2025)
- 🔲 Advanced analytics and reporting
- 🔲 Mobile app for validation requests
- 🔲 Automated reserve management

### Phase 3: Expansion (Q4 2025)
- 🔲 Additional blockchain support
- 🔲 Additional API features

---

**Built with ❤️ for Bitcoin transparency and universal access**
