-- Universal Bitcoin - Database Initialization Script
-- 
-- Creates the initial database schema for the Universal Bitcoin proof-of-reserves system.
-- Includes tables for validations, reserves, audit logs, and Guardian Angels data.

-- Enable TimescaleDB extension for time-series data
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- Enable UUID extension for primary keys
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom types
CREATE TYPE validation_status AS ENUM (
    'pending',
    'processing', 
    'verifying_payment',
    'awaiting_consensus',
    'signing',
    'completed',
    'failed',
    'expired'
);

CREATE TYPE validation_type AS ENUM (
    'proof_of_reserves',
    'custom_message',
    'wallet_verification'
);

CREATE TYPE blockchain_network AS ENUM (
    'ethereum',
    'solana', 
    'polygon',
    'arbitrum',
    'bsc'
);

-- =============================================================================
-- VALIDATION TABLES
-- =============================================================================

-- Main validation requests table
CREATE TABLE validation_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    validation_id VARCHAR(64) UNIQUE NOT NULL,
    type validation_type NOT NULL DEFAULT 'proof_of_reserves',
    status validation_status NOT NULL DEFAULT 'pending',
    
    -- Request data
    chain blockchain_network NOT NULL,
    tx_hash VARCHAR(128) NOT NULL,
    from_address VARCHAR(128) NOT NULL,
    message TEXT NOT NULL,
    
    -- Payment verification
    amount DECIMAL(20,8),
    fee DECIMAL(20,8),
    payment_verified BOOLEAN DEFAULT FALSE,
    
    -- Result data
    signature TEXT,
    bitcoin_address VARCHAR(64),
    guardian_signatures JSONB,
    
    -- Metadata
    user_id UUID,
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(128),
    
    -- Tracking
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    error_message TEXT,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    failed_at TIMESTAMP WITH TIME ZONE,
    
    -- Indexes
    INDEX idx_validation_requests_validation_id (validation_id),
    INDEX idx_validation_requests_status (status),
    INDEX idx_validation_requests_chain (chain),
    INDEX idx_validation_requests_created_at (created_at),
    INDEX idx_validation_requests_tx_hash (tx_hash)
);

-- Convert to hypertable for time-series optimization
SELECT create_hypertable('validation_requests', 'created_at');

-- =============================================================================
-- BITCOIN RESERVES TABLES
-- =============================================================================

-- Bitcoin reserves snapshots
CREATE TABLE bitcoin_reserves (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address VARCHAR(64) NOT NULL,
    balance DECIMAL(20,8) NOT NULL,
    utxos INTEGER NOT NULL,
    block_height BIGINT NOT NULL,
    block_hash VARCHAR(64),
    network VARCHAR(20) NOT NULL DEFAULT 'mainnet',
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_bitcoin_reserves_address (address),
    INDEX idx_bitcoin_reserves_created_at (created_at)
);

-- Convert to hypertable
SELECT create_hypertable('bitcoin_reserves', 'created_at');

-- Token supply across chains
CREATE TABLE token_supply (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    chain blockchain_network NOT NULL,
    contract_address VARCHAR(128) NOT NULL,
    supply DECIMAL(20,8) NOT NULL,
    holders INTEGER,
    transactions_24h INTEGER,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_token_supply_chain (chain),
    INDEX idx_token_supply_created_at (created_at)
);

-- Convert to hypertable
SELECT create_hypertable('token_supply', 'created_at');

-- Reserve ratios over time
CREATE TABLE reserve_ratios (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    bitcoin_balance DECIMAL(20,8) NOT NULL,
    token_supply DECIMAL(20,8) NOT NULL,
    ratio DECIMAL(10,4) NOT NULL,
    status VARCHAR(20) NOT NULL,
    fully_backed BOOLEAN NOT NULL,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes  
    INDEX idx_reserve_ratios_created_at (created_at),
    INDEX idx_reserve_ratios_status (status)
);

-- Convert to hypertable
SELECT create_hypertable('reserve_ratios', 'created_at');

-- =============================================================================
-- GUARDIAN ANGELS TABLES
-- =============================================================================

-- Guardian Angels registry
CREATE TABLE guardians (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    guardian_id VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    public_key TEXT NOT NULL,
    endpoint VARCHAR(256),
    active BOOLEAN DEFAULT TRUE,
    
    -- Statistics
    total_signatures INTEGER DEFAULT 0,
    successful_signatures INTEGER DEFAULT 0,
    last_seen TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_guardians_guardian_id (guardian_id),
    INDEX idx_guardians_active (active)
);

-- Guardian consensus requests
CREATE TABLE guardian_consensus (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    consensus_id VARCHAR(64) UNIQUE NOT NULL,
    validation_id VARCHAR(64) NOT NULL,
    message TEXT NOT NULL,
    required_signatures INTEGER NOT NULL,
    
    -- Status
    status VARCHAR(20) DEFAULT 'pending',
    approved BOOLEAN DEFAULT FALSE,
    
    -- Guardian responses
    guardian_responses JSONB DEFAULT '[]',
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- Foreign keys
    FOREIGN KEY (validation_id) REFERENCES validation_requests(validation_id),
    
    -- Indexes
    INDEX idx_guardian_consensus_consensus_id (consensus_id),
    INDEX idx_guardian_consensus_validation_id (validation_id),
    INDEX idx_guardian_consensus_status (status),
    INDEX idx_guardian_consensus_created_at (created_at)
);

-- =============================================================================
-- AUDIT AND SECURITY TABLES
-- =============================================================================

-- Security audit logs
CREATE TABLE security_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_id UUID,
    ip_address INET,
    user_agent TEXT,
    
    -- Event data
    details JSONB,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_security_audit_logs_event_type (event_type),
    INDEX idx_security_audit_logs_severity (severity),
    INDEX idx_security_audit_logs_created_at (created_at),
    INDEX idx_security_audit_logs_user_id (user_id)
);

-- Convert to hypertable
SELECT create_hypertable('security_audit_logs', 'created_at');

-- Rate limiting data
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identifier VARCHAR(128) NOT NULL, -- IP or user ID
    endpoint VARCHAR(128) NOT NULL,
    requests INTEGER DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_rate_limits_identifier (identifier),
    INDEX idx_rate_limits_endpoint (endpoint),
    INDEX idx_rate_limits_window_start (window_start)
);

-- =============================================================================
-- SYSTEM TABLES
-- =============================================================================

-- Application configuration
CREATE TABLE app_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(128) UNIQUE NOT NULL,
    value JSONB NOT NULL,
    description TEXT,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_app_config_key (key)
);

-- System health metrics
CREATE TABLE system_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    component VARCHAR(64) NOT NULL,
    status VARCHAR(20) NOT NULL,
    metrics JSONB,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_system_health_component (component),
    INDEX idx_system_health_created_at (created_at)
);

-- Convert to hypertable
SELECT create_hypertable('system_health', 'created_at');

-- =============================================================================
-- INITIAL DATA
-- =============================================================================

-- Insert default configuration
INSERT INTO app_config (key, value, description) VALUES
('guardian_threshold', '3', 'Required number of Guardian signatures for consensus'),
('total_guardians', '5', 'Total number of Guardian Angels'),
('validation_timeout', '3600000', 'Validation timeout in milliseconds'),
('max_validation_attempts', '3', 'Maximum retry attempts for validations'),
('supported_chains', '["ethereum", "solana", "polygon", "arbitrum", "bsc"]', 'List of supported blockchain networks');

-- Insert default Guardian Angels (development/testing)
INSERT INTO guardians (guardian_id, name, public_key, endpoint, active) VALUES
('guardian_001', 'Guardian Alpha', 'development_public_key_001', 'https://guardian1.example.com', true),
('guardian_002', 'Guardian Beta', 'development_public_key_002', 'https://guardian2.example.com', true),
('guardian_003', 'Guardian Gamma', 'development_public_key_003', 'https://guardian3.example.com', true),
('guardian_004', 'Guardian Delta', 'development_public_key_004', 'https://guardian4.example.com', true),
('guardian_005', 'Guardian Epsilon', 'development_public_key_005', 'https://guardian5.example.com', true);

-- =============================================================================
-- TRIGGERS AND FUNCTIONS
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_validation_requests_updated_at 
    BEFORE UPDATE ON validation_requests 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_guardians_updated_at 
    BEFORE UPDATE ON guardians 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_app_config_updated_at 
    BEFORE UPDATE ON app_config 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- VIEWS
-- =============================================================================

-- Current reserves view
CREATE VIEW current_reserves AS
SELECT DISTINCT ON (address)
    address,
    balance,
    utxos,
    block_height,
    created_at
FROM bitcoin_reserves
ORDER BY address, created_at DESC;

-- Guardian status view
CREATE VIEW guardian_status AS
SELECT 
    guardian_id,
    name,
    active,
    total_signatures,
    successful_signatures,
    CASE 
        WHEN total_signatures > 0 THEN 
            ROUND((successful_signatures::DECIMAL / total_signatures * 100), 2)
        ELSE 0 
    END as success_rate_percent,
    last_seen,
    CASE 
        WHEN last_seen IS NULL THEN 'never_seen'
        WHEN last_seen > NOW() - INTERVAL '5 minutes' THEN 'online'
        WHEN last_seen > NOW() - INTERVAL '1 hour' THEN 'recent'
        ELSE 'offline'
    END as online_status
FROM guardians;

-- Validation statistics view
CREATE VIEW validation_stats AS
SELECT 
    DATE_TRUNC('day', created_at) as date,
    chain,
    COUNT(*) as total_validations,
    COUNT(*) FILTER (WHERE status = 'completed') as successful_validations,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_validations,
    COUNT(*) FILTER (WHERE status IN ('pending', 'processing', 'verifying_payment', 'awaiting_consensus', 'signing')) as pending_validations,
    AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) FILTER (WHERE status = 'completed') as avg_processing_time_seconds
FROM validation_requests
GROUP BY DATE_TRUNC('day', created_at), chain
ORDER BY date DESC, chain;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;

-- Create indexes for performance
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_validation_requests_composite 
    ON validation_requests (status, chain, created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_audit_logs_composite 
    ON security_audit_logs (event_type, severity, created_at);

-- Analyze tables for query optimization
ANALYZE;

-- Success message
SELECT 'Universal Bitcoin database initialized successfully!' as message;