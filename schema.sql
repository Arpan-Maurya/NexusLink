-- =========================================================================
-- NEXUSLINK: Production PostgreSQL Database Blueprint Schema
-- Decentralized Community Affiliate Network Application
-- =========================================================================

-- Enable pgcrypto or uuid-ossp for UUID generation if needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('admin', 'client', 'promoter')),
    name VARCHAR(255) DEFAULT '',
    wallet_balance NUMERIC(14, 4) NOT NULL DEFAULT 0.0000,
    device_fingerprint VARCHAR(255),
    country VARCHAR(64) DEFAULT 'Global',
    community_types TEXT[] DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. CAMPAIGNS TABLE
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    client_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    target_url TEXT NOT NULL,
    total_budget NUMERIC(14, 4) NOT NULL,
    remaining_budget NUMERIC(14, 4) NOT NULL,
    cost_per_click NUMERIC(14, 4) NOT NULL,
    geo_target TEXT[] DEFAULT '{}',
    community_niches TEXT[] DEFAULT '{}',
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'exhausted')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. PROMOTER_LINKS TABLE
CREATE TABLE IF NOT EXISTS promoter_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    promoter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    custom_slug VARCHAR(128) UNIQUE NOT NULL,
    total_clicks INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_promoter_campaign UNIQUE (promoter_id, campaign_id)
);

CREATE INDEX IF NOT EXISTS idx_promoter_links_slug ON promoter_links(custom_slug);

-- 4. TASKS TABLE (Screenshot Proof & Validation)
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    promoter_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    screenshot_url TEXT NOT NULL,
    proof_notes TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'flagged')),
    payout_amount NUMERIC(14, 4) NOT NULL DEFAULT 0.0000,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. FINANCIAL_LEDGER TABLE
CREATE TABLE IF NOT EXISTS financial_ledger (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    transaction_type VARCHAR(64) NOT NULL CHECK (transaction_type IN ('deposit', 'payout', 'platform_revenue', 'withdrawal')),
    account_id UUID REFERENCES users(id) ON DELETE SET NULL,
    campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
    amount NUMERIC(14, 4) NOT NULL,
    notes TEXT,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. THREAT_LOGS TABLE (Multi-Variable Anti-Fraud Intelligence)
CREATE TABLE IF NOT EXISTS threat_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(128) NOT NULL,
    user_agent TEXT,
    referrer TEXT,
    reason VARCHAR(255) NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    slug VARCHAR(128),
    campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 7. CLICKS_AUDIT_LOGS TABLE (Rate Limiting & Conversion Auditing)
CREATE TABLE IF NOT EXISTS click_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address VARCHAR(128) NOT NULL,
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    promoter_link_id UUID NOT NULL REFERENCES promoter_links(id) ON DELETE CASCADE,
    cost_per_click NUMERIC(14, 4) NOT NULL,
    promoter_payout NUMERIC(14, 4) NOT NULL,
    platform_revenue NUMERIC(14, 4) NOT NULL,
    user_agent TEXT,
    referrer TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 8. WITHDRAWALS TABLE (Pending Authorization Engine)
CREATE TABLE IF NOT EXISTS withdrawals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount NUMERIC(14, 4) NOT NULL,
    destination_wallet VARCHAR(255) NOT NULL,
    network VARCHAR(64) NOT NULL DEFAULT 'Polygon / USDT',
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'rejected')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
