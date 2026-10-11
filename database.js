const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, 'nexuslink.db');
const db = new sqlite3.Database(dbPath);

// Helper wrapper for async sqlite queries
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function initDB() {
  await run(`PRAGMA foreign_keys = ON;`);

  // Users Table
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'client', 'promoter')),
      wallet_balance REAL NOT NULL DEFAULT 0.00,
      device_fingerprint TEXT,
      country TEXT DEFAULT 'United States',
      community_types TEXT DEFAULT '[]',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Campaigns Table
  await run(`
    CREATE TABLE IF NOT EXISTS campaigns (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      title TEXT NOT NULL,
      target_url TEXT NOT NULL,
      total_budget REAL NOT NULL,
      remaining_budget REAL NOT NULL,
      cost_per_click REAL NOT NULL,
      geo_target TEXT DEFAULT '[]',
      community_niches TEXT DEFAULT '[]',
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'paused', 'exhausted')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(client_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Promoter Links Table
  await run(`
    CREATE TABLE IF NOT EXISTS promoter_links (
      id TEXT PRIMARY KEY,
      promoter_id TEXT NOT NULL,
      campaign_id TEXT NOT NULL,
      custom_slug TEXT UNIQUE NOT NULL,
      total_clicks INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(promoter_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
      UNIQUE(promoter_id, campaign_id)
    );
  `);

  await run(`CREATE INDEX IF NOT EXISTS idx_slug ON promoter_links(custom_slug);`);

  // Tasks Table (Proof submissions)
  await run(`
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      promoter_id TEXT NOT NULL,
      campaign_id TEXT NOT NULL,
      screenshot_url TEXT NOT NULL,
      proof_notes TEXT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'flagged')),
      payout_amount REAL NOT NULL DEFAULT 0.00,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(promoter_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
    );
  `);

  // Financial Ledger Table
  await run(`
    CREATE TABLE IF NOT EXISTS financial_ledger (
      id TEXT PRIMARY KEY,
      transaction_type TEXT NOT NULL CHECK(transaction_type IN ('deposit', 'payout', 'platform_revenue', 'withdrawal')),
      account_id TEXT,
      campaign_id TEXT,
      amount REAL NOT NULL,
      notes TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(account_id) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE SET NULL
    );
  `);

  // Threat Logs Table
  await run(`
    CREATE TABLE IF NOT EXISTS threat_logs (
      id TEXT PRIMARY KEY,
      ip_address TEXT NOT NULL,
      user_agent TEXT,
      referrer TEXT,
      reason TEXT NOT NULL,
      risk_score INTEGER NOT NULL DEFAULT 0,
      slug TEXT,
      campaign_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Click Logs Table (for anti-fraud rate limiting audit)
  await run(`
    CREATE TABLE IF NOT EXISTS click_logs (
      id TEXT PRIMARY KEY,
      ip_address TEXT NOT NULL,
      campaign_id TEXT NOT NULL,
      promoter_link_id TEXT NOT NULL,
      cost_per_click REAL NOT NULL,
      promoter_payout REAL NOT NULL,
      platform_revenue REAL NOT NULL,
      user_agent TEXT,
      referrer TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
      FOREIGN KEY(promoter_link_id) REFERENCES promoter_links(id) ON DELETE CASCADE
    );
  `);

  // Withdrawals Table
  await run(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      amount REAL NOT NULL,
      destination_wallet TEXT NOT NULL,
      network TEXT NOT NULL DEFAULT 'Polygon / USDT',
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'authorized', 'rejected')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Seed default demonstration accounts if not exists
  await seedDefaults();
}

async function seedDefaults() {
  const existingAdmin = await get(`SELECT id FROM users WHERE email = ?`, ['admin@nexuslink.network']);
  if (!existingAdmin) {
    const salt = await bcrypt.genSalt(10);
    const passHash = await bcrypt.hash('admin123', salt);
    const clientPassHash = await bcrypt.hash('client123', salt);
    const promoterPassHash = await bcrypt.hash('promoter123', salt);

    const adminId = uuidv4();
    const clientId = uuidv4();
    const promoterId = uuidv4();
    const promoter2Id = uuidv4();

    // 1. Admin
    await run(`
      INSERT INTO users (id, email, password_hash, role, wallet_balance, country)
      VALUES (?, ?, ?, 'admin', 15420.50, 'Global / Multi-Node')
    `, [adminId, 'admin@nexuslink.network', passHash]);

    // 2. Client (Brand)
    await run(`
      INSERT INTO users (id, email, password_hash, role, wallet_balance, country)
      VALUES (?, ?, ?, 'client', 850.00, 'United States')
    `, [clientId, 'growth@web3defi.io', clientPassHash]);

    // 3. Promoter (Seeders)
    await run(`
      INSERT INTO users (id, email, password_hash, role, wallet_balance, country, community_types)
      VALUES (?, ?, ?, 'promoter', 142.80, 'United Kingdom', ?)
    `, [promoterId, 'alex.seeder@community.org', promoterPassHash, JSON.stringify(['Discord', 'Telegram', 'Reddit'])]);

    await run(`
      INSERT INTO users (id, email, password_hash, role, wallet_balance, country, community_types)
      VALUES (?, ?, ?, 'promoter', 65.40, 'Germany', ?)
    `, [promoter2Id, 'elena.growth@nexuslink.io', promoterPassHash, JSON.stringify(['WhatsApp', 'Telegram'])]);

    // Seed Campaigns for Client
    const c1Id = uuidv4();
    const c2Id = uuidv4();
    const c3Id = uuidv4();

    await run(`
      INSERT INTO campaigns (id, client_id, title, target_url, total_budget, remaining_budget, cost_per_click, geo_target, community_niches, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `, [
      c1Id,
      clientId,
      'NexusDeFi Decentralized Staking Hub Launch',
      'https://example.com/nexus-defi-staking',
      1000.00,
      784.50,
      0.50,
      JSON.stringify(['US', 'UK', 'DE', 'SG']),
      JSON.stringify(['Discord', 'Telegram', 'Reddit'])
    ]);

    await run(`
      INSERT INTO campaigns (id, client_id, title, target_url, total_budget, remaining_budget, cost_per_click, geo_target, community_niches, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `, [
      c2Id,
      clientId,
      'CyberShield Zero-Knowledge VPN Early Access',
      'https://example.com/cybershield-vpn-beta',
      500.00,
      310.20,
      0.40,
      JSON.stringify(['Global', 'CA', 'AU', 'JP']),
      JSON.stringify(['WhatsApp', 'Reddit'])
    ]);

    await run(`
      INSERT INTO campaigns (id, client_id, title, target_url, total_budget, remaining_budget, cost_per_click, geo_target, community_niches, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'paused')
    `, [
      c3Id,
      clientId,
      'AlphaGame Play-to-Earn Season 4 Whitelist',
      'https://example.com/alphagame-season4',
      250.00,
      12.00,
      0.60,
      JSON.stringify(['BR', 'PH', 'ID', 'IN']),
      JSON.stringify(['Discord', 'Telegram'])
    ]);

    // Seed Promoter Links
    const pLink1Id = uuidv4();
    const pLink2Id = uuidv4();

    await run(`
      INSERT INTO promoter_links (id, promoter_id, campaign_id, custom_slug, total_clicks)
      VALUES (?, ?, ?, ?, ?)
    `, [pLink1Id, promoterId, c1Id, 'alex-defi-alpha', 431]);

    await run(`
      INSERT INTO promoter_links (id, promoter_id, campaign_id, custom_slug, total_clicks)
      VALUES (?, ?, ?, ?, ?)
    `, [pLink2Id, promoterId, c2Id, 'alex-vpn-secure', 112]);

    // Seed Financial Ledger transactions
    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'deposit', ?, ?, 1000.00, 'Initial smart-escrow deposit for DeFi Campaign')
    `, [uuidv4(), clientId, c1Id]);

    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'platform_revenue', ?, ?, 86.20, 'System spread fee accrued')
    `, [uuidv4(), adminId, c1Id]);

    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'payout', ?, ?, 129.30, 'Promoter click earnings aggregated')
    `, [uuidv4(), promoterId, c1Id]);

    // Seed Proof Submission Task
    await run(`
      INSERT INTO tasks (id, promoter_id, campaign_id, screenshot_url, proof_notes, status, payout_amount)
      VALUES (?, ?, ?, ?, ?, 'pending', 25.00)
    `, [
      uuidv4(),
      promoterId,
      c1Id,
      'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=600&q=80',
      'Posted announcement in 42k Telegram Web3 Alpha Channel & pinned for 24h.'
    ]);

    // Seed Pending Withdrawal
    await run(`
      INSERT INTO withdrawals (id, user_id, amount, destination_wallet, network, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `, [
      uuidv4(),
      promoterId,
      100.00,
      '0x71C...B9e4',
      'Polygon / USDT'
    ]);

    // Seed sample anti-fraud threat logs
    await run(`
      INSERT INTO threat_logs (id, ip_address, user_agent, referrer, reason, risk_score, slug)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      uuidv4(),
      '198.51.100.42',
      'Mozilla/5.0 (compatible; DatacenterBot/1.0)',
      'https://anonymous-crawler.net',
      'Known Datacenter IP Subnet (AS16509 AWS)',
      92,
      'alex-defi-alpha'
    ]);

    await run(`
      INSERT INTO threat_logs (id, ip_address, user_agent, referrer, reason, risk_score, slug)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      uuidv4(),
      '203.0.113.88',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/118.0.0.0',
      '',
      'Commercial VPN / Tor Exit Node Signature',
      88,
      'alex-vpn-secure'
    ]);
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  initDB
};
