const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
require('dotenv').config();
const { Pool } = require('pg');

const useSupabase = false;
const pgPool = useSupabase ? new Pool({ connectionString: process.env.SUPABASE_DB_URL, ssl: { rejectUnauthorized: false } }) : null;
// Supabase connection verification removed – using SQLite only

const dbPath = path.resolve(__dirname, 'nexuslink.db');
const db = new sqlite3.Database(dbPath);
// Helper wrapper for async sqlite queries
function run(sql, params = []) {
  if (useSupabase) {
    return pgPool.query(sql, params).then(res => ({ lastID: null, changes: res.rowCount }));
  }
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  if (useSupabase) {
    return pgPool.query(sql, params).then(res => res.rows[0] || null);
  }
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  if (useSupabase) {
    return pgPool.query(sql, params).then(res => res.rows);
  }
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// Transaction execution helper
function runTransaction(callback) {
  if (useSupabase) {
    return (async () => {
      const client = await pgPool.connect();
      try {
        await client.query('BEGIN');
        const result = await callback({
          run: (sql, p) => client.query(sql, p),
          get: (sql, p) => client.query(sql, p).then(r => r.rows[0] || null),
          all: (sql, p) => client.query(sql, p).then(r => r.rows)
        });
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
    })();
  }
  // SQLite fallback
  return new Promise((resolve, reject) => {
    db.serialize(async () => {
      try {
        await run('BEGIN IMMEDIATE;');
        const result = await callback({ run, get, all });
        await run('COMMIT;');
        resolve(result);
      } catch (err) {
        try { await run('ROLLBACK;'); } catch (_) {}
        reject(err);
      }
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
      name TEXT DEFAULT '',
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

    const adminId = 'admin-1';
    const clientId = 'client-1';
    const promoterId = 'promoter-1';
    const promoter2Id = 'promoter-2';

    // 1. Admin
    await run(`
      INSERT INTO users (id, email, password_hash, role, name, wallet_balance, country)
      VALUES (?, ?, ?, 'admin', 'Nexus Governance', 1280000.00, 'Global / Multi-Node')
    `, [adminId, 'admin@nexuslink.network', passHash]);

    // 2. Client (Brand)
    await run(`
      INSERT INTO users (id, email, password_hash, role, name, wallet_balance, country)
      VALUES (?, ?, ?, 'client', 'Web3 DeFi Growth', 70550.00, 'United States')
    `, [clientId, 'growth@web3defi.io', clientPassHash]);

    // 3. Promoter (Seeders)
    await run(`
      INSERT INTO users (id, email, password_hash, role, name, wallet_balance, country, community_types)
      VALUES (?, ?, ?, 'promoter', 'Alex Seeder', 11877.30, 'United Kingdom', ?)
    `, [promoterId, 'alex.seeder@community.org', promoterPassHash, JSON.stringify(['Discord', 'Telegram', 'Reddit'])]);

    await run(`
      INSERT INTO users (id, email, password_hash, role, name, wallet_balance, country, community_types)
      VALUES (?, ?, ?, 'promoter', 'Elena Growth', 5420.00, 'Germany', ?)
    `, [promoter2Id, 'elena.growth@nexuslink.io', promoterPassHash, JSON.stringify(['WhatsApp', 'Telegram'])]);

    // Seed Campaigns for Client
    const c1Id = 'camp-1';
    const c2Id = 'camp-2';
    const c3Id = 'camp-3';

    await run(`
      INSERT INTO campaigns (id, client_id, title, target_url, total_budget, remaining_budget, cost_per_click, geo_target, community_niches, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `, [
      c1Id,
      clientId,
      'NexusDeFi Decentralized Staking Hub Launch',
      'https://example.com/nexus-defi-staking',
      83000.00,
      65072.00,
      41.50,
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
      41500.00,
      25746.60,
      33.20,
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
      20750.00,
      996.00,
      49.80,
      JSON.stringify(['BR', 'PH', 'ID', 'IN']),
      JSON.stringify(['Discord', 'Telegram'])
    ]);

    // Seed Promoter Links
    const pLink1Id = 'link-1';
    const pLink2Id = 'link-2';

    await run(`
      INSERT INTO promoter_links (id, promoter_id, campaign_id, custom_slug, total_clicks)
      VALUES (?, ?, ?, ?, ?)
    `, [pLink1Id, promoterId, c1Id, 'alex-defi-alpha', 432]);

    await run(`
      INSERT INTO promoter_links (id, promoter_id, campaign_id, custom_slug, total_clicks)
      VALUES (?, ?, ?, ?, ?)
    `, [pLink2Id, promoterId, c2Id, 'alex-vpn-secure', 112]);

    // Seed Financial Ledger transactions
    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'deposit', ?, ?, 83000.00, 'Initial escrow deposit for DeFi Campaign')
    `, [uuidv4(), clientId, c1Id]);

    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'deposit', ?, ?, 20750.00, 'Escrow top-up for AlphaGame Season 4')
    `, [uuidv4(), clientId, c3Id]);

    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'platform_revenue', ?, ?, 7154.60, 'System spread fee accrued')
    `, [uuidv4(), adminId, c1Id]);

    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'payout', ?, ?, 10731.90, 'Promoter click earnings aggregated')
    `, [uuidv4(), promoterId, c1Id]);

    // Seed Proof Submission Task
    await run(`
      INSERT INTO tasks (id, promoter_id, campaign_id, screenshot_url, proof_notes, status, payout_amount)
      VALUES (?, ?, ?, ?, ?, 'pending', 2075.00)
    `, [
      'task-1',
      promoterId,
      c1Id,
      'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=600&q=80',
      'Pinned announcement in 42k Telegram Web3 Alpha Channel for 24h.'
    ]);

    // Seed Pending Withdrawal
    await run(`
      INSERT INTO withdrawals (id, user_id, amount, destination_wallet, network, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `, [
      'w-1',
      promoterId,
      8300.00,
      '0x71C...B9e4',
      'Polygon / USDT'
    ]);

    // Seed sample anti-fraud threat logs
    await run(`
      INSERT INTO threat_logs (id, ip_address, user_agent, referrer, reason, risk_score, slug, campaign_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      't-1',
      '198.51.100.42',
      'DatacenterBot/1.0',
      'https://anonymous-crawler.net',
      'Known Datacenter IP Subnet (AS16509 AWS)',
      92,
      'alex-defi-alpha',
      c1Id
    ]);

    await run(`
      INSERT INTO threat_logs (id, ip_address, user_agent, referrer, reason, risk_score, slug, campaign_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      't-2',
      '203.0.113.88',
      'HeadlessChrome/118.0.0.0',
      '',
      'Commercial VPN / Tor Exit Node Signature',
      88,
      'alex-vpn-secure',
      c2Id
    ]);

    await run(`
      INSERT INTO threat_logs (id, ip_address, user_agent, referrer, reason, risk_score, slug, campaign_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      't-3',
      '54.210.88.19',
      'Python-requests/2.31.0',
      '',
      'Automated scraper via AWS Cloud Datacenter',
      95,
      'alex-defi-alpha',
      c1Id
    ]);
  }
}

module.exports = {
  db,
  run,
  get,
  all,
  runTransaction,
  initDB
};
