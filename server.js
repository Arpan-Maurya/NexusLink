const express = require('express');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, run, get, all, runTransaction, initDB } = require('./database');
const { inspectTrafficHeaders } = require('./antiFraud');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'nexuslink_secure_atomic_arbitrage_secret_2026';

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(__dirname));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// AUTHENTICATION HELPER & MIDDLEWARE
// ============================================================================
function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
      name: user.name || ''
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Optional / Non-blocking authentication extractor
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['x-access-token'];
  let token = null;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (authHeader) {
    token = authHeader.trim();
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }

  if (token) {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;
    } catch (err) {
      req.user = null;
      req.tokenInvalid = true;
    }
  } else {
    req.user = null;
  }
  next();
}

app.use(authenticate);

// Role requirement guard
function requireRole(roles = []) {
  return (req, res, next) => {
    if (!req.user) {
      if (req.tokenInvalid) {
        return res.status(401).json({ error: 'Invalid or expired authentication token. Please sign in.' });
      }
      return res.status(401).json({ error: 'Authentication required. Please sign in.' });
    }
    if (roles.length > 0 && !roles.includes(req.user.role)) {
      return res.status(403).json({ error: `Access denied. Role '${req.user.role}' is not authorized for this resource.` });
    }
    next();
  };
}

// ============================================================================
// 1. ADVANCED REDIRECT ROUTING & ANTI-FRAUD CONTROLLER ENGINE
// GET /r/:slug
// ============================================================================
app.get('/r/:slug', async (req, res) => {
  const { slug } = req.params;

  try {
    // 1. Locate the promoter link & associated campaign
    const link = await get(`
      SELECT pl.*, c.id as campaign_id, c.client_id, c.target_url, c.cost_per_click, 
             c.remaining_budget, c.status as campaign_status
      FROM promoter_links pl
      JOIN campaigns c ON pl.campaign_id = c.id
      WHERE pl.custom_slug = ?
    `, [slug]);

    if (!link) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html><head><title>NexusLink - Invalid Link</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>body{background:#0a0c10;color:#e6edf3;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}</style>
        </head><body><div style="text-align:center;"><h2>Invalid or Expired NexusLink</h2><p>This tracking link does not exist.</p></div></body></html>
      `);
    }

    const targetUrl = link.target_url || 'https://google.com';

    // 2. Active middleware inspection
    const audit = await inspectTrafficHeaders(req, link.campaign_id);

    // Check if campaign is active and has sufficient budget
    const hasBudget = Number(link.remaining_budget) >= Number(link.cost_per_click);
    const isCampaignActive = link.campaign_status === 'active' && hasBudget;

    if (!audit.valid || !isCampaignActive) {
      const threatReason = !audit.valid 
        ? audit.reason 
        : `Campaign inactive or budget exhausted (₹${Number(link.remaining_budget).toFixed(2)})`;
      
      const threatScore = !audit.valid ? audit.riskScore : 45;

      // Log the event inside threat_logs
      await run(`
        INSERT INTO threat_logs (id, ip_address, user_agent, referrer, reason, risk_score, slug, campaign_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        uuidv4(),
        audit.ip,
        audit.userAgent,
        audit.referrer,
        threatReason,
        threatScore,
        slug,
        link.campaign_id
      ]);

      // Direct transparent redirect WITHOUT incrementing clicks or triggering financial payouts
      return res.redirect(302, targetUrl);
    }

    // 3. Traffic verified successfully:
    // Execute atomic balance deduction & 60/40 split allocation inside a database transaction
    const cpc = Number(link.cost_per_click);
    const promoterShare = Number((cpc * 0.60).toFixed(4));
    const platformShare = Number((cpc * 0.40).toFixed(4));

    await runTransaction(async () => {
      // A. Increment Promoter_Links.total_clicks by 1
      await run(`
        UPDATE promoter_links SET total_clicks = total_clicks + 1 WHERE id = ?
      `, [link.id]);

      // B. Deduct cost_per_click from Campaigns.remaining_budget
      await run(`
        UPDATE campaigns 
        SET remaining_budget = MAX(0, remaining_budget - ?),
            status = CASE WHEN remaining_budget - ? <= 0 THEN 'exhausted' ELSE status END
        WHERE id = ?
      `, [cpc, cpc, link.campaign_id]);

      // C. Credit 60% of cost_per_click to Promoter's wallet_balance
      await run(`
        UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?
      `, [promoterShare, link.promoter_id]);

      // D. Log into click_logs
      const clickLogId = uuidv4();
      await run(`
        INSERT INTO click_logs (id, ip_address, campaign_id, promoter_link_id, cost_per_click, promoter_payout, platform_revenue, user_agent, referrer)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        clickLogId,
        audit.ip,
        link.campaign_id,
        link.id,
        cpc,
        promoterShare,
        platformShare,
        audit.userAgent,
        audit.referrer
      ]);

      // E. Log Financial Ledger records (Promoter Payout & Platform Revenue)
      await run(`
        INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
        VALUES (?, 'payout', ?, ?, ?, ?)
      `, [
        uuidv4(),
        link.promoter_id,
        link.campaign_id,
        promoterShare,
        `Valid referral click via slug: ${slug} (60% split)`
      ]);

      await run(`
        INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
        VALUES (?, 'platform_revenue', NULL, ?, ?, ?)
      `, [
        uuidv4(),
        link.campaign_id,
        platformShare,
        `Platform commission fee (40% split) for click on ${slug}`
      ]);
    });

    // Immediately trigger HTTP 302 redirect sending browser visitor to target_url
    return res.redirect(302, targetUrl);

  } catch (err) {
    console.error('Redirect routing error:', err);
    // On unexpected error, safely redirect without payouts to preserve visitor experience
    return res.redirect(302, 'https://google.com');
  }
});

// ============================================================================
// 2. AUTHENTICATION & SESSION ENDPOINTS
// ============================================================================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await get(`SELECT * FROM users WHERE email = ?`, [email]);
    if (!user) {
      return res.status(401).json({ error: 'User not found with this email' });
    }
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Incorrect credentials' });
    }

    const safeUser = { ...user };
    delete safeUser.password_hash;
    safeUser.community_types = JSON.parse(safeUser.community_types || '[]');

    const token = generateToken(safeUser);
    res.json({ success: true, token, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Unified Registration Endpoint (Brand / Client & Promoter)
app.post('/api/auth/register', async (req, res) => {
  const { email, password, role, name, country, community_types, device_fingerprint } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const targetRole = role === 'client' ? 'client' : 'promoter'; // Admin registration restricted
    const existing = await get(`SELECT id FROM users WHERE email = ?`, [email]);
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    const newId = uuidv4();
    const displayName = name || email.split('@')[0];

    const initialBalance = targetRole === 'client' ? 0.00 : 0.00;
    const communities = Array.isArray(community_types) 
      ? community_types 
      : (community_types ? community_types.split(',').map(s => s.trim()) : ['Telegram', 'WhatsApp']);

    await run(`
      INSERT INTO users (id, email, password_hash, role, name, wallet_balance, country, community_types, device_fingerprint)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      newId,
      email,
      hash,
      targetRole,
      displayName,
      initialBalance,
      country || 'Global',
      JSON.stringify(communities),
      device_fingerprint || 'fp_' + Math.random().toString(36).substring(7)
    ]);

    const user = await get(`SELECT id, email, role, name, wallet_balance, country, community_types, created_at FROM users WHERE id = ?`, [newId]);
    user.community_types = JSON.parse(user.community_types || '[]');

    const token = generateToken(user);
    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Backward-compatible promoter quick registration
app.post('/api/auth/register-promoter', async (req, res) => {
  req.body.role = 'promoter';
  return app._router.handle(req, res);
});

// Current User profile fetch (strictly derives identity from JWT)
app.get('/api/auth/me', requireRole(['admin', 'client', 'promoter']), async (req, res) => {
  try {
    const user = await get(`SELECT id, email, role, name, wallet_balance, country, community_types, created_at FROM users WHERE id = ?`, [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.community_types = JSON.parse(user.community_types || '[]');
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// User fetch by ID (Admins can view any user; other roles can only view their own record)
app.get('/api/users/:id', requireRole(['admin', 'client', 'promoter']), async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.id !== req.params.id) {
      return res.status(403).json({ error: 'Access denied to this user profile' });
    }
    const user = await get(`SELECT id, email, role, name, wallet_balance, country, community_types, created_at FROM users WHERE id = ?`, [req.params.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.community_types = JSON.parse(user.community_types || '[]');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 3. OVERVIEW & TELEMETRY APIS
// ============================================================================
app.get('/api/overview/metrics', async (req, res) => {
  try {
    const totalDeposits = await get(`SELECT COALESCE(SUM(amount), 0) as total FROM financial_ledger WHERE transaction_type = 'deposit'`);
    const totalClicks = await get(`SELECT COALESCE(SUM(total_clicks), 0) as total FROM promoter_links`);
    const platformRevenue = await get(`SELECT COALESCE(SUM(amount), 0) as total FROM financial_ledger WHERE transaction_type = 'platform_revenue'`);
    const totalThreats = await get(`SELECT COUNT(id) as count FROM threat_logs`);

    res.json({
      totalDeposits: totalDeposits.total || 0,
      totalClicks: totalClicks.total || 0,
      platformRevenue: platformRevenue.total || 0,
      totalThreats: totalThreats.count || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/campaigns/top', async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 3;
  try {
    const campaigns = await all(`
      SELECT id, title, cost_per_click, remaining_budget, total_budget, status
      FROM campaigns
      WHERE status = 'active'
      ORDER BY total_budget DESC
      LIMIT ?
    `, [limit]);
    res.json(campaigns);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 4. ADMINISTRATOR GOVERNANCE & SECURITY APIS (Restricted to 'admin')
// ============================================================================
app.get('/api/admin/metrics', requireRole(['admin']), async (req, res) => {
  try {
    const totalDeposits = await get(`SELECT COALESCE(SUM(amount), 0) as total FROM financial_ledger WHERE transaction_type = 'deposit'`);
    const totalPayouts = await get(`SELECT COALESCE(SUM(amount), 0) as total FROM financial_ledger WHERE transaction_type = 'payout'`);
    const platformRevenue = await get(`SELECT COALESCE(SUM(amount), 0) as total FROM financial_ledger WHERE transaction_type = 'platform_revenue'`);
    const totalClicks = await get(`SELECT COALESCE(SUM(total_clicks), 0) as total FROM promoter_links`);
    const totalThreats = await get(`SELECT COUNT(id) as count FROM threat_logs`);
    const pendingWithdrawalsCount = await get(`SELECT COUNT(id) as count FROM withdrawals WHERE status = 'pending'`);
    const pendingTasksCount = await get(`SELECT COUNT(id) as count FROM tasks WHERE status = 'pending'`);

    res.json({
      totalDeposits: totalDeposits.total || 0,
      totalPayouts: totalPayouts.total || 0,
      platformRevenue: platformRevenue.total || 0,
      totalClicks: totalClicks.total || 0,
      totalThreats: totalThreats.count || 0,
      pendingWithdrawals: pendingWithdrawalsCount.count || 0,
      pendingTasks: pendingTasksCount.count || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/ledger', requireRole(['admin']), async (req, res) => {
  try {
    const ledger = await all(`
      SELECT fl.*, u.email as account_email, c.title as campaign_title
      FROM financial_ledger fl
      LEFT JOIN users u ON fl.account_id = u.id
      LEFT JOIN campaigns c ON fl.campaign_id = c.id
      ORDER BY fl.timestamp DESC LIMIT 100
    `);

    const formatted = ledger.map(l => ({
      id: l.id,
      type: l.transaction_type,
      amount: l.amount,
      account: l.account_email || 'Nexus Treasury',
      notes: l.notes || '',
      timestamp: l.timestamp
    }));

    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/ledger/export-csv', requireRole(['admin']), async (req, res) => {
  try {
    const ledger = await all(`
      SELECT fl.*, u.email as account_email
      FROM financial_ledger fl
      LEFT JOIN users u ON fl.account_id = u.id
      ORDER BY fl.timestamp DESC
    `);

    let csv = "Type,Amount,Account,Notes,Timestamp\n";
    ledger.forEach(l => {
      const type = l.transaction_type || '';
      const amount = l.amount || 0;
      const account = l.account_email || 'Nexus Treasury';
      const notes = (l.notes || '').replace(/"/g, '""');
      const timestamp = l.timestamp || '';
      csv += `"${type}","${amount}","${account}","${notes}","${timestamp}"\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=nexuslink_ledger_${Date.now()}.csv`);
    res.send(csv);
  } catch (err) {
    res.status(500).send('Failed to generate CSV');
  }
});

app.get('/api/admin/threats', requireRole(['admin']), async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  try {
    const threats = await all(`
      SELECT tl.*, c.title as campaign_title 
      FROM threat_logs tl
      LEFT JOIN campaigns c ON tl.campaign_id = c.id
      ORDER BY tl.created_at DESC LIMIT ?
    `, [limit]);
    res.json(threats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/withdrawals', requireRole(['admin']), async (req, res) => {
  try {
    const list = await all(`
      SELECT w.*, u.email, u.wallet_balance
      FROM withdrawals w
      JOIN users u ON w.user_id = u.id
      ORDER BY w.created_at DESC
    `);
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function handleAdminWithdrawalResolution(req, res) {
  const action = req.body.action || req.body.status;
  const isAuth = action === 'authorize' || action === 'approved';
  try {
    const item = await get(`SELECT * FROM withdrawals WHERE id = ?`, [req.params.id]);
    if (!item) return res.status(404).json({ error: 'Withdrawal not found' });
    if (item.status !== 'pending') return res.status(400).json({ error: `Withdrawal is already ${item.status}` });

    await runTransaction(async () => {
      if (isAuth) {
        await run(`UPDATE withdrawals SET status = 'authorized' WHERE id = ?`, [req.params.id]);
        await run(`
          INSERT INTO financial_ledger (id, transaction_type, account_id, amount, notes)
          VALUES (?, 'withdrawal', ?, ?, ?)
        `, [uuidv4(), item.user_id, item.amount, `Withdrawal to ${item.destination_wallet} on ${item.network} authorized`]);
      } else {
        await run(`UPDATE withdrawals SET status = 'rejected' WHERE id = ?`, [req.params.id]);
        // Refund balance to user
                await run(`UPDATE users SET wallet_balance = ROUND(wallet_balance + ?, 2) WHERE id = ?`, [item.amount, item.user_id]);
      }
    });

    res.json({ success: true, status: isAuth ? 'authorized' : 'rejected' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

app.post('/api/admin/withdrawals/:id/authorize', requireRole(['admin']), handleAdminWithdrawalResolution);
app.post('/api/admin/withdrawals/:id', requireRole(['admin']), handleAdminWithdrawalResolution);

// Admin campaign status toggle
app.post('/api/admin/campaigns/:id/status', requireRole(['admin']), async (req, res) => {
  const { status } = req.body;
  if (!['active', 'paused', 'exhausted'].includes(status)) {
    return res.status(400).json({ error: "Invalid status: must be 'active', 'paused', or 'exhausted'" });
  }
  try {
    const campaign = await get(`SELECT id FROM campaigns WHERE id = ?`, [req.params.id]);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
    await run(`UPDATE campaigns SET status = ? WHERE id = ?`, [status, req.params.id]);
    res.json({ success: true, status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 5. CLIENT / BRAND DASHBOARD APIS
// ============================================================================
app.get('/api/client/campaigns', requireRole(['admin','client']), async (req, res) => {
  let clientId = null;
  if (req.user && req.user.role === 'client') {
    clientId = req.user.id;
  } else if (req.user && req.user.role === 'admin' && req.query.client_id) {
    clientId = req.query.client_id;
  } else if (!req.user && req.query.client_id) {
    clientId = req.query.client_id;
  }
  try {
    let sql = `
      SELECT c.*, 
        COALESCE(SUM(pl.total_clicks), 0) as total_clicks,
        COUNT(DISTINCT pl.promoter_id) as active_promoters
      FROM campaigns c
      LEFT JOIN promoter_links pl ON c.id = pl.campaign_id
    `;
    const params = [];
    if (clientId) {
      sql += ` WHERE c.client_id = ? `;
      params.push(clientId);
    }
    sql += ` GROUP BY c.id ORDER BY c.created_at DESC`;

    const campaigns = await all(sql, params);
    const parsed = campaigns.map(c => ({
      ...c,
      geo_target: JSON.parse(c.geo_target || '[]'),
      community_niches: JSON.parse(c.community_niches || '[]'),
      budget_depleted: Number((c.total_budget - c.remaining_budget).toFixed(2))
    }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/client/campaigns', requireRole(['client', 'admin']), async (req, res) => {
  const {
    client_id,
    title,
    target_url,
    total_budget,
    cost_per_click,
    geo_target,
    community_niches
  } = req.body;

  try {
    if (!title || !target_url || !total_budget || !cost_per_click) {
      return res.status(400).json({ error: 'Missing mandatory campaign fields' });
    }

    const budget = Number(total_budget);
    const cpc = Number(cost_per_click);

    if (isNaN(budget) || budget <= 0) {
      return res.status(400).json({ error: 'Total budget must be a positive number' });
    }
    if (isNaN(cpc) || cpc <= 0) {
      return res.status(400).json({ error: 'Cost per click must be a positive number' });
    }
    if (cpc > budget) {
      return res.status(400).json({ error: 'Cost per click cannot exceed total budget' });
    }
    if (!target_url.startsWith('http://') && !target_url.startsWith('https://')) {
      return res.status(400).json({ error: 'Target URL must be a valid HTTP or HTTPS URL' });
    }

    // Identity derivation: Clients strictly create under their own ID; Admins may specify client_id
    const resolvedClientId = (req.user.role === 'admin' && client_id) ? client_id : req.user.id;

    const campaignId = 'camp-' + Date.now();
    const geo = Array.isArray(geo_target) ? geo_target : (geo_target ? geo_target.split(',').map(s => s.trim()) : ['Global', 'US']);
    const niches = Array.isArray(community_niches) ? community_niches : (community_niches ? community_niches.split(',').map(s => s.trim()) : ['Telegram', 'Discord', 'Reddit']);

    await runTransaction(async () => {
      await run(`
        INSERT INTO campaigns (id, client_id, title, target_url, total_budget, remaining_budget, cost_per_click, geo_target, community_niches, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
      `, [
        campaignId,
        resolvedClientId,
        title,
        target_url,
        budget,
        budget,
        cpc,
        JSON.stringify(geo),
        JSON.stringify(niches)
      ]);

      // Record Deposit in Financial Ledger
      await run(`
        INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
        VALUES (?, 'deposit', ?, ?, ?, ?)
      `, [
        uuidv4(),
        resolvedClientId,
        campaignId,
        budget,
        `Escrow deposit for campaign: ${title}`
      ]);
    });

    const created = await get(`SELECT * FROM campaigns WHERE id = ?`, [campaignId]);
    created.geo_target = JSON.parse(created.geo_target || '[]');
    created.community_niches = JSON.parse(created.community_niches || '[]');

    res.json({ success: true, campaign: created });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Client toggle own campaign status (with strict ownership check)
app.post('/api/client/campaigns/:id/status', requireRole(['client', 'admin']), async (req, res) => {
  const { status } = req.body;
  try {
    const campaign = await get(`SELECT * FROM campaigns WHERE id = ?`, [req.params.id]);
    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    // Enforce ownership: Clients can only modify their own campaigns
    if (req.user.role === 'client' && campaign.client_id !== req.user.id) {
      return res.status(403).json({ error: 'Access denied. You do not own this campaign.' });
    }

    const validStatus = status === 'paused' ? 'paused' : 'active';
    await run(`UPDATE campaigns SET status = ? WHERE id = ?`, [validStatus, req.params.id]);
    res.json({ success: true, status: validStatus });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Client metrics summary
app.get('/api/client/metrics', requireRole(['admin','client']), async (req, res) => {
  const clientId = (req.user && req.user.role === 'client') 
    ? req.user.id 
    : ((req.user && req.user.role === 'admin' && req.query.client_id) ? req.query.client_id : (req.query.client_id || null));
  try {
    let sql = `
      SELECT 
        COALESCE(SUM(c.total_budget), 0) as total_escrow,
        COALESCE(SUM(c.total_budget - c.remaining_budget), 0) as total_spent,
        COUNT(CASE WHEN c.status = 'active' THEN 1 END) as active_campaigns
      FROM campaigns c
    `;
    const params = [];
    if (clientId) {
      sql += ` WHERE c.client_id = ? `;
      params.push(clientId);
    }
    const metrics = await get(sql, params);

    const clicksSql = clientId ? `
      SELECT COALESCE(SUM(pl.total_clicks), 0) as total_clicks 
      FROM promoter_links pl 
      JOIN campaigns c ON pl.campaign_id = c.id 
      WHERE c.client_id = ?
    ` : `SELECT COALESCE(SUM(total_clicks), 0) as total_clicks FROM promoter_links`;

    const clicksRes = await get(clicksSql, clientId ? [clientId] : []);
    
    let fraudSaved = 0;
    if (clientId) {
      const threatRes = await get(`
        SELECT COUNT(tl.id) as total_threats 
        FROM threat_logs tl 
        JOIN campaigns c ON tl.campaign_id = c.id 
        WHERE c.client_id = ?
      `, [clientId]);
      fraudSaved = threatRes ? threatRes.total_threats : 0;
    } else {
      const threatRes = await get(`SELECT COUNT(id) as total_threats FROM threat_logs`);
      fraudSaved = threatRes ? threatRes.total_threats : 0;
    }

    res.json({
      totalEscrow: metrics.total_escrow || 0,
      totalSpent: metrics.total_spent || 0,
      activeCampaigns: metrics.active_campaigns || 0,
      totalClicks: clicksRes.total_clicks || 0,
      fraudSaved: fraudSaved
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 6. PROMOTER DASHBOARD ("SEEDERS") APIS
// ============================================================================
app.get('/api/promoter/marketplace', requireRole(['promoter','admin']), async (req, res) => {
  const promoterId = (req.user && req.user.role === 'promoter') 
    ? req.user.id 
    : (req.query.promoter_id || 'promoter-1');
  try {
    const campaigns = await all(`
      SELECT c.*, u.email as brand_email,
        (SELECT pl.custom_slug FROM promoter_links pl WHERE pl.campaign_id = c.id AND pl.promoter_id = ?) as joined_slug,
        (SELECT pl.total_clicks FROM promoter_links pl WHERE pl.campaign_id = c.id AND pl.promoter_id = ?) as my_clicks
      FROM campaigns c
      JOIN users u ON c.client_id = u.id
      WHERE c.status = 'active' AND c.remaining_budget >= c.cost_per_click
      ORDER BY c.created_at DESC
    `, [promoterId, promoterId]);

    const parsed = campaigns.map(c => ({
      ...c,
      geo_target: JSON.parse(c.geo_target || '[]'),
      community_niches: JSON.parse(c.community_niches || '[]'),
      promoter_cpc_reward: Number((c.cost_per_click * 0.60).toFixed(4))
    }));
    res.json(parsed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

async function handleGenerateLink(req, res) {
  const { promoter_id, campaign_id } = req.body;
  const resolvedPromoterId = (req.user && req.user.role === 'promoter')
    ? req.user.id
    : ((req.user && req.user.role === 'admin' && promoter_id) ? promoter_id : (req.user ? req.user.id : (promoter_id || 'promoter-1')));

  try {
    if (!campaign_id) {
      return res.status(400).json({ error: 'campaign_id is required' });
    }

    const campaign = await get(`SELECT * FROM campaigns WHERE id = ?`, [campaign_id]);
    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }
    if (campaign.status !== 'active') {
      return res.status(400).json({ error: 'Cannot generate tracking link for an inactive campaign' });
    }

    // Check if already generated
    const existing = await get(`
      SELECT * FROM promoter_links WHERE promoter_id = ? AND campaign_id = ?
    `, [resolvedPromoterId, campaign_id]);

    if (existing) {
      return res.json({ success: true, link: existing, isNew: false });
    }

    // Generate unique clean slug
    const promoter = await get(`SELECT email, name FROM users WHERE id = ?`, [resolvedPromoterId]);
    const cleanPrefix = promoter && promoter.name 
      ? promoter.name.split(' ')[0].replace(/[^a-zA-Z0-9]/g, '').toLowerCase()
      : (promoter ? promoter.email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').toLowerCase() : 'user');
    
    const randSuffix = Math.random().toString(36).substring(2, 7);
    const customSlug = `${cleanPrefix}-${randSuffix}`;

    const linkId = 'link-' + Date.now();
    await run(`
      INSERT INTO promoter_links (id, promoter_id, campaign_id, custom_slug, total_clicks)
      VALUES (?, ?, ?, ?, 0)
    `, [linkId, resolvedPromoterId, campaign_id, customSlug]);

    const created = await get(`SELECT * FROM promoter_links WHERE id = ?`, [linkId]);
    res.json({ success: true, link: created, isNew: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

app.post('/api/promoter/generate-link', requireRole(['promoter', 'admin']), handleGenerateLink);
app.post('/api/promoter/links', requireRole(['promoter', 'admin']), handleGenerateLink);

app.get('/api/promoter/my-links', requireRole(['promoter', 'admin']), async (req, res) => {
  const promoterId = (req.user.role === 'admin' && req.query.promoter_id) ? req.query.promoter_id : req.user.id;
  try {
    const links = await all(`
      SELECT pl.*, c.title as campaign_title, c.cost_per_click, c.target_url, c.status as campaign_status
      FROM promoter_links pl
      JOIN campaigns c ON pl.campaign_id = c.id
      WHERE pl.promoter_id = ?
      ORDER BY pl.created_at DESC
    `, [promoterId]);

    const enriched = links.map(l => ({
      ...l,
      estimated_earnings: Number((l.total_clicks * l.cost_per_click * 0.6).toFixed(2))
    }));

    res.json(enriched);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Promoter metrics summary
app.get('/api/promoter/metrics', async (req, res) => {
  const promoterId = (req.user && req.user.role === 'promoter') 
    ? req.user.id 
    : ((req.user && req.user.role === 'admin' && req.query.promoter_id) ? req.query.promoter_id : (req.query.promoter_id || 'promoter-1'));
  try {
    const user = await get(`SELECT wallet_balance FROM users WHERE id = ?`, [promoterId]);
    const links = await all(`SELECT total_clicks FROM promoter_links WHERE promoter_id = ?`, [promoterId]);
    
    const balance = user ? user.wallet_balance : 0;
    const clicks = links.reduce((acc, l) => acc + (l.total_clicks || 0), 0);
    const slugsCount = links.length;

    res.json({
      walletBalance: balance,
      totalClicks: clicks,
      activeSlugs: slugsCount
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Proof Submission Form (Task submission)
app.post('/api/promoter/tasks', requireRole(['promoter', 'admin']), async (req, res) => {
  const { promoter_id, campaign_id, screenshot_url, proof_notes, payout_amount } = req.body;
  const resolvedPromoterId = (req.user.role === 'admin' && promoter_id) ? promoter_id : req.user.id;

  try {
    if (!campaign_id || !screenshot_url) {
      return res.status(400).json({ error: 'Missing required proof fields (campaign_id, screenshot_url)' });
    }

    const campaign = await get(`SELECT id, remaining_budget FROM campaigns WHERE id = ?`, [campaign_id]);
    if (!campaign) {
      return res.status(404).json({ error: 'Campaign not found' });
    }

    const payout = Number(payout_amount) || 2075.00;
    const taskId = 'task-' + Date.now();
    await run(`
      INSERT INTO tasks (id, promoter_id, campaign_id, screenshot_url, proof_notes, status, payout_amount)
      VALUES (?, ?, ?, ?, ?, 'pending', ?)
    `, [
      taskId,
      resolvedPromoterId,
      campaign_id,
      screenshot_url,
      proof_notes || '',
      payout
    ]);

    const task = await get(`SELECT * FROM tasks WHERE id = ?`, [taskId]);
    res.json({ success: true, task });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tasks', async (req, res) => {
  const promoterId = (req.user && req.user.role === 'promoter') 
    ? req.user.id 
    : (req.query.promoter_id || null);
  try {
    let sql = `
      SELECT t.*, c.title as campaign_title, u.email as promoter_email
      FROM tasks t
      JOIN campaigns c ON t.campaign_id = c.id
      JOIN users u ON t.promoter_id = u.id
    `;
    const params = [];
    if (promoterId) {
      sql += ` WHERE t.promoter_id = ? `;
      params.push(promoterId);
    }
    sql += ` ORDER BY t.created_at DESC `;

    const tasks = await all(sql, params);
    const formatted = tasks.map(t => ({
      id: t.id,
      campaign_title: t.campaign_title,
      notes: t.proof_notes || '',
      screenshot: t.screenshot_url,
      payout: t.payout_amount,
      status: t.status,
      promoter_email: t.promoter_email,
      created_at: t.created_at
    }));

    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Review Task Proof
app.post('/api/admin/tasks/:id/review', requireRole(['admin']), async (req, res) => {
  const { status } = req.body; // 'approved' or 'flagged'
  if (!['approved', 'flagged'].includes(status)) {
    return res.status(400).json({ error: "Status must be 'approved' or 'flagged'" });
  }
  try {
    const task = await get(`SELECT * FROM tasks WHERE id = ?`, [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Task proof not found' });
    if (task.status !== 'pending') return res.status(400).json({ error: `Task proof is already ${task.status}` });

    await runTransaction(async () => {
      await run(`UPDATE tasks SET status = ? WHERE id = ?`, [status, req.params.id]);

      if (status === 'approved') {
        // Credit bonus payout to promoter wallet
        await run(`
          UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?
        `, [task.payout_amount, task.promoter_id]);

        // Deduct from campaign budget
        await run(`
          UPDATE campaigns SET remaining_budget = MAX(0, remaining_budget - ?) WHERE id = ?
        `, [task.payout_amount, task.campaign_id]);

        // Log in Financial Ledger
        await run(`
          INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
          VALUES (?, 'payout', ?, ?, ?, ?)
        `, [
          uuidv4(),
          task.promoter_id,
          task.campaign_id,
          task.payout_amount,
          `Approved Community Broadcast Task Proof reward`
        ]);
      }
    });

    res.json({ success: true, status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Wallet Withdraw Request (Atomic balance verification & deduction)
async function handleWithdrawalRequest(req, res) {
  const { user_id, amount, destination_wallet, network } = req.body;
  // Non-admins CANNOT withdraw from other accounts
  const resolvedUserId = (req.user.role === 'admin' && user_id) ? user_id : req.user.id;

  try {
    const withdrawAmt = Number(amount);
    if (!withdrawAmt || isNaN(withdrawAmt) || withdrawAmt <= 0) {
      return res.status(400).json({ error: 'Invalid withdrawal amount: must be greater than zero' });
    }

    if (!destination_wallet || destination_wallet.trim().length < 4) {
      return res.status(400).json({ error: 'Valid destination wallet address is required' });
    }

    const wid = 'w-' + Date.now();
    let remainingBal = 0;

    await runTransaction(async () => {
      const user = await get(`SELECT wallet_balance FROM users WHERE id = ?`, [resolvedUserId]);
      if (!user) {
        throw new Error('User account not found');
      }
      if (Number(user.wallet_balance) < withdrawAmt) {
        throw new Error(`Insufficient wallet balance. Available: ₹${Number(user.wallet_balance).toFixed(2)}, Requested: ₹${withdrawAmt.toFixed(2)}`);
      }

      await run(`UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?`, [withdrawAmt, resolvedUserId]);

      await run(`
        INSERT INTO withdrawals (id, user_id, amount, destination_wallet, network, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
      `, [
        wid,
        resolvedUserId,
        withdrawAmt,
        destination_wallet.trim(),
        network || 'Polygon / USDT'
      ]);

      remainingBal = Number((user.wallet_balance - withdrawAmt).toFixed(2));
    });

    res.json({ success: true, withdrawalId: wid, remainingBalance: remainingBal });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}

app.post('/api/promoter/withdraw', requireRole(['promoter', 'client', 'admin']), handleWithdrawalRequest);
app.post('/api/withdrawals', requireRole(['promoter', 'client', 'admin']), handleWithdrawalRequest);

app.get('/api/promoter/wallet-history', requireRole(['promoter', 'client', 'admin']), async (req, res) => {
  const userId = (req.user.role === 'admin' && req.query.user_id) ? req.query.user_id : req.user.id;
  try {
    const txs = await all(`
      SELECT fl.*, c.title as campaign_title
      FROM financial_ledger fl
      LEFT JOIN campaigns c ON fl.campaign_id = c.id
      WHERE fl.account_id = ?
      ORDER BY fl.timestamp DESC LIMIT 50
    `, [userId]);

    const withdrawals = await all(`
      SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC
    `, [userId]);

    res.json({ transactions: txs, withdrawals });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Interactive Anti-Fraud Simulator Endpoint
app.post('/api/test-fraud-engine', async (req, res) => {
  const { test_ip, test_user_agent, test_referrer, slug } = req.body;
  try {
    const mockReq = {
      headers: {
        'x-forwarded-for': test_ip || '127.0.0.1',
        'user-agent': test_user_agent || 'Mozilla/5.0 Chrome/120.0.0.0',
        'referer': test_referrer || ''
      },
      socket: { remoteAddress: test_ip || '127.0.0.1' },
      ip: test_ip || '127.0.0.1'
    };

    const link = slug ? await get(`SELECT campaign_id FROM promoter_links WHERE custom_slug = ?`, [slug]) : null;
    const campaignId = link ? link.campaign_id : null;

    const evaluation = await inspectTrafficHeaders(mockReq, campaignId);
    res.json(evaluation);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Health check API
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    version: '2.0.0', 
    protocol: 'NexusLink Anti-Fraud Engine', 
    timestamp: new Date().toISOString() 
  });
});

// Fallback for all SPA routes
app.use((req, res) => {
  const rootIndex = path.join(__dirname, 'index.html');
  const pubIndex = path.join(__dirname, 'public', 'index.html');
  const fs = require('fs');
  if (fs.existsSync(rootIndex)) {
    res.sendFile(rootIndex);
  } else {
    res.sendFile(pubIndex);
  }
});

// Start Server
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`[NexusLink Engine] Running on port ${PORT}`);
    console.log(`[NexusLink Anti-Fraud] Active monitoring on /r/:slug`);
  });
}).catch(err => {
  console.error('Database initialization failed:', err);
});
