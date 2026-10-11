const express = require('express');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const { db, run, get, all, initDB } = require('./database');
const { inspectTrafficHeaders } = require('./antiFraud');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

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

    // Default target URL fallback
    const targetUrl = link.target_url || 'https://google.com';

    // 2. Active middleware inspection
    const audit = await inspectTrafficHeaders(req, link.campaign_id);

    // Check if campaign is active and has sufficient budget
    const hasBudget = Number(link.remaining_budget) >= Number(link.cost_per_click);
    const isCampaignActive = link.campaign_status === 'active' && hasBudget;

    if (!audit.valid || !isCampaignActive) {
      const threatReason = !audit.valid 
        ? audit.reason 
        : `Campaign inactive or budget exhausted ($${Number(link.remaining_budget).toFixed(2)})`;
      
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
    // Execute atomic balance deduction & 60/40 split allocation
    const cpc = Number(link.cost_per_click);
    const promoterShare = Number((cpc * 0.60).toFixed(4));
    const platformShare = Number((cpc * 0.40).toFixed(4));

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

    // Immediately trigger HTTP 302 redirect sending browser visitor to target_url
    return res.redirect(302, targetUrl);

  } catch (err) {
    console.error('Redirect routing error:', err);
    // On unexpected error, safely redirect without payouts to preserve visitor experience
    return res.redirect(302, 'https://google.com');
  }
});

// ============================================================================
// 2. AUTHENTICATION & SESSION SIMULATOR
// ============================================================================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
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
    res.json({ success: true, user: safeUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Promoter Quick Registration
app.post('/api/auth/register-promoter', async (req, res) => {
  const { email, password, country, community_types, device_fingerprint } = req.body;
  try {
    const existing = await get(`SELECT id FROM users WHERE email = ?`, [email]);
    if (existing) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password || 'password123', salt);
    const newId = uuidv4();

    await run(`
      INSERT INTO users (id, email, password_hash, role, wallet_balance, country, community_types, device_fingerprint)
      VALUES (?, ?, ?, 'promoter', 0.00, ?, ?, ?)
    `, [
      newId,
      email,
      hash,
      country || 'Global',
      JSON.stringify(community_types || ['Telegram']),
      device_fingerprint || 'fp_' + Math.random().toString(36).substring(7)
    ]);

    const user = await get(`SELECT id, email, role, wallet_balance, country, community_types FROM users WHERE id = ?`, [newId]);
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Current User fetch
app.get('/api/users/:id', async (req, res) => {
  try {
    const user = await get(`SELECT id, email, role, wallet_balance, country, community_types, created_at FROM users WHERE id = ?`, [req.params.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.community_types = JSON.parse(user.community_types || '[]');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 3. ADMINISTRATOR DASHBOARD APIS
// ============================================================================
app.get('/api/admin/metrics', async (req, res) => {
  try {
    const totalDeposits = await get(`SELECT SUM(amount) as total FROM financial_ledger WHERE transaction_type = 'deposit'`);
    const totalPayouts = await get(`SELECT SUM(amount) as total FROM financial_ledger WHERE transaction_type = 'payout'`);
    const platformRevenue = await get(`SELECT SUM(amount) as total FROM financial_ledger WHERE transaction_type = 'platform_revenue'`);
    const totalClicks = await get(`SELECT SUM(total_clicks) as total FROM promoter_links`);
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

app.get('/api/admin/ledger', async (req, res) => {
  try {
    const ledger = await all(`
      SELECT fl.*, u.email as account_email, c.title as campaign_title
      FROM financial_ledger fl
      LEFT JOIN users u ON fl.account_id = u.id
      LEFT JOIN campaigns c ON fl.campaign_id = c.id
      ORDER BY fl.timestamp DESC LIMIT 100
    `);
    res.json(ledger);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/threats', async (req, res) => {
  try {
    const threats = await all(`
      SELECT tl.*, c.title as campaign_title 
      FROM threat_logs tl
      LEFT JOIN campaigns c ON tl.campaign_id = c.id
      ORDER BY tl.created_at DESC LIMIT 100
    `);
    res.json(threats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/withdrawals', async (req, res) => {
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

app.post('/api/admin/withdrawals/:id/authorize', async (req, res) => {
  const { action } = req.body; // 'authorize' or 'rejected'
  try {
    const item = await get(`SELECT * FROM withdrawals WHERE id = ?`, [req.params.id]);
    if (!item) return res.status(404).json({ error: 'Withdrawal not found' });
    if (item.status !== 'pending') return res.status(400).json({ error: 'Already resolved' });

    if (action === 'authorize') {
      await run(`UPDATE withdrawals SET status = 'authorized' WHERE id = ?`, [req.params.id]);
      // Log to financial ledger
      await run(`
        INSERT INTO financial_ledger (id, transaction_type, account_id, amount, notes)
        VALUES (?, 'withdrawal', ?, ?, ?)
      `, [uuidv4(), item.user_id, item.amount, `Withdrawal to ${item.destination_wallet} on ${item.network} authorized`]);
    } else {
      await run(`UPDATE withdrawals SET status = 'rejected' WHERE id = ?`, [req.params.id]);
      // Refund balance to user
      await run(`UPDATE users SET wallet_balance = wallet_balance + ? WHERE id = ?`, [item.amount, item.user_id]);
    }

    res.json({ success: true, status: action === 'authorize' ? 'authorized' : 'rejected' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Campaign approval or status toggle by admin
app.post('/api/admin/campaigns/:id/status', async (req, res) => {
  const { status } = req.body;
  try {
    await run(`UPDATE campaigns SET status = ? WHERE id = ?`, [status, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 4. CLIENT / BRAND DASHBOARD APIS
// ============================================================================
app.get('/api/client/campaigns', async (req, res) => {
  const clientId = req.query.client_id;
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

app.post('/api/client/campaigns', async (req, res) => {
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

    const campaignId = uuidv4();
    const budget = Number(total_budget);
    const cpc = Number(cost_per_click);

    await run(`
      INSERT INTO campaigns (id, client_id, title, target_url, total_budget, remaining_budget, cost_per_click, geo_target, community_niches, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `, [
      campaignId,
      client_id,
      title,
      target_url,
      budget,
      budget,
      cpc,
      JSON.stringify(geo_target || []),
      JSON.stringify(community_niches || [])
    ]);

    // Record Deposit in Financial Ledger
    await run(`
      INSERT INTO financial_ledger (id, transaction_type, account_id, campaign_id, amount, notes)
      VALUES (?, 'deposit', ?, ?, ?, ?)
    `, [
      uuidv4(),
      client_id,
      campaignId,
      budget,
      `Escrow deposit for campaign: ${title}`
    ]);

    const created = await get(`SELECT * FROM campaigns WHERE id = ?`, [campaignId]);
    created.geo_target = JSON.parse(created.geo_target || '[]');
    created.community_niches = JSON.parse(created.community_niches || '[]');

    res.json({ success: true, campaign: created });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// 5. PROMOTER DASHBOARD ("SEEDERS") APIS
// ============================================================================
// Marketplace view: active campaigns matching geo or niches
app.get('/api/promoter/marketplace', async (req, res) => {
  const promoterId = req.query.promoter_id;
  try {
    const campaigns = await all(`
      SELECT c.*, u.email as brand_email,
        (SELECT pl.custom_slug FROM promoter_links pl WHERE pl.campaign_id = c.id AND pl.promoter_id = ?) as joined_slug,
        (SELECT pl.total_clicks FROM promoter_links pl WHERE pl.campaign_id = c.id AND pl.promoter_id = ?) as my_clicks
      FROM campaigns c
      JOIN users u ON c.client_id = u.id
      WHERE c.status = 'active' AND c.remaining_budget >= c.cost_per_click
      ORDER BY c.created_at DESC
    `, [promoterId || '', promoterId || '']);

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

// One-click "Generate Referral Link" button
app.post('/api/promoter/generate-link', async (req, res) => {
  const { promoter_id, campaign_id } = req.body;
  try {
    // Check if already generated
    const existing = await get(`
      SELECT * FROM promoter_links WHERE promoter_id = ? AND campaign_id = ?
    `, [promoter_id, campaign_id]);

    if (existing) {
      return res.json({ success: true, link: existing, isNew: false });
    }

    // Generate unique slug
    const promoter = await get(`SELECT email FROM users WHERE id = ?`, [promoter_id]);
    const cleanPrefix = promoter ? promoter.email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').toLowerCase() : 'user';
    const randSuffix = Math.random().toString(36).substring(2, 7);
    const customSlug = `${cleanPrefix}-${randSuffix}`;

    const linkId = uuidv4();
    await run(`
      INSERT INTO promoter_links (id, promoter_id, campaign_id, custom_slug, total_clicks)
      VALUES (?, ?, ?, ?, 0)
    `, [linkId, promoter_id, campaign_id, customSlug]);

    const created = await get(`SELECT * FROM promoter_links WHERE id = ?`, [linkId]);
    res.json({ success: true, link: created, isNew: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Promoter's active referral links
app.get('/api/promoter/my-links', async (req, res) => {
  const promoterId = req.query.promoter_id;
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

// Proof Submission Form (Task submission)
app.post('/api/promoter/tasks', async (req, res) => {
  const { promoter_id, campaign_id, screenshot_url, proof_notes, payout_amount } = req.body;
  try {
    if (!promoter_id || !campaign_id || !screenshot_url) {
      return res.status(400).json({ error: 'Missing required proof fields' });
    }

    const taskId = uuidv4();
    await run(`
      INSERT INTO tasks (id, promoter_id, campaign_id, screenshot_url, proof_notes, status, payout_amount)
      VALUES (?, ?, ?, ?, ?, 'pending', ?)
    `, [
      taskId,
      promoter_id,
      campaign_id,
      screenshot_url,
      proof_notes || '',
      payout_amount || 15.00
    ]);

    const task = await get(`SELECT * FROM tasks WHERE id = ?`, [taskId]);
    res.json({ success: true, task });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tasks', async (req, res) => {
  const promoterId = req.query.promoter_id;
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
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Review Task Proof
app.post('/api/admin/tasks/:id/review', async (req, res) => {
  const { status } = req.body; // 'approved' or 'flagged'
  try {
    const task = await get(`SELECT * FROM tasks WHERE id = ?`, [req.params.id]);
    if (!task) return res.status(404).json({ error: 'Task proof not found' });

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

    res.json({ success: true, status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Wallet Withdraw Request
app.post('/api/promoter/withdraw', async (req, res) => {
  const { user_id, amount, destination_wallet, network } = req.body;
  try {
    const withdrawAmt = Number(amount);
    if (!withdrawAmt || withdrawAmt <= 0) {
      return res.status(400).json({ error: 'Invalid withdrawal amount' });
    }

    const user = await get(`SELECT wallet_balance FROM users WHERE id = ?`, [user_id]);
    if (!user || user.wallet_balance < withdrawAmt) {
      return res.status(400).json({ error: 'Insufficient wallet balance' });
    }

    // Deduct pending balance immediately to avoid double spend
    await run(`UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?`, [withdrawAmt, user_id]);

    const wid = uuidv4();
    await run(`
      INSERT INTO withdrawals (id, user_id, amount, destination_wallet, network, status)
      VALUES (?, ?, ?, ?, ?, 'pending')
    `, [
      wid,
      user_id,
      withdrawAmt,
      destination_wallet || '0xWalletAddressHere',
      network || 'Polygon / USDT'
    ]);

    res.json({ success: true, withdrawalId: wid });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/promoter/wallet-history', async (req, res) => {
  const userId = req.query.user_id;
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

// Interactive Anti-Fraud Simulator Endpoint (Test any IP, UA, or header)
app.post('/api/test-fraud-engine', async (req, res) => {
  const { test_ip, test_user_agent, test_referrer, slug } = req.body;
  try {
    // Synthetic mock request
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

// Fallback for all SPA routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
