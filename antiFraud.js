/**
 * Anti-Fraud Inspection Engine
 * Inspects connecting IP, User-Agent, and HTTP Referrer
 * Blocks known hosting providers, datacenter subnets, VPN/proxy headers, and duplicate clicks
 */
const { run, get, all } = require('./database');
const { v4: uuidv4 } = require('uuid');

// Known hosting provider and datacenter IP prefixes / ASN signatures
const KNOWN_DATACENTER_PREFIXES = [
  '198.51.100.', // Documentation / test datacenter
  '203.0.113.',  // Documentation / test datacenter
  '54.',         // AWS EC2
  '52.',         // AWS EC2
  '34.',         // Google Cloud
  '35.',         // Google Cloud
  '20.',         // Microsoft Azure
  '40.',         // Microsoft Azure
  '104.244.',    // DigitalOcean / Cloudflare
  '167.99.',     // DigitalOcean
  '142.93.',     // DigitalOcean
  '138.197.',    // DigitalOcean
  '185.220.',    // Tor Exit Nodes
  '185.100.'     // Known VPN proxies
];

// Suspicious bot/crawler/headless user agents
const BOT_USER_AGENTS = [
  'bot', 'crawl', 'spider', 'headless', 'python-requests', 'curl', 'wget',
  'aiohttp', 'puppeteer', 'playwright', 'selenium', 'phantomjs', 'postman'
];

/**
 * Traffic Inspector Middleware / Evaluator
 * Returns { valid: boolean, reason: string, riskScore: number, ip, userAgent, referrer }
 */
async function inspectTrafficHeaders(req, campaignId) {
  // Extract real IP through reverse proxy headers or socket
  const forwarded = req.headers['x-forwarded-for'];
  const rawIp = forwarded ? forwarded.split(',')[0].trim() : (req.socket.remoteAddress || req.ip || '127.0.0.1');
  let ip = rawIp;
  if (ip === '::1' || ip === '::ffff:127.0.0.1') {
    ip = '127.0.0.1';
  } else if (ip.startsWith('::ffff:')) {
    ip = ip.replace('::ffff:', '');
  }
  if (ip.includes(':') && !ip.includes('::') && ip.split(':').length === 2) {
    ip = ip.split(':')[0];
  }

  const userAgent = req.headers['user-agent'] || 'Unknown';
  const referrer = req.headers['referer'] || req.headers['referrer'] || '';

  // Check 1: Missing or blank User-Agent
  if (!userAgent || userAgent === 'Unknown' || userAgent.length < 5) {
    return {
      valid: false,
      reason: 'Missing or empty User-Agent string',
      riskScore: 85,
      ip,
      userAgent,
      referrer
    };
  }

  // Check 2: Headless browsers and automation bots
  const uaLower = userAgent.toLowerCase();
  for (const bot of BOT_USER_AGENTS) {
    if (uaLower.includes(bot)) {
      return {
        valid: false,
        reason: `Automated Bot/Scraper/Headless signature detected: (${bot})`,
        riskScore: 95,
        ip,
        userAgent,
        referrer
      };
    }
  }

  // Check 3: VPN / Proxy detection headers
  const proxyHeaders = [
    'x-forwarded-host',
    'via',
    'x-real-ip-original',
    'proxy-connection',
    'cf-connecting-o2o',
    'true-client-ip'
  ];
  const hasSuspiciousProxyHeader = proxyHeaders.some(h => req.headers[h] && req.headers[h].includes('tor'));
  if (hasSuspiciousProxyHeader) {
    return {
      valid: false,
      reason: 'Anonymizing Proxy/Tor transport header detected',
      riskScore: 90,
      ip,
      userAgent,
      referrer
    };
  }

  // Check 4: Cross-reference known datacenter / commercial VPN subnets
  const isDatacenter = KNOWN_DATACENTER_PREFIXES.some(prefix => ip.startsWith(prefix));
  if (isDatacenter) {
    return {
      valid: false,
      reason: `Known Datacenter Subnet / Hosting Provider IP detected (${ip})`,
      riskScore: 90,
      ip,
      userAgent,
      referrer
    };
  }

  // Check 5: Rate Limiting & Duplicate Click Check
  // Limit tracking increments to a maximum of 2 clicks per unique IP address per campaign within a rolling 60-minute window.
  if (campaignId) {
    const clickHistory = await all(`
      SELECT id FROM click_logs 
      WHERE ip_address = ? AND campaign_id = ? AND created_at >= datetime('now', '-60 minutes')
    `, [ip, campaignId]);

    if (clickHistory && clickHistory.length >= 2) {
      return {
        valid: false,
        reason: `Rate limit threshold breached: ${clickHistory.length} clicks from IP within 60 minutes (Max 2 allowed)`,
        riskScore: 80,
        ip,
        userAgent,
        referrer
      };
    }
  }

  return {
    valid: true,
    reason: 'Verified legitimate resident visitor',
    riskScore: 5,
    ip,
    userAgent,
    referrer
  };
}

module.exports = {
  inspectTrafficHeaders,
  KNOWN_DATACENTER_PREFIXES
};
