const http = require('http');

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data,
          json
        });
      });
    });
    req.on('error', reject);
    if (postData) {
      req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
    }
    req.end();
  });
}

async function runSuite() {
  console.log('===============================================================');
  console.log(' NEXUSLINK COMPLETE SYSTEM VERIFICATION SUITE');
  console.log('===============================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, detail = '') {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName} - ${detail}`);
      failed++;
    }
  }

  try {
    // 1. Health Endpoint
    const health = await request({ hostname: 'localhost', port: 3000, path: '/api/health', method: 'GET' });
    assert(health.status === 200 && health.json && health.json.status === 'healthy', 'Health Check', health.data);

    // 2. Authentication - Valid Login
    const adminLogin = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'admin@nexuslink.network', password: 'admin123' });
    assert(adminLogin.status === 200 && adminLogin.json.token && adminLogin.json.user.role === 'admin' && !adminLogin.json.user.password_hash,
      'Valid Admin Login & No Password Leak', adminLogin.data);
    const adminToken = adminLogin.json ? adminLogin.json.token : null;

    const clientLogin = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'growth@web3defi.io', password: 'client123' });
    assert(clientLogin.status === 200 && clientLogin.json.user.role === 'client', 'Valid Client Login', clientLogin.data);
    const clientToken = clientLogin.json ? clientLogin.json.token : null;
    const clientId = clientLogin.json ? clientLogin.json.user.id : null;

    const promoterLogin = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'alex.seeder@community.org', password: 'promoter123' });
    assert(promoterLogin.status === 200 && promoterLogin.json.user.role === 'promoter', 'Valid Promoter Login', promoterLogin.data);
    const promoterToken = promoterLogin.json ? promoterLogin.json.token : null;
    const promoterId = promoterLogin.json ? promoterLogin.json.user.id : null;

    // 3. Authentication - Invalid Login
    const badPass = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'admin@nexuslink.network', password: 'wrongpassword' });
    assert(badPass.status === 401, 'Invalid Password Rejection (401)', badPass.data);

    const badEmail = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/login', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: 'nonexistent@nexuslink.network', password: 'password123' });
    assert(badEmail.status === 401, 'Nonexistent Email Rejection (401)', badEmail.data);

    // 4. Registration - Client and Promoter
    const newClientEmail = `client_${Date.now()}@domain.com`;
    const regClient = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/register', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: newClientEmail, password: 'password123', role: 'client', name: 'New Brand Account' });
    assert(regClient.status === 200 && regClient.json.user.role === 'client', 'Client Registration', regClient.data);
    const newClientToken = regClient.json ? regClient.json.token : null;
    const newClientId = regClient.json ? regClient.json.user.id : null;

    const newPromoterEmail = `promoter_${Date.now()}@domain.com`;
    const regPromoter = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/register', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: newPromoterEmail, password: 'password123', role: 'promoter', name: 'New Promoter Account' });
    assert(regPromoter.status === 200 && regPromoter.json.user.role === 'promoter', 'Promoter Registration', regPromoter.data);

    const dupReg = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/register', method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { email: newClientEmail, password: 'password123', role: 'client' });
    assert(dupReg.status === 400, 'Duplicate Registration Rejection (400)', dupReg.data);

    // 5. Protected Endpoint Without JWT & Profile Session Handling
    const noJwtMe = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET'
    });
    assert(noJwtMe.status === 401, 'Protected /api/auth/me without JWT Rejection (401)', noJwtMe.data);

    const badJwtMe = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': 'Bearer bad_invalid_token_123' }
    });
    assert(badJwtMe.status === 401, 'Protected /api/auth/me with Tampered JWT Rejection (401)', badJwtMe.data);

    const withJwtMe = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${clientToken}` }
    });
    assert(withJwtMe.status === 200 && withJwtMe.json.user.id === clientId, 'Valid /api/auth/me returns Authenticated User', withJwtMe.data);

    // 6. Role Authorization & Wrong-Role Access
    const promoterAdminMetrics = await request({
      hostname: 'localhost', port: 3000, path: '/api/admin/metrics', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    assert(promoterAdminMetrics.status === 403, 'Promoter accessing Admin Metrics Rejection (403)', promoterAdminMetrics.data);

    const clientAdminThreats = await request({
      hostname: 'localhost', port: 3000, path: '/api/admin/threats', method: 'GET',
      headers: { 'Authorization': `Bearer ${clientToken}` }
    });
    assert(clientAdminThreats.status === 403, 'Client accessing Admin Threats Rejection (403)', clientAdminThreats.data);

    const promoterCreateCamp = await request({
      hostname: 'localhost', port: 3000, path: '/api/client/campaigns', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, { title: 'Illegal Campaign', target_url: 'https://test.com', total_budget: 1000, cost_per_click: 10 });
    assert(promoterCreateCamp.status === 403, 'Promoter creating Client Campaign Rejection (403)', promoterCreateCamp.data);

    // 7. Client Campaign Creation & Validation
    const invalidBudgetCamp = await request({
      hostname: 'localhost', port: 3000, path: '/api/client/campaigns', method: 'POST',
      headers: { 'Authorization': `Bearer ${clientToken}`, 'Content-Type': 'application/json' }
    }, { title: 'Zero Budget', target_url: 'https://test.com', total_budget: -100, cost_per_click: 10 });
    assert(invalidBudgetCamp.status === 400, 'Negative Budget Campaign Rejection (400)', invalidBudgetCamp.data);

    const validCamp = await request({
      hostname: 'localhost', port: 3000, path: '/api/client/campaigns', method: 'POST',
      headers: { 'Authorization': `Bearer ${clientToken}`, 'Content-Type': 'application/json' }
    }, {
      title: 'Solana Mobile Ecosystem Campaign',
      target_url: 'https://example.com/solana-saga-launch',
      total_budget: 25000,
      cost_per_click: 50,
      geo_target: ['IN', 'US', 'SG'],
      community_niches: ['Telegram', 'Twitter']
    });
    assert(validCamp.status === 200 && validCamp.json.campaign && validCamp.json.campaign.remaining_budget === 25000,
      'Valid Campaign Creation with Escrow Ledger Record', validCamp.data);
    const createdCampId = validCamp.json ? validCamp.json.campaign.id : null;

    // 8. Campaign Ownership Checks
    // newClient trying to pause original client's campaign
    const crossClientStatus = await request({
      hostname: 'localhost', port: 3000, path: `/api/client/campaigns/${createdCampId}/status`, method: 'POST',
      headers: { 'Authorization': `Bearer ${newClientToken}`, 'Content-Type': 'application/json' }
    }, { status: 'paused' });
    assert(crossClientStatus.status === 403, 'Cross-client Campaign Tampering Rejection (403)', crossClientStatus.data);

    // Owner pausing own campaign
    const ownerPause = await request({
      hostname: 'localhost', port: 3000, path: `/api/client/campaigns/${createdCampId}/status`, method: 'POST',
      headers: { 'Authorization': `Bearer ${clientToken}`, 'Content-Type': 'application/json' }
    }, { status: 'paused' });
    assert(ownerPause.status === 200 && ownerPause.json.status === 'paused', 'Owner Pausing Own Campaign', ownerPause.data);

    // Owner resuming own campaign
    const ownerResume = await request({
      hostname: 'localhost', port: 3000, path: `/api/client/campaigns/${createdCampId}/status`, method: 'POST',
      headers: { 'Authorization': `Bearer ${clientToken}`, 'Content-Type': 'application/json' }
    }, { status: 'active' });
    assert(ownerResume.status === 200 && ownerResume.json.status === 'active', 'Owner Resuming Own Campaign', ownerResume.data);

    // 9. Promoter Link Generation
    const genLink = await request({
      hostname: 'localhost', port: 3000, path: '/api/promoter/generate-link', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, { campaign_id: createdCampId });
    assert(genLink.status === 200 && genLink.json.link && genLink.json.link.custom_slug, 'Promoter Tracking Link Generation', genLink.data);
    const slug = genLink.json ? genLink.json.link.custom_slug : null;

    // Check Alias /api/promoter/links
    const genLinkAlias = await request({
      hostname: 'localhost', port: 3000, path: '/api/promoter/links', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, { campaign_id: createdCampId });
    assert(genLinkAlias.status === 200 && genLinkAlias.json.isNew === false, 'Promoter Link Alias Idempotency', genLinkAlias.data);

    // 10. Public Referral Clicks & Atomic Financial Arbitrage
    // Fetch initial promoter balance
    const pProfileBefore = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    const initialBal = pProfileBefore.json.user.wallet_balance;

    // Click 1: Legitimate human referral (Simulate unique residential IP)
    const testIp = '103.45.67.' + Math.floor(Math.random() * 250 + 1);
    const click1 = await request({
      hostname: 'localhost', port: 3000, path: `/r/${slug}`, method: 'GET',
      headers: {
        'x-forwarded-for': testIp,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'referer': 'https://t.me/web3community'
      }
    });
    assert(click1.status === 302, 'Referral Click 1 Returns HTTP 302 Safe Redirect', click1.headers.location);

    // Check promoter balance credited (60% of ₹50 = ₹30)
    const pProfileAfter1 = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    const expectedBal = Number((initialBal + 30.00).toFixed(2));
    assert(Math.abs(pProfileAfter1.json.user.wallet_balance - expectedBal) < 0.05,
      `Promoter Balance Credited (Expected ~₹${expectedBal}, Got ₹${pProfileAfter1.json.user.wallet_balance})`);

    // Click 2: Second click from same IP (allowed by rolling 2-click threshold)
    const click2 = await request({
      hostname: 'localhost', port: 3000, path: `/r/${slug}`, method: 'GET',
      headers: {
        'x-forwarded-for': testIp,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
      }
    });
    assert(click2.status === 302, 'Referral Click 2 Allowed (2/2 threshold)', click2.headers.location);

    // Click 3: Third click from same IP (Threshold breached: Max 2 allowed per 60 min)
    const pProfileBefore3 = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    const balBefore3 = pProfileBefore3.json.user.wallet_balance;

    const click3 = await request({
      hostname: 'localhost', port: 3000, path: `/r/${slug}`, method: 'GET',
      headers: {
        'x-forwarded-for': testIp,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
      }
    });
    assert(click3.status === 302, 'Referral Click 3 Safely Redirected without Crash', click3.headers.location);

    const pProfileAfter3 = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    assert(pProfileAfter3.json.user.wallet_balance === balBefore3,
      'Duplicate Rate-Limited Click Prevented Balance Modification', `${balBefore3} vs ${pProfileAfter3.json.user.wallet_balance}`);

    // Fraudulent Bot Click (AWS Datacenter & Python-requests)
    const fraudClick = await request({
      hostname: 'localhost', port: 3000, path: `/r/${slug}`, method: 'GET',
      headers: {
        'x-forwarded-for': '54.210.88.99',
        'user-agent': 'Python-requests/2.31.0 Puppeteer Bot'
      }
    });
    assert(fraudClick.status === 302, 'Fraudulent Click Safely Redirects', fraudClick.headers.location);

    const pProfileAfterFraud = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    assert(pProfileAfterFraud.json.user.wallet_balance === balBefore3,
      'Fraudulent Click Discarded from Earnings & Budget', `${balBefore3} vs ${pProfileAfterFraud.json.user.wallet_balance}`);

    // Nonexistent Slug
    const badSlug = await request({ hostname: 'localhost', port: 3000, path: '/r/nonexistent-invalid-slug-999', method: 'GET' });
    assert(badSlug.status === 404, 'Nonexistent Referral Slug returns 404', badSlug.status);

    // 11. Task Submission & Admin Review
    const submitTask = await request({
      hostname: 'localhost', port: 3000, path: '/api/promoter/tasks', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, {
      campaign_id: createdCampId,
      screenshot_url: 'https://images.unsplash.com/proof-screenshot.jpg',
      proof_notes: 'Broadcasted to 15,000 Telegram members',
      payout_amount: 1500.00
    });
    assert(submitTask.status === 200 && submitTask.json.task && submitTask.json.task.status === 'pending',
      'Promoter Task Proof Submission', submitTask.data);
    const taskId = submitTask.json ? submitTask.json.task.id : null;

    const reviewTask = await request({
      hostname: 'localhost', port: 3000, path: `/api/admin/tasks/${taskId}/review`, method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' }
    }, { status: 'approved' });
    assert(reviewTask.status === 200 && reviewTask.json.status === 'approved', 'Admin Task Approval & Escrow Payout', reviewTask.data);

    // 12. Promoter Withdrawal Flow & Admin Authorization/Refund
    const withdrawReq = await request({
      hostname: 'localhost', port: 3000, path: '/api/promoter/withdraw', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, {
      amount: 1000.00,
      destination_wallet: '0xABC...1234',
      network: 'Polygon / USDT'
    });
    assert(withdrawReq.status === 200 && withdrawReq.json.withdrawalId, 'Promoter Withdrawal Creation', withdrawReq.data);
    const wid = withdrawReq.json ? withdrawReq.json.withdrawalId : null;

    // Excessive withdrawal
    const excessWithdraw = await request({
      hostname: 'localhost', port: 3000, path: '/api/promoter/withdraw', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, {
      amount: 99999999.00,
      destination_wallet: '0xABC...1234'
    });
    assert(excessWithdraw.status === 400, 'Excessive Negative Balance Withdrawal Rejection (400)', excessWithdraw.data);

    // Admin Authorize Withdrawal
    const authWithdraw = await request({
      hostname: 'localhost', port: 3000, path: `/api/admin/withdrawals/${wid}/authorize`, method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' }
    }, { action: 'authorize' });
    assert(authWithdraw.status === 200 && authWithdraw.json.status === 'authorized', 'Admin Withdrawal Authorization', authWithdraw.data);

    // Second withdrawal to test Rejection & Refund
    const withdraw2Req = await request({
      hostname: 'localhost', port: 3000, path: '/api/promoter/withdraw', method: 'POST',
      headers: { 'Authorization': `Bearer ${promoterToken}`, 'Content-Type': 'application/json' }
    }, {
      amount: 500.00,
      destination_wallet: '0xREFUND...5555',
      network: 'Polygon / USDT'
    });
    const wid2 = withdraw2Req.json ? withdraw2Req.json.withdrawalId : null;
    const balBeforeReject = withdraw2Req.json.remainingBalance;

    const rejectWithdraw = await request({
      hostname: 'localhost', port: 3000, path: `/api/admin/withdrawals/${wid2}`, method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}`, 'Content-Type': 'application/json' }
    }, { action: 'reject' });
    assert(rejectWithdraw.status === 200 && rejectWithdraw.json.status === 'rejected', 'Admin Withdrawal Rejection', rejectWithdraw.data);

    const pProfileAfterReject = await request({
      hostname: 'localhost', port: 3000, path: '/api/auth/me', method: 'GET',
      headers: { 'Authorization': `Bearer ${promoterToken}` }
    });
    assert(pProfileAfterReject.json.user.wallet_balance === Number((balBeforeReject + 500.00).toFixed(2)),
      'Rejected Withdrawal Balance Fully Refunded to Wallet', `${pProfileAfterReject.json.user.wallet_balance} vs ${balBeforeReject + 500.00}`);

    // 13. Financial Ledger & CSV Export
    const adminLedger = await request({
      hostname: 'localhost', port: 3000, path: '/api/admin/ledger', method: 'GET',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    assert(adminLedger.status === 200 && Array.isArray(adminLedger.json) && adminLedger.json.length > 0,
      'Admin Financial Ledger Access', `Count: ${adminLedger.json ? adminLedger.json.length : 0}`);

    const csvExport = await request({
      hostname: 'localhost', port: 3000, path: `/api/admin/ledger/export-csv?token=${encodeURIComponent(adminToken)}`, method: 'GET'
    });
    assert(csvExport.status === 200 && csvExport.headers['content-type'].includes('text/csv') && csvExport.data.includes('Type,Amount,Account,Notes,Timestamp'),
      'Admin Ledger CSV Streaming with Query Token Authentication', csvExport.data.slice(0, 80));

    const unauthorizedCsv = await request({
      hostname: 'localhost', port: 3000, path: '/api/admin/ledger/export-csv', method: 'GET'
    });
    assert(unauthorizedCsv.status === 401, 'Unauthorized Ledger CSV Rejection (401)', unauthorizedCsv.data);

  } catch (err) {
    console.error('Test execution error:', err);
    failed++;
  }

  console.log('\n===============================================================');
  console.log(` TEST SUMMARY: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('===============================================================');
  process.exit(failed > 0 ? 1 : 0);
}

runSuite();
