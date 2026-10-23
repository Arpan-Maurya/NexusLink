// setup_rls.js
// This script enables Row Level Security (RLS) on Supabase tables and creates owner policies.
// It uses the service-role connection (SUPABASE_DB_URL) which bypasses RLS for backend operations,
// but the policies provide defense‑in‑depth for any client‑side keys.

require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.SUPABASE_DB_URL,
  ssl: { rejectUnauthorized: false }
});

async function run(sql) {
  await pool.query(sql);
}

async function enableRLS() {
  // Users – each user can access only their own record
  await run(`ALTER TABLE users ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS users_owner ON users;`);
  await run(`CREATE POLICY users_owner ON users FOR ALL USING (id = auth.uid()) WITH CHECK (id = auth.uid());`);

  // Campaigns – client owns its campaigns
  await run(`ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS campaigns_owner ON campaigns;`);
  await run(`CREATE POLICY campaigns_owner ON campaigns FOR ALL USING (client_id = auth.uid()) WITH CHECK (client_id = auth.uid());`);

  // Promoter Links – promoter owns its links
  await run(`ALTER TABLE promoter_links ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS promoter_links_owner ON promoter_links;`);
  await run(`CREATE POLICY promoter_links_owner ON promoter_links FOR ALL USING (promoter_id = auth.uid()) WITH CHECK (promoter_id = auth.uid());`);

  // Tasks – promoter owns its task proofs
  await run(`ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS tasks_owner ON tasks;`);
  await run(`CREATE POLICY tasks_owner ON tasks FOR ALL USING (promoter_id = auth.uid()) WITH CHECK (promoter_id = auth.uid());`);

  // Withdrawals – user owns its withdrawals
  await run(`ALTER TABLE withdrawals ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS withdrawals_owner ON withdrawals;`);
  await run(`CREATE POLICY withdrawals_owner ON withdrawals FOR ALL USING (user_id = auth.uid()) WITH CHECK (user_id = auth.uid());`);

  // Financial Ledger – restrict to admin (service‑role bypasses RLS, but other keys cannot read)
  await run(`ALTER TABLE financial_ledger ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS financial_ledger_admin ON financial_ledger;`);
  await run(`CREATE POLICY financial_ledger_admin ON financial_ledger FOR SELECT USING (auth.role() = 'admin');`);

  // Threat Logs – admin only
  await run(`ALTER TABLE threat_logs ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS threat_logs_admin ON threat_logs;`);
  await run(`CREATE POLICY threat_logs_admin ON threat_logs FOR SELECT USING (auth.role() = 'admin');`);

  // Click Logs – admin only
  await run(`ALTER TABLE click_logs ENABLE ROW LEVEL SECURITY;`);
  await run(`DROP POLICY IF EXISTS click_logs_admin ON click_logs;`);
  await run(`CREATE POLICY click_logs_admin ON click_logs FOR SELECT USING (auth.role() = 'admin');`);

  console.log('RLS enabled and policies created');
  await pool.end();
}

enableRLS().catch(err => {
  console.error('Error applying RLS policies:', err);
  process.exit(1);
});
