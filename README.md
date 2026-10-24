https://nexuslink-turns-private--7vazrqp.gamma.site/

# NexusLink: Production Decentralized Community Affiliate Network Application

NexusLink is a high-performance decentralized affiliate and community seeding network designed for autonomous traffic arbitrage, anti-fraud inspection, and escrow-backed atomic payouts.

---

## 1. User Roles & Permissions Architecture

- **Administrator Dashboard:**
  - **Global Financial Ledger View:** Double-entry tracking of all deposits, promoter payouts, and platform revenue commissions.
  - **Campaign Validation Portal:** Real-time visibility and status management over all brand campaigns.
  - **Pending Withdrawal Authorization Engine:** Multi-variable payout sanctioning with approval/rejection and balance reconciliation.
  - **Multi-Variable Anti-Fraud Alert System:** Live telemetry capturing datacenter bots, proxy subnets, and rate-limit violators.

- **Client / Brand Dashboard:**
  - **Onboarding Pipeline:** Instant registration and client escrow vault management.
  - **Campaign Builder Form:** Fields for Campaign Title, Destination Link, Geographic Filters (Country/Region arrays), Community Niches (WhatsApp, Discord, Telegram, Reddit), Total Escrow Deposit Budget (\$), and Cost-Per-Click rate (\$).
  - **Live Tracking Charts:** Visual Chart.js telemetry comparing verified clicks generated against budget depleted (\$).

- **Promoter Dashboard ("Seeders"):**
  - **Quick Registration:** Fast onboarding with country location and community niche preferences (WhatsApp, Discord, Telegram, Reddit).
  - **Marketplace View:** Filtered catalog of active client campaigns with payout rewards per click.
  - **One-Click "Generate Referral Link":** Automatic creation of unique slugs and tracking URLs (`/r/:slug`).
  - **Proof Submission Form:** Screenshot evidence upload alongside calculated tracking link payload.
  - **Wallet Withdraw Portal:** Instant balance withdrawals with network choices (Polygon USDT, Arbitrum USDC, etc.) and complete transaction history.

---

## 2. Database Data Models & Inter-Relationships (PostgreSQL Blueprint)

The schema is defined in [schema.sql](file:///C:/Users/harsh/.gemini/antigravity/scratch/nexuslink/schema.sql) and implemented with SQLite persistence in [database.js](file:///C:/Users/harsh/.gemini/antigravity/scratch/nexuslink/database.js):

- **`users` Table:**
  - `id` (UUID PRIMARY KEY)
  - `email` (VARCHAR UNIQUE)
  - `password_hash` (VARCHAR)
  - `role` (admin, client, promoter)
  - `wallet_balance` (NUMERIC(14,4))
  - `device_fingerprint` (VARCHAR)
  - `country` (VARCHAR)
  - `community_types` (TEXT[])
  - `created_at` (TIMESTAMP)

- **`campaigns` Table:**
  - `id` (UUID PRIMARY KEY)
  - `client_id` (UUID REFERENCES users(id))
  - `title` (VARCHAR)
  - `target_url` (TEXT)
  - `total_budget` (NUMERIC)
  - `remaining_budget` (NUMERIC)
  - `cost_per_click` (NUMERIC)
  - `geo_target` (TEXT[])
  - `community_niches` (TEXT[])
  - `status` (active, paused, exhausted)
  - `created_at` (TIMESTAMP)

- **`promoter_links` Table:**
  - `id` (UUID PRIMARY KEY)
  - `promoter_id` (UUID REFERENCES users(id))
  - `campaign_id` (UUID REFERENCES campaigns(id))
  - `custom_slug` (VARCHAR UNIQUE INDEXED)
  - `total_clicks` (INTEGER)
  - `created_at` (TIMESTAMP)

- **`tasks` Table:**
  - `id` (UUID PRIMARY KEY)
  - `promoter_id` (UUID REFERENCES users(id))
  - `campaign_id` (UUID REFERENCES campaigns(id))
  - `screenshot_url` (TEXT)
  - `proof_notes` (TEXT)
  - `status` (pending, approved, flagged)
  - `payout_amount` (NUMERIC)
  - `created_at` (TIMESTAMP)

- **`financial_ledger` Table:**
  - `id` (UUID PRIMARY KEY)
  - `transaction_type` (deposit, payout, platform_revenue, withdrawal)
  - `account_id` (UUID REFERENCES users(id))
  - `campaign_id` (UUID REFERENCES campaigns(id))
  - `amount` (NUMERIC)
  - `notes` (TEXT)
  - `timestamp` (TIMESTAMP)

- **`threat_logs` Table:**
  - Multi-variable anti-fraud database recording connecting IP, User-Agent, Referrer, detection reason, risk score (0-100), and associated slug.

- **`click_logs` Table:**
  - Rate-limit audit logs for enforcing rolling 60-minute window limits.

- **`withdrawals` Table:**
  - Tracking requested, authorized, and rejected payouts.

---

## 3. Advanced Redirect Routing & Anti-Fraud Controller Engine

- **Route:** `GET /r/:slug`
- **Active Middleware:** `inspectTrafficHeaders()`:
  - Extracts connecting IP (with reverse proxy `X-Forwarded-For` support), User-Agent, and Referrer.
  - Cross-references incoming IP against known hosting providers and datacenter subnets (AWS, Google Cloud, Azure, DigitalOcean, Tor Exit Nodes, VPN proxies).
  - Validates User-Agent strings against automated bots, headless browsers, scrapers (`puppeteer`, `selenium`, `python-requests`, etc.).
  - **Duplicate Click Throttling:** Enforces maximum **2 clicks per unique IP address per campaign within a rolling 60-minute window**.
- **On Legitimate Traffic (Pass):**
  - Increments `promoter_links.total_clicks` by 1.
  - Executes atomic deduction from `campaigns.remaining_budget` equal to `cost_per_click`.
  - Splitting: Credits **60%** of CPC into promoter's `wallet_balance` and logs **40%** to platform revenue.
  - Triggers HTTP 302 redirect sending visitor to `target_url`.
- **On Fraud Traffic (Fail):**
  - Logs threat in `threat_logs` table with risk score.
  - Directly triggers HTTP 302 transparent redirect to `target_url` without incrementing clicks or deducting funds.

---

## 4. UI & Design System

- Mobile-first, responsive dark-mode interface built with Tailwind CSS, Chart.js, and Lucide icons.
- Interactive multi-role preview switcher to navigate Admin, Client, and Promoter views seamlessly.
- Built-in live Anti-Fraud inspection modal to test simulated IPs, user agents, and referral flows.

---

## 5. Running the Application Locally

1. Install dependencies:
   ```bash
   npm install
   ```

2. Start the server:
   ```bash
   node server.js
   ```

3. Open your browser:
   ```
   http://localhost:3000
   ```

Create an account from the Sign Up form to test the registration flow. Demo credentials are intentionally not displayed in the frontend.
