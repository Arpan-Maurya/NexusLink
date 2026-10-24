# NexusLink landing page update

This version updates the existing single-page frontend to match the supplied NexusLink reference more closely and removes the public demo-login and fraud-simulator UI.

## What changed

- Rebuilt the landing section in `index.html` using the existing local campaign images in `assets/cards/`.
- Added responsive styles for the warm cream background, green CTAs, campaign image cards, benefits row, stats panel, and lower feature section.
- Changed the header navigation to Brands, Promoters, 3D Network Portal, Admin, Contact, Log in, and Get Started.
- Removed the Run Simulator button, simulator modal, and simulator-only frontend handlers.
- Removed the demo credential banner, demo login selector, and Admin/Brand demo login buttons.
- Removed automatic demo email/password fallbacks from the login form.
- Changed authentication failure handling so a failed login or unavailable server does not create a fake logged-in frontend session.

## Run locally

1. Install Node.js (LTS) if it is not installed.
2. Open a terminal in this folder (the folder containing `package.json`).
3. Run `npm install`.
4. Start the backend with `npm start`.
5. Open `http://localhost:3000` in your browser.
6. Use **Get Started** to register a real account or **Log in** to sign in.

## Where to customize

- Main landing HTML: `index.html`, section `id="view-landing"`.
- Landing styles: the CSS block in `index.html`, section comment `NexusLink reference landing page`.
- Header navigation: `index.html`, `header.top-nav`.
- Campaign images: `assets/cards/skincare.jpg`, `lifestyle.jpg`, `product.jpg`, `brand.jpg`, `food.jpg`, `tech.jpg`, and `home.jpg`.
- Decorative landing-page arrows: `Union (1).svg` and `Union (2).svg`, positioned next to the handwritten creator/growth labels.
- Authentication API handling: `handleAuthSubmit()` in the inline JavaScript in `index.html`.

## Important

The demo accounts may still exist in local seed data or an existing SQLite database for development. They are no longer exposed as one-click credentials in the frontend. For a public deployment, configure a strong `JWT_SECRET`, remove development seed accounts from the production database, and never commit real credentials or production database files.
