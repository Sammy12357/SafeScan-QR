## SafeScan QR Compliance Checklist

This checklist documents compliance-oriented controls implemented for audit, investor, and future developer review. It is not legal advice; production launch should include attorney review.

### GDPR
- [x] Consent banner with reject option - `templates/footer.html`, `static/app-widgets.js`, `POST /api/consent`
- [x] Consent records stored with timestamp, IP hash, locale, banner version, and 12-month expiry - `consent_logs` table
- [x] User rights portal - `/legal/data-request`
- [x] Data processing records - `/admin/data-processing-log`
- [x] Breach notification template - `/admin/report-breach`
- [x] SCCs noted for international transfers - `/legal/privacy-policy`
- [x] Retention periods defined - Privacy Policy Section 3
- [x] Age threshold for EU users set to 16 in age confirmation flow - `/auth/confirm-age`

### CCPA/CPRA
- [x] Do Not Sell or Share link in footer - `templates/footer.html`
- [x] Opt-out page - `/legal/do-not-sell`
- [x] California rights section - `/legal/data-request`
- [x] No data sold to third parties - Privacy Policy
- [x] CCPA scale threshold note for future readiness - `/admin/data-processing-log`

### COPPA
- [x] Age confirmation gate after Google OAuth - `/auth/confirm-age`
- [x] Under-13 users are blocked and no account is created - `confirm_age.html`

### LGPD
- [x] One-click consent revocation - `/account/settings`
- [x] Third-party sharing list included - Privacy Policy Section 4

### PIPEDA
- [x] Canadian privacy principles noted - Privacy Policy Section 6

### General
- [x] Privacy Policy versioned and dated - `/legal/privacy-policy`
- [x] Terms of Use with arbitration clause - `/legal/terms-of-use`
- [x] Cookie Policy with cookie table - `/legal/cookie-policy`
- [x] Footer links on every page - `templates/footer.html`
- [x] Internal consent log - `/legal/consent-log`
- [x] Admin routes protected by active admin/owner session; airdrop automation still supports `AIRDROP_ADMIN_SECRET` fallback
- [x] Internal admin dashboard - `/admin`
- [x] Audit log table and admin audit viewer - `/admin/logs`
- [x] Airdrop fraud flags and review queue - `/admin/airdrop/fraud`

### Production Follow-Ups
- [ ] Attorney review before public launch or token distribution.
- [ ] Connect transactional email for privacy request confirmations and completion notices.
- [x] Keep signed-in user scan history and leaderboard counters as long-term records unless the user requests deletion or an owner removes the account.
- [ ] Encrypt or hash stored wallet addresses before production scale.
- [ ] Replace email query parameters with signed session state.
- [ ] Remove the remaining airdrop shared-secret fallback after automation has an owner session or signed job token.
