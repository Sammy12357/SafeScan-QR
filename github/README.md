# SafeScan QR Judge Test Codes

This folder contains six QR code images extracted from the judging test PDF.
Use these files to test the SafeScan QR scanner flow, or feel free to scan any
other QR code.

## Suggested Judging Flow

1. Open the SafeScan QR website.
2. Click "Sign in / Sign up" and authenticate with Google.
3. Return to the main scanner page.
4. Click "Connect wallet" and connect a Solana wallet such as Phantom.
5. Upload or scan the QR images in this folder:
   - `judge-qr-01.png`
   - `judge-qr-02.png`
   - `judge-qr-03.png`
   - `judge-qr-04.png`
   - `judge-qr-05.png`
   - `judge-qr-06.png`
6. After at least five successful scans, check the airdrop progress section.
   Tier 1: Scanner should show as satisfied or unlocked.
7. Open the profile area to confirm the connected wallet and account state.
8. Visit "Scan history" to verify previous scans were saved.
9. Visit "Leaderboard" to see scan-count ranking and user progress.

No special admin credentials are required for the normal judging flow. A Google
account and a Solana wallet browser/extension are enough to test the main user
experience.

## QR Payloads

- `judge-qr-01.png`: JavaScript/XSS-style payload.
- `judge-qr-02.png`: Long repeated text payload.
- `judge-qr-03.png`: Shell-command-style payload.
- `judge-qr-04.png`: SQL-injection-style payload.
- `judge-qr-05.png`: YouTube URL.
- `judge-qr-06.png`: SafeScan QR GitHub repository URL.
