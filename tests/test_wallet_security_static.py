from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = (ROOT / "hackabull.py").read_text(encoding="utf-8")
CLIENT = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
LOGIN = (ROOT / "templates" / "login.html").read_text(encoding="utf-8")
INDEX = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
QR_CAMERA = (ROOT / "static" / "qr-camera.js").read_text(encoding="utf-8")
AUTH = (ROOT / "static" / "auth.js").read_text(encoding="utf-8")
REQUIREMENTS = (ROOT / "requirements.txt").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    marker = f"async def {name}"
    start = SERVER.index(marker)
    next_route = SERVER.find("\n@qr_app.", start + len(marker))
    return SERVER[start: next_route if next_route != -1 else len(SERVER)]


def test_wallet_nonce_and_wallet_tables_exist():
    assert "CREATE TABLE IF NOT EXISTS wallets" in SERVER
    assert "CREATE TABLE IF NOT EXISTS wallet_nonces" in SERVER
    assert "user_id TEXT PRIMARY KEY" in SERVER
    assert "expires_at TEXT NOT NULL" in SERVER


def test_verify_uses_nonce_from_database_not_request_body():
    body = function_body("api_wallet_verify")
    assert 'validate_strict_payload(payload, {"walletAddress", "signature"})' in body
    assert "SELECT * FROM wallet_nonces" in body
    assert "stored[\"nonce\"]" in body
    assert "payload.get(\"nonce\")" not in body


def test_failed_signature_invalidates_nonce():
    body = function_body("api_wallet_verify")
    assert "UPDATE wallet_nonces SET used = 1" in body
    assert "wallet.verification_failed" in body
    assert "Signature verification failed" in body


def test_scan_submission_uses_verified_server_wallet_only():
    body = function_body("scan_qr")
    assert "verified_wallet = get_verified_wallet(user_email)" in body
    assert "wallet_address = verified_wallet[\"address\"] if verified_wallet else \"\"" in body
    assert "validate_wallet_address(wallet_address)" not in body


def test_frontend_uses_sign_message_challenge_flow():
    assert "/api/wallet/nonce" in CLIENT
    assert "/api/wallet/verify" in CLIENT
    assert "wallet.provider.signMessage" in CLIENT
    assert "base58Encode(signatureBytes)" in CLIENT
    assert "walletVerified" in CLIENT


def test_frontend_offers_phantom_mobile_browser_handoff():
    assert "https://phantom.app/ul/browse/" in CLIENT
    assert "walletConnect" in CLIENT
    assert "Open in Phantom" in CLIENT
    assert "waitForSolanaWallets" in CLIENT
    assert "window.phantom?.solana" in CLIENT
    assert "/login?next=" in CLIENT


def test_crypto_pattern_signals_cover_modern_drainer_techniques():
    # check_crypto_pattern_signals is a sync function, so locate it directly
    # rather than via function_body() (which expects "async def").
    start = SERVER.index("def check_crypto_pattern_signals")
    end = SERVER.find("\ndef ", start + 1)
    body = SERVER[start:end if end != -1 else len(SERVER)]
    # EIP-2612 / Permit2 gasless approval phishing (Inferno/Pink/Angel drainers)
    assert "permit" in body.lower()
    assert "permit2" in body.lower()
    # NFT collection drains via blanket operator approval
    assert "setapprovalforall" in body.lower()
    # WalletConnect pairing URI session-hijack
    assert "wc:" in body


def test_google_sign_in_uses_visible_redirect_button_for_wallet_browsers():
    assert "auth-google-native" in LOGIN
    assert "googleFallbackButton" in LOGIN
    assert 'data-ux_mode="redirect"' in LOGIN
    assert 'data-state="{{ next_url }}"' in LOGIN
    assert "opacity: 0.01" not in LOGIN
    assert 'data-login_uri="{{ auth_google_url }}"' in LOGIN
    assert "https://accounts.google.com" in SERVER
    assert "next_url" in SERVER
    assert "renderGoogleButton" in AUTH
    assert "google.accounts.id.prompt" in AUTH
    assert "state: state" in AUTH


def test_camera_scanner_uses_back_button_not_x_close():
    assert 'aria-label="Back to scanner"' in QR_CAMERA
    assert ">Back</button>" in QR_CAMERA
    assert 'aria-label="Close scanner">Ã—</button>' not in QR_CAMERA
    assert "riskModalCloseButton" not in INDEX
    assert 'aria-label="Close scan result">X</button>' not in INDEX


def test_stylized_qr_preprocessing_uses_low_threshold_zxing_path():
    assert "55, 70, 85" in SERVER
    assert "decode_barcodes_with_zxing(candidate, qr_only=True)" in SERVER
    assert "zxing-cpp" in REQUIREMENTS
    assert "STYLIZED_THRESHOLDS" in QR_CAMERA
    assert "ENHANCED_SCAN_EVERY_N_FRAMES" in QR_CAMERA
    assert "decodeWithJsQRPasses" in QR_CAMERA


def test_disconnect_is_server_side_and_idor_safe():
    body = function_body("api_wallet_disconnect")
    assert "wallet = get_verified_wallet(user[\"email\"])" in body
    assert "DELETE FROM wallets WHERE user_id = ?" in body
    assert "wallet.disconnected" in body
    assert "payload" not in body
