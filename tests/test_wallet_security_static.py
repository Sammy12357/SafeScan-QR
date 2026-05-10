from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SERVER = (ROOT / "hackabull.py").read_text(encoding="utf-8")
CLIENT = (ROOT / "static" / "app.js").read_text(encoding="utf-8")


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


def test_disconnect_is_server_side_and_idor_safe():
    body = function_body("api_wallet_disconnect")
    assert "wallet = get_verified_wallet(user[\"email\"])" in body
    assert "DELETE FROM wallets WHERE user_id = ?" in body
    assert "wallet.disconnected" in body
    assert "payload" not in body
