import sqlite3
import os
import asyncio
import json
from datetime import datetime
from dotenv import load_dotenv

try:
    import base58
    from solana.rpc.async_api import AsyncClient
    from solders.pubkey import Pubkey
    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction
    from solders.message import MessageV0
    from spl.token.instructions import (
        get_associated_token_address,
        create_associated_token_account,
        transfer_checked,
        TransferCheckedParams
    )
    from spl.token.constants import TOKEN_PROGRAM_ID
    try:
        from spl.token.constants import TOKEN_2022_PROGRAM_ID
    except ImportError:
        TOKEN_2022_PROGRAM_ID = None
except ImportError:
    base58 = None
    AsyncClient = None
    Pubkey = None
    Keypair = None
    VersionedTransaction = None
    MessageV0 = None
    get_associated_token_address = None
    create_associated_token_account = None
    transfer_checked = None
    TransferCheckedParams = None
    TOKEN_PROGRAM_ID = None
    TOKEN_2022_PROGRAM_ID = None

load_dotenv()

# SQR Configuration
MINT_ADDRESS_VALUE = "Bpdt7Hey78HeEEr9Q6x19gYAns5n6w44LdjJhxN3pump"
MINT_ADDRESS = Pubkey.from_string(MINT_ADDRESS_VALUE) if Pubkey is not None else MINT_ADDRESS_VALUE
AIRDROP_BASE_ALLOCATION = int(os.getenv("SQR_BASE_ALLOCATION", "100"))
AIRDROP_TOKEN_ALLOCATIONS = {
    "Scanner": AIRDROP_BASE_ALLOCATION,
    "Referrer": AIRDROP_BASE_ALLOCATION * 2,
    "Guardian": AIRDROP_BASE_ALLOCATION * 5,
}
RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
AIRDROP_ENABLED = os.getenv("AIRDROP_ENABLED", "false").lower() in ("1", "true", "yes", "on")
SOLANA_MAINNET_ENABLED = os.getenv("SOLANA_MAINNET_ENABLED", "false").lower() in ("1", "true", "yes", "on")
AIRDROP_DRY_RUN = os.getenv("AIRDROP_DRY_RUN", "true").lower() in ("1", "true", "yes", "on")
AIRDROP_MAX_RECIPIENTS_PER_RUN = int(os.getenv("AIRDROP_MAX_RECIPIENTS_PER_RUN", "25"))
AIRDROP_MAX_TOKENS_PER_RUN = int(os.getenv("AIRDROP_MAX_TOKENS_PER_RUN", "2500"))
AIRDROP_ADMIN_SECRET = os.getenv("AIRDROP_ADMIN_SECRET", "")


def describe_exception(exc):
    message = str(exc) or repr(exc)
    return {
        "type": type(exc).__name__,
        "message": message
    }


def is_mainnet_rpc(rpc_url=RPC_URL):
    return "mainnet" in (rpc_url or "").lower()


def validate_airdrop_runtime():
    if not AIRDROP_ENABLED:
        raise RuntimeError("Airdrop sweep is disabled. Set AIRDROP_ENABLED=true to run it.")
    if is_mainnet_rpc() and not SOLANA_MAINNET_ENABLED:
        raise RuntimeError("Mainnet airdrop is disabled. Set SOLANA_MAINNET_ENABLED=true to allow mainnet transfers.")
    if not AIRDROP_ADMIN_SECRET or len(AIRDROP_ADMIN_SECRET) < 16:
        raise RuntimeError("AIRDROP_ADMIN_SECRET must be set to a strong value before running an airdrop.")
    if AIRDROP_MAX_RECIPIENTS_PER_RUN < 1:
        raise RuntimeError("AIRDROP_MAX_RECIPIENTS_PER_RUN must be at least 1.")
    if AIRDROP_MAX_TOKENS_PER_RUN < 1:
        raise RuntimeError("AIRDROP_MAX_TOKENS_PER_RUN must be at least 1.")


def require_solana_runtime():
    missing = [
        name
        for name, value in {
            "base58": base58,
            "solana": AsyncClient,
            "solders": Pubkey,
            "spl-token": transfer_checked,
        }.items()
        if value is None
    ]
    if missing:
        raise RuntimeError(f"Solana airdrop dependencies are not installed: {', '.join(missing)}")


def associated_token_address(owner, token_program_id):
    try:
        return get_associated_token_address(
            owner,
            MINT_ADDRESS,
            token_program_id=token_program_id
        )
    except TypeError as exc:
        if token_program_id == TOKEN_PROGRAM_ID:
            return get_associated_token_address(owner, MINT_ADDRESS)
        raise RuntimeError("Installed SPL library does not support Token-2022 associated token accounts.") from exc


def create_token_account_instruction(payer, owner, token_program_id):
    try:
        return create_associated_token_account(
            payer,
            owner,
            MINT_ADDRESS,
            token_program_id=token_program_id
        )
    except TypeError as exc:
        if token_program_id == TOKEN_PROGRAM_ID:
            return create_associated_token_account(payer, owner, MINT_ADDRESS)
        raise RuntimeError("Installed SPL library does not support Token-2022 associated token account creation.") from exc


def load_server_wallet():
    require_solana_runtime()
    pk_str = os.getenv("SOLANA_PRIVATE_KEY")
    if not pk_str:
        raise RuntimeError("SOLANA_PRIVATE_KEY is not set.")

    pk_str = pk_str.strip()
    try:
        if pk_str.startswith("["):
            key_bytes = bytes(json.loads(pk_str))
        else:
            key_bytes = base58.b58decode(pk_str)
    except Exception as exc:
        raise RuntimeError("SOLANA_PRIVATE_KEY must be a base58 keypair or a JSON byte array.") from exc

    if len(key_bytes) not in (32, 64):
        raise RuntimeError(f"SOLANA_PRIVATE_KEY decoded to {len(key_bytes)} bytes; expected 32 or 64.")

    return Keypair.from_seed(key_bytes) if len(key_bytes) == 32 else Keypair.from_bytes(key_bytes)


async def get_mint_decimals(client):
    supply = await client.get_token_supply(MINT_ADDRESS)
    if not supply.value:
        raise RuntimeError(f"Could not read token supply for mint {MINT_ADDRESS}. RPC response: {supply!r}")
    return supply.value.decimals


async def get_token_program_id(client):
    mint_info = await client.get_account_info(MINT_ADDRESS)
    if not mint_info.value:
        raise RuntimeError(f"Token mint account was not found: {MINT_ADDRESS}")

    token_program_id = mint_info.value.owner
    supported_programs = [TOKEN_PROGRAM_ID]
    if TOKEN_2022_PROGRAM_ID is not None:
        supported_programs.append(TOKEN_2022_PROGRAM_ID)

    if token_program_id not in supported_programs:
        raise RuntimeError(f"Unexpected token program for SQR mint: {token_program_id}")

    return token_program_id


async def get_token_balance(client, token_account):
    balance = await client.get_token_account_balance(token_account)
    if not balance.value:
        return 0
    return int(balance.value.amount)


def airdrop_tier(scan_count, referrals):
    if scan_count >= 50 and referrals >= 2:
        return "Guardian"
    if scan_count >= 5 and referrals >= 1:
        return "Referrer"
    if scan_count >= 5:
        return "Scanner"
    return "Pending"


def fetch_qualified_recipients(cursor):
    cursor.execute("""
        SELECT u.email,
               COALESCE(w.address, s.wallet_address) AS wallet_address,
               COALESCE(s.scan_count, 0) AS scan_count,
               COALESCE(s.tokens_sent, 0) AS tokens_sent,
               u.airdrop_status,
               u.status,
               COALESCE((SELECT COUNT(*) FROM referrals r WHERE r.referrer_email = u.email AND r.counted = 1), 0) AS referrals,
               COALESCE((SELECT COUNT(*) FROM fraud_flags f WHERE f.user_id = u.email AND f.reviewed = 0), 0) AS fraud_flags
        FROM users u
        LEFT JOIN scans s ON s.email = u.email
        LEFT JOIN wallets w ON w.user_id = u.email AND w.verified = 1 AND w.disconnected_at IS NULL
        WHERE u.status = 'active'
          AND u.airdrop_status IN ('eligible', 'cleared')
          AND COALESCE(s.tokens_sent, 0) = 0
          AND COALESCE((SELECT COUNT(*) FROM fraud_flags f WHERE f.user_id = u.email AND f.reviewed = 0), 0) = 0
          AND COALESCE(w.address, s.wallet_address) IS NOT NULL
          AND TRIM(COALESCE(w.address, s.wallet_address)) != ''
    """)

    recipients = []
    skipped = []
    for row in cursor.fetchall():
        email, wallet_address, scan_count, tokens_sent, status, account_status, referrals, fraud_flags = row
        tier = airdrop_tier(int(scan_count or 0), int(referrals or 0))
        amount = AIRDROP_TOKEN_ALLOCATIONS.get(tier, 0)
        if amount <= 0:
            skipped.append({"email": email, "reason": "Tier is not qualified for distribution.", "tier": tier})
            continue
        recipients.append({
            "email": email,
            "wallet": wallet_address,
            "tier": tier,
            "amount": amount,
            "scan_count": int(scan_count or 0),
            "referrals": int(referrals or 0),
        })
    return recipients, skipped


def ensure_distribution_columns(cursor):
    cursor.execute("PRAGMA table_info(scans)")
    columns = {row[1] for row in cursor.fetchall()}
    if "airdrop_tokens_sent" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_tokens_sent INTEGER DEFAULT 0")
    if "airdrop_sent_at" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_sent_at TEXT")

async def airdrop_sweep():
    print("\n--- SafeScan Airdrop Sweep ---")
    validate_airdrop_runtime()
    require_solana_runtime()
    client = AsyncClient(RPC_URL)
    conn = None

    try:
        # Load Server Wallet
        server_wallet = load_server_wallet()
        token_program_id = await get_token_program_id(client)
        server_ata = associated_token_address(server_wallet.pubkey(), token_program_id)
        decimals = await get_mint_decimals(client)

        server_info = await client.get_account_info(server_ata)
        if server_info.value is None:
            raise RuntimeError(
                f"Server wallet token account does not exist for SQR. "
                f"Send SQR to this ATA first: {server_ata}"
            )

        # 1. Connect to Database
        conn = sqlite3.connect(os.getenv("SQLITE_DB_PATH") or os.path.join(os.getenv("DATA_DIR", "/var/data"), "qr_cache.db"))
        cursor = conn.cursor()
        ensure_distribution_columns(cursor)
        conn.commit()

        winners, skipped = fetch_qualified_recipients(cursor)
        if len(winners) > AIRDROP_MAX_RECIPIENTS_PER_RUN:
            raise RuntimeError(
                f"Airdrop recipient limit exceeded: {len(winners)} > {AIRDROP_MAX_RECIPIENTS_PER_RUN}."
            )
        total_tokens_to_send = sum(winner["amount"] for winner in winners)
        if total_tokens_to_send > AIRDROP_MAX_TOKENS_PER_RUN:
            raise RuntimeError(
                f"Airdrop token limit exceeded: {total_tokens_to_send} > {AIRDROP_MAX_TOKENS_PER_RUN}."
            )
        total_required_raw = total_tokens_to_send * (10 ** decimals)

        server_balance = await get_token_balance(client, server_ata)
        if total_required_raw and server_balance < total_required_raw:
            raise RuntimeError(
                f"Server SQR balance is too low. Need {total_required_raw} raw units, found {server_balance}."
            )

        summary = {
            "status": "ok",
            "eligible": len(winners),
            "sent": [],
            "skipped": skipped,
            "failed": [],
            "mint": str(MINT_ADDRESS),
            "token_program": str(token_program_id),
            "source_token_account": str(server_ata),
            "base_allocation": AIRDROP_BASE_ALLOCATION,
            "total_tokens_to_send": total_tokens_to_send,
            "total_tokens_sent": 0
        }

        if not winners:
            print("No new winners found. Make sure you scanned 5 times on the web app!")
            return summary

        print(f"Found {len(winners)} winner(s). Starting transfer...")

        for winner in winners:
            email = winner["email"]
            wallet_str = winner["wallet"]
            amount = int(winner["amount"])
            amount_raw = amount * (10 ** decimals)
            try:
                if AIRDROP_DRY_RUN:
                    print(f"DRY RUN: would send {amount} SQR to {email}")
                    summary["sent"].append({
                        "email": email,
                        "wallet": wallet_str,
                        "tier": winner["tier"],
                        "amount": amount,
                        "signature": "dry-run",
                        "explorer_url": None,
                        "dry_run": True,
                    })
                    continue

                if not wallet_str:
                    print(f"SKIPPED {email}: no wallet address saved.")
                    summary["skipped"].append({"email": email, "reason": "No wallet address saved."})
                    continue

                target_wallet = Pubkey.from_string(wallet_str)
                target_ata = associated_token_address(target_wallet, token_program_id)

                instructions = []

                # 3. Create token account if they don't have one
                info = await client.get_account_info(target_ata)
                if info.value is None:
                    instructions.append(create_token_account_instruction(
                        server_wallet.pubkey(),
                        target_wallet,
                        token_program_id
                    ))

                instructions.append(transfer_checked(TransferCheckedParams(
                    program_id=token_program_id,
                    source=server_ata,
                    mint=MINT_ADDRESS,
                    dest=target_ata,
                    owner=server_wallet.pubkey(),
                    amount=amount_raw,
                    decimals=decimals
                )))

                # 5. Sign and execute
                recent_blockhash = (await client.get_latest_blockhash()).value.blockhash
                msg = MessageV0.try_compile(server_wallet.pubkey(), instructions, [], recent_blockhash)
                tx = VersionedTransaction(msg, [server_wallet])
                result = await client.send_transaction(tx)
                await client.confirm_transaction(result.value, commitment="confirmed")

                # 6. Update Database to mark as 'sent'
                cursor.execute("UPDATE scans SET tokens_sent = 1, airdrop_tokens_sent = ?, airdrop_sent_at = ? WHERE email = ?", (amount, datetime.utcnow().isoformat() + "Z", email))
                conn.commit()

                print(f"SUCCESS: {amount} SQR sent to {email}")
                print(f"Tx URL: https://explorer.solana.com/tx/{result.value}")
                summary["total_tokens_sent"] += amount
                summary["sent"].append({
                    "email": email,
                    "wallet": wallet_str,
                    "tier": winner["tier"],
                    "amount": amount,
                    "signature": str(result.value),
                    "explorer_url": f"https://explorer.solana.com/tx/{result.value}"
                })

            except Exception as exc:
                error = describe_exception(exc)
                print(f"FAILED to pay {email}: {error['type']} - {error['message']}")
                summary["failed"].append({"email": email, "wallet": wallet_str, "error": error})

        if summary["failed"] and not summary["sent"]:
            summary["status"] = "failed"
        elif summary["failed"]:
            summary["status"] = "partial"

        return summary

    finally:
        if conn:
            conn.close()
        await client.close()

if __name__ == "__main__":
    asyncio.run(airdrop_sweep())
